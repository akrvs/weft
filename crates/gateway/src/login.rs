use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use weft_core::address::Kind;
use weft_core::cbor::{self, Value};
use weft_core::{Address, Challenge, Manifest, Proof, PublicKey, login};

pub const PENDING_TTL: u64 = 300;
pub const SESSION_TTL: u64 = 86_400;
pub const MAX_ENTRIES: usize = 1024;
pub const COOKIE: &str = "weft_session";
pub const SESSIONS: &str = "gateway/sessions";

pub type Token = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Origin,
    Proof(weft_core::Error),
    Nonce,
    Full,
    Random,
    Denied,
    State(String),
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Origin => f.write_str("origin is not a valid service name"),
            Self::Proof(e) => write!(f, "proof rejected: {e}"),
            Self::Nonce => f.write_str("challenge unknown, used, or expired"),
            Self::Full => f.write_str("too many logins in flight"),
            Self::Random => f.write_str("no randomness"),
            Self::Denied => f.write_str("identity is not on the allow list"),
            Self::State(e) => f.write_str(e),
        }
    }
}

#[derive(Debug)]
pub enum Claim {
    Unknown,
    Waiting(Challenge),
    Ready(Token),
}

#[derive(Debug)]
struct Pending {
    expires: u64,
    token: Option<Token>,
}

#[derive(Debug)]
struct Session {
    author: PublicKey,
    expires: u64,
}

#[derive(Debug)]
pub struct Logins {
    origin: String,
    path: PathBuf,
    allow: Option<HashSet<PublicKey>>,
    pending: Mutex<HashMap<[u8; 32], Pending>>,
    sessions: Mutex<BTreeMap<Token, Session>>,
}

fn random() -> Result<[u8; 32], Refusal> {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).map_err(|_| Refusal::Random)?;
    Ok(out)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn state(e: impl core::fmt::Display) -> Refusal {
    Refusal::State(e.to_string())
}

pub fn allowlist(text: &str) -> Result<HashSet<PublicKey>, Refusal> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| {
            let address: Address = l.parse().map_err(|e| Refusal::State(format!("{l}: {e}")))?;
            if address.kind() != Kind::Key {
                return Err(Refusal::State(format!("{l}: not a key address")));
            }
            PublicKey::from_bytes(address.bytes()).map_err(|e| Refusal::State(format!("{l}: {e}")))
        })
        .collect()
}

fn load(path: &Path, now: u64) -> Result<BTreeMap<Token, Session>, Refusal> {
    parse(path, now).map_err(|e| Refusal::State(format!("{}: {e}", path.display())))
}

fn parse(path: &Path, now: u64) -> Result<BTreeMap<Token, Session>, Refusal> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(state(e)),
    };
    let value = cbor::decode(&bytes).map_err(state)?;
    let items = value.as_array().ok_or_else(|| state("not an array"))?;
    if items.len() > MAX_ENTRIES {
        return Err(state("too many sessions"));
    }
    let mut sessions = BTreeMap::new();
    for item in items {
        let map = item.as_map().ok_or_else(|| state("session is not a map"))?;
        cbor::only(map, &["author", "expires", "token"]).map_err(state)?;
        let token: Token = cbor::field(map, "token")
            .map_err(state)?
            .as_bytes()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| state("token is not 32 bytes"))?;
        let author = cbor::field(map, "author")
            .map_err(state)?
            .as_bytes()
            .and_then(|b| <&[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| state("author is not 32 bytes"))
            .and_then(|b| PublicKey::from_bytes(b).map_err(state))?;
        let expires = cbor::field(map, "expires")
            .map_err(state)?
            .as_uint()
            .ok_or_else(|| state("expires is not an integer"))?;
        if now < expires && sessions.insert(token, Session { author, expires }).is_some() {
            return Err(state("duplicate token"));
        }
    }
    Ok(sessions)
}

fn save(path: &Path, sessions: &BTreeMap<Token, Session>) -> Result<(), Refusal> {
    let items = sessions
        .iter()
        .map(|(token, s)| {
            Value::Map(vec![
                ("author".into(), Value::Bytes(s.author.bytes().to_vec())),
                ("expires".into(), Value::Uint(s.expires)),
                ("token".into(), Value::Bytes(token.to_vec())),
            ])
        })
        .collect();
    weft_home::fs::replace_private(path, &Value::Array(items).encode()).map_err(state)
}

impl Logins {
    pub fn new(
        origin: String,
        home: &Path,
        allow: Option<HashSet<PublicKey>>,
        now: u64,
    ) -> Result<Self, Refusal> {
        if !login::valid_service(&origin) {
            return Err(Refusal::Origin);
        }
        let path = home.join(SESSIONS);
        let sessions = load(&path, now)?;
        Ok(Self {
            origin,
            path,
            allow,
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(sessions),
        })
    }

    pub fn allows(&self, author: &PublicKey) -> bool {
        self.allow.as_ref().is_none_or(|set| set.contains(author))
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn secure(&self) -> bool {
        self.origin.starts_with("https://")
    }

    pub fn open(&self, now: u64) -> Result<Challenge, Refusal> {
        let nonce = random()?;
        let expires = now.saturating_add(PENDING_TTL);
        let mut pending = lock(&self.pending);
        pending.retain(|_, p| now < p.expires);
        if pending.len() >= MAX_ENTRIES {
            return Err(Refusal::Full);
        }
        pending.insert(nonce, Pending { expires, token: None });
        Ok(Challenge { service: self.origin.clone(), nonce, expires })
    }

    pub fn satisfy(
        &self,
        proof: &Proof,
        now: u64,
        newer: Option<&Manifest>,
    ) -> Result<(PublicKey, Token), Refusal> {
        let login = proof.verify(&self.origin, now, newer).map_err(Refusal::Proof)?;
        if !self.allows(&login.author) {
            return Err(Refusal::Denied);
        }
        let token = random()?;
        let mut pending = lock(&self.pending);
        let entry = pending.get_mut(&login.challenge.nonce).ok_or(Refusal::Nonce)?;
        if now >= entry.expires || entry.token.is_some() {
            return Err(Refusal::Nonce);
        }
        let mut sessions = lock(&self.sessions);
        sessions.retain(|_, s| now < s.expires);
        if sessions.len() >= MAX_ENTRIES {
            return Err(Refusal::Full);
        }
        let expires = now.saturating_add(SESSION_TTL);
        sessions.insert(token, Session { author: login.author, expires });
        if let Err(e) = save(&self.path, &sessions) {
            sessions.remove(&token);
            return Err(e);
        }
        entry.token = Some(token);
        Ok((login.author, token))
    }

    pub fn claim(&self, nonce: &[u8; 32], now: u64) -> Claim {
        let mut pending = lock(&self.pending);
        let Some(entry) = pending.get(nonce) else { return Claim::Unknown };
        if now >= entry.expires {
            pending.remove(nonce);
            return Claim::Unknown;
        }
        match entry.token {
            Some(token) => {
                pending.remove(nonce);
                Claim::Ready(token)
            }
            None => Claim::Waiting(Challenge {
                service: self.origin.clone(),
                nonce: *nonce,
                expires: entry.expires,
            }),
        }
    }

    pub fn session(&self, token: &Token, now: u64) -> Option<PublicKey> {
        let sessions = lock(&self.sessions);
        sessions.get(token).filter(|s| now < s.expires).map(|s| s.author)
    }

    pub fn logout(&self, token: &Token) -> Result<(), Refusal> {
        let mut sessions = lock(&self.sessions);
        if sessions.remove(token).is_some() {
            save(&self.path, &sessions)?;
        }
        Ok(())
    }

    pub fn cookie(&self, token: Option<&Token>) -> String {
        let (value, age) = match token {
            Some(t) => (login::to_text(t), SESSION_TTL),
            None => (String::new(), 0),
        };
        let secure = if self.secure() { "; Secure" } else { "" };
        format!("{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{secure}")
    }
}

pub fn token_from_cookies(header: &str) -> Option<Token> {
    header
        .split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix(COOKIE).and_then(|rest| rest.strip_prefix('=')))
        .and_then(|value| login::from_text(value).ok())
        .and_then(|bytes| bytes.try_into().ok())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use weft_core::SecretKey;

    const T: u64 = 1_800_000_000;
    const ORIGIN: &str = "http://127.0.0.1:8080";

    fn home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("weft-logins-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn logins(name: &str) -> Logins {
        Logins::new(ORIGIN.into(), &home(name), None, T).unwrap()
    }

    fn proof(challenge: &Challenge, key: &SecretKey) -> Proof {
        let login = challenge.draft(&key.public(), &key.public(), T).sign(key).unwrap();
        Proof { login, manifest: None }
    }

    #[test]
    fn origin_must_be_a_service_name() {
        let dir = home("origin");
        assert!(Logins::new("HTTP://x".into(), &dir, None, T).is_err());
        assert!(Logins::new(String::new(), &dir, None, T).is_err());
        assert!(Logins::new(ORIGIN.into(), &dir, None, T).is_ok());
        assert!(Logins::new("https://example.com".into(), &dir, None, T).unwrap().secure());
    }

    #[test]
    fn nonce_is_single_use_and_expires() {
        let logins = logins("nonce");
        let key = SecretKey::from_seed([1; 32]);
        let challenge = logins.open(T).unwrap();
        assert!(matches!(logins.claim(&challenge.nonce, T + 1), Claim::Waiting(_)));
        let p = proof(&challenge, &key);
        let (author, token) = logins.satisfy(&p, T + 1, None).unwrap();
        assert_eq!(author, key.public());
        assert_eq!(logins.satisfy(&p, T + 1, None), Err(Refusal::Nonce));
        let Claim::Ready(claimed) = logins.claim(&challenge.nonce, T + 2) else { panic!() };
        assert_eq!(claimed, token);
        assert!(matches!(logins.claim(&challenge.nonce, T + 2), Claim::Unknown));
        assert_eq!(logins.session(&token, T + 3), Some(key.public()));
        assert_eq!(logins.session(&token, T + SESSION_TTL + 1), None);
        logins.logout(&token).unwrap();
        assert_eq!(logins.session(&token, T + 3), None);

        let late = logins.open(T).unwrap();
        assert!(matches!(logins.claim(&late.nonce, T + PENDING_TTL), Claim::Unknown));
        let stale = logins.open(T).unwrap();
        assert!(logins.satisfy(&proof(&stale, &key), T + PENDING_TTL, None).is_err());
        let unknown = Challenge { service: ORIGIN.into(), nonce: [7; 32], expires: T + 300 };
        assert_eq!(logins.satisfy(&proof(&unknown, &key), T + 1, None), Err(Refusal::Nonce));
        let elsewhere = Challenge { service: "http://evil".into(), ..challenge };
        assert!(matches!(
            logins.satisfy(&proof(&elsewhere, &key), T + 1, None),
            Err(Refusal::Proof(_))
        ));
    }

    #[test]
    fn pending_is_capped_and_swept() {
        let logins = logins("capped");
        for _ in 0..MAX_ENTRIES {
            logins.open(T).unwrap();
        }
        assert_eq!(logins.open(T).err(), Some(Refusal::Full));
        logins.open(T + PENDING_TTL).unwrap();
    }

    #[test]
    fn cookies_round_trip() {
        let logins = logins("cookies");
        let token = [5u8; 32];
        let set = logins.cookie(Some(&token));
        assert!(
            set.contains("HttpOnly") && set.contains("SameSite=Strict") && !set.contains("Secure")
        );
        let value = set.split(';').next().unwrap();
        assert_eq!(token_from_cookies(&format!("a=b; {value}; c=d")), Some(token));
        assert_eq!(token_from_cookies("weft_session=!!!"), None);
        assert_eq!(token_from_cookies("weft_session=AAAA"), None);
        assert!(logins.cookie(None).contains("Max-Age=0"));
        let secure = Logins::new("https://x".into(), &home("secure"), None, T).unwrap();
        assert!(secure.cookie(Some(&token)).contains("Secure"));
    }

    #[test]
    fn sessions_survive_a_restart_and_a_bad_file_refuses() {
        let dir = home("persist");
        let key = SecretKey::from_seed([1; 32]);
        let first = Logins::new(ORIGIN.into(), &dir, None, T).unwrap();
        let challenge = first.open(T).unwrap();
        let (_, token) = first.satisfy(&proof(&challenge, &key), T + 1, None).unwrap();
        let stale = first.open(T).unwrap();
        let (_, old) = first.satisfy(&proof(&stale, &key), T + 1, None).unwrap();
        drop(first);

        let second = Logins::new(ORIGIN.into(), &dir, None, T + 2).unwrap();
        assert_eq!(second.session(&token, T + 3), Some(key.public()));
        second.logout(&token).unwrap();
        let third = Logins::new(ORIGIN.into(), &dir, None, T + 4).unwrap();
        assert_eq!(third.session(&token, T + 5), None);
        assert_eq!(third.session(&old, T + 5), Some(key.public()));
        let later = Logins::new(ORIGIN.into(), &dir, None, T + SESSION_TTL + 2).unwrap();
        assert_eq!(later.session(&old, T + SESSION_TTL + 3), None);

        let path = dir.join(SESSIONS);
        let good = std::fs::read(&path).unwrap();
        std::fs::write(&path, &good[..good.len() - 1]).unwrap();
        assert!(matches!(
            Logins::new(ORIGIN.into(), &dir, None, T).unwrap_err(),
            Refusal::State(_)
        ));
        let extra = Value::Array(vec![Value::Map(vec![
            ("author".into(), Value::Bytes(key.public().bytes().to_vec())),
            ("expires".into(), Value::Uint(T + 10)),
            ("token".into(), Value::Bytes(vec![1; 32])),
            ("x".into(), Value::Uint(1)),
        ])]);
        std::fs::write(&path, extra.encode()).unwrap();
        assert!(Logins::new(ORIGIN.into(), &dir, None, T).is_err());
        let short = Value::Array(vec![Value::Map(vec![
            ("author".into(), Value::Bytes(vec![1; 31])),
            ("expires".into(), Value::Uint(T + 10)),
            ("token".into(), Value::Bytes(vec![1; 32])),
        ])]);
        std::fs::write(&path, short.encode()).unwrap();
        assert!(Logins::new(ORIGIN.into(), &dir, None, T).is_err());
        std::fs::write(&path, Value::Array(vec![]).encode()).unwrap();
        assert!(Logins::new(ORIGIN.into(), &dir, None, T).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allow_list_gates_identities() {
        let listed = SecretKey::from_seed([1; 32]);
        let stranger = SecretKey::from_seed([2; 32]);
        let text = format!(" {}\n\n", listed.public().address());
        let allow = allowlist(&text).unwrap();
        let logins = Logins::new(ORIGIN.into(), &home("allow"), Some(allow), T).unwrap();
        assert!(logins.allows(&listed.public()));
        assert!(!logins.allows(&stranger.public()));
        let challenge = logins.open(T).unwrap();
        assert_eq!(
            logins.satisfy(&proof(&challenge, &stranger), T + 1, None),
            Err(Refusal::Denied)
        );
        assert!(logins.satisfy(&proof(&challenge, &listed), T + 1, None).is_ok());
        assert!(allowlist("not an address").is_err());
        assert!(allowlist(&Address::of(b"x").to_string()).is_err());
        assert!(allowlist("").unwrap().is_empty());
    }
}
