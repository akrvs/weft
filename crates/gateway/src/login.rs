use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use weft_core::address::Kind;
use weft_core::{Address, Challenge, Manifest, Proof, PublicKey, login};

use crate::state::State;

pub const PENDING_TTL: u64 = 300;
pub const SESSION_TTL: u64 = 86_400;
pub const PENDING_MAX: usize = 1024;
pub const DEFAULT_SESSIONS: usize = 4096;
pub const COOKIE: &str = "weft_session";
pub const MAX_HOST: usize = 253;

pub type Token = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Origin,
    Host,
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
            Self::Origin => f.write_str("origin is not an http or https service name"),
            Self::Host => f.write_str("host is not a service name"),
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
    service: String,
}

#[derive(Debug)]
struct Session {
    author: PublicKey,
    expires: u64,
}

#[derive(Debug)]
pub struct Logins {
    origin: String,
    cap: usize,
    state: Arc<State>,
    allow: RwLock<Option<HashSet<PublicKey>>>,
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

fn scheme(origin: &str) -> Option<&str> {
    ["https", "http"].into_iter().find(|s| {
        origin.strip_prefix(s).and_then(|r| r.strip_prefix("://")).is_some_and(|h| !h.is_empty())
    })
}

pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b":.-[]".contains(&b))
}

fn soonest(sessions: &BTreeMap<Token, Session>, cap: usize) -> Vec<Token> {
    let mut by_expiry: Vec<(u64, Token)> = sessions.iter().map(|(t, s)| (s.expires, *t)).collect();
    by_expiry.sort_unstable();
    by_expiry.iter().take(sessions.len().saturating_sub(cap)).map(|(_, t)| *t).collect()
}

impl Logins {
    pub fn new(
        origin: String,
        state: Arc<State>,
        allow: Option<HashSet<PublicKey>>,
        cap: usize,
        now: u64,
    ) -> Result<Self, Refusal> {
        if !login::valid_service(&origin) || scheme(&origin).is_none() {
            return Err(Refusal::Origin);
        }
        let mut sessions = BTreeMap::new();
        let mut gone = Vec::new();
        for (token, author, expires) in state.sessions()? {
            if now < expires {
                sessions.insert(token, Session { author, expires });
            } else {
                gone.push(token);
            }
        }
        let evicted = soonest(&sessions, cap);
        for t in &evicted {
            sessions.remove(t);
        }
        gone.extend(evicted);
        state.remove_sessions(gone.iter())?;
        Ok(Self {
            origin,
            cap,
            state,
            allow: RwLock::new(allow),
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(sessions),
        })
    }

    pub fn allows(&self, author: &PublicKey) -> bool {
        let allow = self.allow.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        allow.as_ref().is_none_or(|set| set.contains(author))
    }

    pub fn set_allow(&self, allow: Option<HashSet<PublicKey>>) {
        *self.allow.write().unwrap_or_else(std::sync::PoisonError::into_inner) = allow;
    }

    pub fn sweep(&self, now: u64) -> Result<usize, Refusal> {
        let mut sessions = lock(&self.sessions);
        let gone: Vec<Token> =
            sessions.iter().filter(|(_, s)| now >= s.expires).map(|(t, _)| *t).collect();
        for t in &gone {
            sessions.remove(t);
        }
        if !gone.is_empty() {
            self.state.remove_sessions(gone.iter())?;
        }
        Ok(gone.len())
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn secure(&self) -> bool {
        self.origin.starts_with("https://")
    }

    pub fn service(&self, host: Option<&str>) -> Result<String, Refusal> {
        let Some(host) = host else { return Ok(self.origin.clone()) };
        if !valid_host(host) {
            return Err(Refusal::Host);
        }
        let service = format!("{}://{host}", scheme(&self.origin).unwrap_or("http"));
        if login::valid_service(&service) { Ok(service) } else { Err(Refusal::Host) }
    }

    pub fn open(&self, now: u64, host: Option<&str>) -> Result<Challenge, Refusal> {
        let service = self.service(host)?;
        let nonce = random()?;
        let expires = now.saturating_add(PENDING_TTL);
        let mut pending = lock(&self.pending);
        pending.retain(|_, p| now < p.expires);
        if pending.len() >= PENDING_MAX {
            return Err(Refusal::Full);
        }
        pending.insert(nonce, Pending { expires, token: None, service: service.clone() });
        Ok(Challenge { service, nonce, expires })
    }

    pub fn satisfy(
        &self,
        proof: &Proof,
        now: u64,
        newer: Option<&Manifest>,
    ) -> Result<(PublicKey, Token), Refusal> {
        let nonce = Challenge::from_record(&proof.login).map_err(Refusal::Proof)?.nonce;
        let token = random()?;
        let mut pending = lock(&self.pending);
        let entry = pending.get_mut(&nonce).ok_or(Refusal::Nonce)?;
        if now >= entry.expires || entry.token.is_some() {
            return Err(Refusal::Nonce);
        }
        let login = proof.verify(&entry.service, now, newer).map_err(Refusal::Proof)?;
        if !self.allows(&login.author) {
            return Err(Refusal::Denied);
        }
        let mut sessions = lock(&self.sessions);
        let mut gone: Vec<Token> =
            sessions.iter().filter(|(_, s)| now >= s.expires).map(|(t, _)| *t).collect();
        for t in &gone {
            sessions.remove(t);
        }
        let evicted = soonest(&sessions, self.cap.saturating_sub(1));
        for t in &evicted {
            sessions.remove(t);
        }
        gone.extend(evicted);
        if !gone.is_empty() {
            self.state.remove_sessions(gone.iter())?;
        }
        let expires = now.saturating_add(SESSION_TTL);
        self.state.put_session(&token, &login.author, expires)?;
        sessions.insert(token, Session { author: login.author, expires });
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
                service: entry.service.clone(),
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
            self.state.remove_sessions([token])?;
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
    use std::path::{Path, PathBuf};
    use weft_core::SecretKey;

    const T: u64 = 1_800_000_000;
    const ORIGIN: &str = "http://127.0.0.1:8080";

    fn home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("weft-logins-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn state(dir: &Path) -> Arc<State> {
        Arc::new(State::open(dir).unwrap())
    }

    fn at(origin: &str, dir: &Path, cap: usize, now: u64) -> Result<Logins, Refusal> {
        Logins::new(origin.into(), state(dir), None, cap, now)
    }

    fn logins(name: &str) -> Logins {
        at(ORIGIN, &home(name), DEFAULT_SESSIONS, T).unwrap()
    }

    fn proof(challenge: &Challenge, key: &SecretKey) -> Proof {
        let login = challenge.draft(&key.public(), &key.public(), T).sign(key).unwrap();
        Proof { login, manifest: None }
    }

    #[test]
    fn a_full_sessions_table_evicts_the_soonest_expiry_and_a_load_keeps_the_newest() {
        let dir = home("evict");
        let logins = at(ORIGIN, &dir, 2, T).unwrap();
        let keys: Vec<_> = (1..=3u8).map(|n| SecretKey::from_seed([n; 32])).collect();
        let tokens: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let now = T + u64::try_from(i).unwrap();
                let challenge = logins.open(now, None).unwrap();
                logins.satisfy(&proof(&challenge, key), now, None).unwrap().1
            })
            .collect();
        assert_eq!(logins.session(&tokens[0], T + 3), None, "the first login made room");
        assert_eq!(logins.session(&tokens[1], T + 3), Some(keys[1].public()));
        assert_eq!(logins.session(&tokens[2], T + 3), Some(keys[2].public()));
        drop(logins);
        let lowered = at(ORIGIN, &dir, 1, T + 3).unwrap();
        assert_eq!(lowered.session(&tokens[1], T + 4), None, "a lower cap keeps the newest");
        assert_eq!(lowered.session(&tokens[2], T + 4), Some(keys[2].public()));
        drop(lowered);
        let one = at(ORIGIN, &dir, 1, T + 4).unwrap();
        let challenge = one.open(T + 5, None).unwrap();
        let (_, fresh) = one.satisfy(&proof(&challenge, &keys[0]), T + 5, None).unwrap();
        assert_eq!(one.session(&tokens[2], T + 6), None);
        assert_eq!(one.session(&fresh, T + 6), Some(keys[0].public()));
        assert_eq!(one.state.sessions().unwrap().len(), 1, "evictions reach the table");
        drop(one);
        assert!(at(ORIGIN, &dir, 100_000, T).is_ok(), "no cap ceiling");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn origin_must_be_an_http_service_name() {
        let dir = home("origin");
        assert_eq!(at("HTTP://x", &dir, DEFAULT_SESSIONS, T).unwrap_err(), Refusal::Origin);
        assert_eq!(at("", &dir, DEFAULT_SESSIONS, T).unwrap_err(), Refusal::Origin);
        assert_eq!(at("ftp://x", &dir, DEFAULT_SESSIONS, T).unwrap_err(), Refusal::Origin);
        assert_eq!(at("http://", &dir, DEFAULT_SESSIONS, T).unwrap_err(), Refusal::Origin);
        assert!(at(ORIGIN, &dir, DEFAULT_SESSIONS, T).is_ok());
        assert!(at("https://example.com", &dir, DEFAULT_SESSIONS, T).unwrap().secure());
    }

    #[test]
    fn the_service_follows_the_host_under_the_origin_scheme() {
        let dir = home("host");
        let logins = at("https://gw.example", &dir, DEFAULT_SESSIONS, T).unwrap();
        assert_eq!(logins.service(None).unwrap(), "https://gw.example");
        assert_eq!(logins.service(Some("alice.example")).unwrap(), "https://alice.example");
        assert_eq!(
            logins.service(Some("alice.example:8443")).unwrap(),
            "https://alice.example:8443"
        );
        assert_eq!(logins.service(Some("[::1]:8443")).unwrap(), "https://[::1]:8443");
        for bad in ["", "Alice.example", "a/b", "a?b", "a@b", "a b", &"x".repeat(254)] {
            assert_eq!(logins.service(Some(bad)).unwrap_err(), Refusal::Host, "{bad}");
        }
        let key = SecretKey::from_seed([1; 32]);
        let challenge = logins.open(T, Some("alice.example")).unwrap();
        assert_eq!(challenge.service, "https://alice.example");
        let Claim::Waiting(waiting) = logins.claim(&challenge.nonce, T + 1) else { panic!() };
        assert_eq!(waiting.service, "https://alice.example");
        let elsewhere = Challenge { service: "https://gw.example".into(), ..challenge.clone() };
        assert!(matches!(
            logins.satisfy(&proof(&elsewhere, &key), T + 1, None),
            Err(Refusal::Proof(_))
        ));
        assert!(logins.satisfy(&proof(&challenge, &key), T + 1, None).is_ok());
    }

    #[test]
    fn nonce_is_single_use_and_expires() {
        let logins = logins("nonce");
        let key = SecretKey::from_seed([1; 32]);
        let challenge = logins.open(T, None).unwrap();
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

        let late = logins.open(T, None).unwrap();
        assert!(matches!(logins.claim(&late.nonce, T + PENDING_TTL), Claim::Unknown));
        let stale = logins.open(T, None).unwrap();
        assert!(logins.satisfy(&proof(&stale, &key), T + PENDING_TTL, None).is_err());
        let unknown = Challenge { service: ORIGIN.into(), nonce: [7; 32], expires: T + 300 };
        assert_eq!(logins.satisfy(&proof(&unknown, &key), T + 1, None), Err(Refusal::Nonce));
        let used = Challenge { service: "http://evil".into(), ..challenge };
        assert_eq!(logins.satisfy(&proof(&used, &key), T + 1, None), Err(Refusal::Nonce));
        let elsewhere =
            Challenge { service: "http://evil".into(), ..logins.open(T, None).unwrap() };
        assert!(matches!(
            logins.satisfy(&proof(&elsewhere, &key), T + 1, None),
            Err(Refusal::Proof(_))
        ));
    }

    #[test]
    fn pending_is_capped_and_swept() {
        let logins = logins("capped");
        for _ in 0..PENDING_MAX {
            logins.open(T, None).unwrap();
        }
        assert_eq!(logins.open(T, None).err(), Some(Refusal::Full));
        logins.open(T + PENDING_TTL, None).unwrap();
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
        let secure = at("https://x", &home("secure"), DEFAULT_SESSIONS, T).unwrap();
        assert!(secure.cookie(Some(&token)).contains("Secure"));
    }

    #[test]
    fn sweep_drops_expired_sessions_from_the_table_and_allow_is_replaceable() {
        let dir = home("sweep");
        let key = SecretKey::from_seed([1; 32]);
        let logins = at(ORIGIN, &dir, DEFAULT_SESSIONS, T).unwrap();
        let challenge = logins.open(T, None).unwrap();
        let (_, token) = logins.satisfy(&proof(&challenge, &key), T + 1, None).unwrap();
        assert_eq!(logins.sweep(T + 2).unwrap(), 0);
        assert_eq!(logins.sweep(T + SESSION_TTL + 1).unwrap(), 1);
        assert_eq!(logins.session(&token, T + 2), None);
        assert!(logins.state.sessions().unwrap().is_empty(), "the sweep reached the table");

        let stranger = SecretKey::from_seed([2; 32]);
        assert!(logins.allows(&stranger.public()));
        logins.set_allow(Some(HashSet::from([key.public()])));
        assert!(!logins.allows(&stranger.public()));
        assert!(logins.allows(&key.public()));
        logins.set_allow(None);
        assert!(logins.allows(&stranger.public()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sessions_survive_a_restart_and_a_bad_table_refuses() {
        let dir = home("persist");
        let key = SecretKey::from_seed([1; 32]);
        let first = at(ORIGIN, &dir, DEFAULT_SESSIONS, T).unwrap();
        let challenge = first.open(T, None).unwrap();
        let (_, token) = first.satisfy(&proof(&challenge, &key), T + 1, None).unwrap();
        let stale = first.open(T, None).unwrap();
        let (_, old) = first.satisfy(&proof(&stale, &key), T + 1, None).unwrap();
        drop(first);

        let second = at(ORIGIN, &dir, DEFAULT_SESSIONS, T + 2).unwrap();
        assert_eq!(second.session(&token, T + 3), Some(key.public()));
        second.logout(&token).unwrap();
        drop(second);
        let third = at(ORIGIN, &dir, DEFAULT_SESSIONS, T + 4).unwrap();
        assert_eq!(third.session(&token, T + 5), None);
        assert_eq!(third.session(&old, T + 5), Some(key.public()));
        drop(third);
        let later = at(ORIGIN, &dir, DEFAULT_SESSIONS, T + SESSION_TTL + 2).unwrap();
        assert_eq!(later.session(&old, T + SESSION_TTL + 3), None);
        assert!(later.state.sessions().unwrap().is_empty(), "expired rows leave the table");
        drop(later);

        let path = dir.join(crate::state::FILE);
        let good = std::fs::read(&path).unwrap();
        std::fs::write(&path, &good[..64]).unwrap();
        assert!(matches!(State::open(&dir).unwrap_err(), Refusal::State(_)));
        std::fs::write(&path, b"not a database").unwrap();
        assert!(State::open(&dir).is_err());
        std::fs::write(&path, good).unwrap();
        assert!(at(ORIGIN, &dir, DEFAULT_SESSIONS, T).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allow_list_gates_identities() {
        let listed = SecretKey::from_seed([1; 32]);
        let stranger = SecretKey::from_seed([2; 32]);
        let text = format!(" {}\n\n", listed.public().address());
        let allow = allowlist(&text).unwrap();
        let logins =
            Logins::new(ORIGIN.into(), state(&home("allow")), Some(allow), DEFAULT_SESSIONS, T)
                .unwrap();
        assert!(logins.allows(&listed.public()));
        assert!(!logins.allows(&stranger.public()));
        let challenge = logins.open(T, None).unwrap();
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
