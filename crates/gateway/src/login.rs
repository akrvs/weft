use std::collections::HashMap;
use std::sync::Mutex;

use weft_core::{Challenge, Manifest, Proof, PublicKey, login};

pub const PENDING_TTL: u64 = 300;
pub const SESSION_TTL: u64 = 86_400;
pub const MAX_ENTRIES: usize = 1024;
pub const COOKIE: &str = "weft_session";

pub type Token = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Origin,
    Proof(weft_core::Error),
    Nonce,
    Full,
    Random,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Origin => f.write_str("origin is not a valid service name"),
            Self::Proof(e) => write!(f, "proof rejected: {e}"),
            Self::Nonce => f.write_str("challenge unknown, used, or expired"),
            Self::Full => f.write_str("too many logins in flight"),
            Self::Random => f.write_str("no randomness"),
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
    pending: Mutex<HashMap<[u8; 32], Pending>>,
    sessions: Mutex<HashMap<Token, Session>>,
}

fn random() -> Result<[u8; 32], Refusal> {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).map_err(|_| Refusal::Random)?;
    Ok(out)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn sweep<V>(map: &mut HashMap<[u8; 32], V>, now: u64, expires: impl Fn(&V) -> u64) {
    map.retain(|_, v| now < expires(v));
}

impl Logins {
    pub fn new(origin: String) -> Result<Self, Refusal> {
        if !login::valid_service(&origin) {
            return Err(Refusal::Origin);
        }
        Ok(Self {
            origin,
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        })
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
        sweep(&mut pending, now, |p| p.expires);
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
        let token = random()?;
        let mut pending = lock(&self.pending);
        let entry = pending.get_mut(&login.challenge.nonce).ok_or(Refusal::Nonce)?;
        if now >= entry.expires || entry.token.is_some() {
            return Err(Refusal::Nonce);
        }
        entry.token = Some(token);
        drop(pending);
        let mut sessions = lock(&self.sessions);
        sweep(&mut sessions, now, |s| s.expires);
        if sessions.len() >= MAX_ENTRIES {
            return Err(Refusal::Full);
        }
        let expires = now.saturating_add(SESSION_TTL);
        sessions.insert(token, Session { author: login.author, expires });
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

    pub fn logout(&self, token: &Token) {
        lock(&self.sessions).remove(token);
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

    fn proof(challenge: &Challenge, key: &SecretKey) -> Proof {
        let login = challenge.draft(&key.public(), &key.public(), T).sign(key).unwrap();
        Proof { login, manifest: None }
    }

    #[test]
    fn origin_must_be_a_service_name() {
        assert!(Logins::new("HTTP://x".into()).is_err());
        assert!(Logins::new(String::new()).is_err());
        assert!(Logins::new(ORIGIN.into()).is_ok());
        assert!(Logins::new("https://example.com".into()).unwrap().secure());
    }

    #[test]
    fn nonce_is_single_use_and_expires() {
        let logins = Logins::new(ORIGIN.into()).unwrap();
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
        logins.logout(&token);
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
        let logins = Logins::new(ORIGIN.into()).unwrap();
        for _ in 0..MAX_ENTRIES {
            logins.open(T).unwrap();
        }
        assert_eq!(logins.open(T).err(), Some(Refusal::Full));
        logins.open(T + PENDING_TTL).unwrap();
    }

    #[test]
    fn cookies_round_trip() {
        let logins = Logins::new(ORIGIN.into()).unwrap();
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
        assert!(Logins::new("https://x".into()).unwrap().cookie(Some(&token)).contains("Secure"));
    }
}
