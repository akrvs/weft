use data_encoding::BASE64URL_NOPAD;

use crate::cbor::{self, Value};
use crate::record::Body;
use crate::{Draft, Error, Manifest, PublicKey, Record, Result, manifest, verify};

pub const KIND: &str = "login";
pub const MAX_SERVICE: usize = 253;
pub const MAX_PROOF: usize = 65_536;

pub fn valid_service(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SERVICE
        && s.bytes().all(|b| (0x21..=0x7e).contains(&b) && !b.is_ascii_uppercase())
}

pub fn to_text(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

pub fn from_text(text: &str) -> Result<Vec<u8>> {
    if text.len() > MAX_PROOF / 3 * 4 + 4 {
        return Err(Error::Limit("text"));
    }
    BASE64URL_NOPAD.decode(text.as_bytes()).map_err(|_| Error::Encoding("not base64url"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub service: String,
    pub nonce: [u8; 32],
    pub expires: u64,
}

impl Challenge {
    pub fn check(&self) -> Result<()> {
        if valid_service(&self.service) { Ok(()) } else { Err(Error::Field("service")) }
    }

    pub fn encode(&self) -> Vec<u8> {
        Value::Map(vec![
            ("expires".to_owned(), Value::Uint(self.expires)),
            ("nonce".to_owned(), Value::Bytes(self.nonce.to_vec())),
            ("service".to_owned(), Value::Text(self.service.clone())),
        ])
        .encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let value = cbor::decode(body)?;
        let m = value.as_map().ok_or(Error::Encoding("challenge is not a map"))?;
        cbor::only(m, &["expires", "nonce", "service"])?;
        let challenge = Self {
            service: cbor::field(m, "service")?
                .as_text()
                .ok_or(Error::Field("service"))?
                .to_owned(),
            nonce: cbor::bytes32(cbor::field(m, "nonce")?, "nonce")?,
            expires: cbor::field(m, "expires")?.as_uint().ok_or(Error::Field("expires"))?,
        };
        challenge.check()?;
        Ok(challenge)
    }

    pub fn to_text(&self) -> String {
        to_text(&self.encode())
    }

    pub fn from_text(text: &str) -> Result<Self> {
        Self::decode(&from_text(text)?)
    }

    pub fn draft(&self, author: &PublicKey, signer: &PublicKey, created: u64) -> Draft {
        Draft {
            author: *author,
            signer: *signer,
            kind: KIND.to_owned(),
            created,
            refs: vec![],
            body: Body::Inline(self.encode()),
        }
    }

    pub fn from_record(record: &Record) -> Result<Self> {
        if record.kind() != KIND {
            return Err(Error::Field("kind"));
        }
        let Body::Inline(body) = record.body() else { return Err(Error::Field("body")) };
        if !record.refs().is_empty() {
            return Err(Error::Field("refs"));
        }
        let challenge = Self::decode(body)?;
        if challenge.expires <= record.created() {
            return Err(Error::Field("expires"));
        }
        Ok(challenge)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    pub author: PublicKey,
    pub signer: PublicKey,
    pub challenge: Challenge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub login: Record,
    pub manifest: Option<Record>,
}

impl Proof {
    pub fn encode(&self) -> Vec<u8> {
        let mut m = vec![("login".to_owned(), Value::Bytes(self.login.to_bytes()))];
        if let Some(r) = &self.manifest {
            m.push(("manifest".to_owned(), Value::Bytes(r.to_bytes())));
        }
        Value::Map(m).encode()
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() > MAX_PROOF {
            return Err(Error::Limit("proof"));
        }
        let value = cbor::decode(buf)?;
        let m = value.as_map().ok_or(Error::Encoding("proof is not a map"))?;
        cbor::only(m, &["login", "manifest"])?;
        let login = cbor::field(m, "login")?.as_bytes().ok_or(Error::Field("login"))?;
        let manifest = match cbor::optional(m, "manifest") {
            Some(v) => Some(Record::from_bytes(v.as_bytes().ok_or(Error::Field("manifest"))?)?),
            None => None,
        };
        Ok(Self { login: Record::from_bytes(login)?, manifest })
    }

    pub fn to_text(&self) -> String {
        to_text(&self.encode())
    }

    pub fn from_text(text: &str) -> Result<Self> {
        Self::decode(&from_text(text)?)
    }

    fn inline_manifest(&self) -> Result<Option<Manifest>> {
        let Some(record) = &self.manifest else { return Ok(None) };
        if record.kind() != manifest::KIND || record.author() != self.login.author() {
            return Err(Error::Login("manifest is not the author's"));
        }
        verify(record, None)?;
        Ok(Some(Manifest::from_record(record)?))
    }

    pub fn verify(&self, service: &str, now: u64, newer: Option<&Manifest>) -> Result<Login> {
        if self.login.kind() != KIND {
            return Err(Error::Field("kind"));
        }
        let inline = self.inline_manifest()?;
        let chosen = match (inline.as_ref(), newer) {
            (Some(a), Some(b)) => Some(if b.seq > a.seq { b } else { a }),
            (a, b) => a.or(b),
        };
        verify(&self.login, chosen)?;
        let challenge = Challenge::from_record(&self.login)?;
        if challenge.service != service {
            return Err(Error::Login("service mismatch"));
        }
        if now >= challenge.expires {
            return Err(Error::Login("challenge expired"));
        }
        Ok(Login { author: *self.login.author(), signer: *self.login.signer(), challenge })
    }
}
