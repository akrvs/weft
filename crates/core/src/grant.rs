use crate::cbor::{self, Value};
use crate::record::{Body, valid_kind};
use crate::{Address, Draft, Error, PublicKey, Record, Result};

pub const KIND: &str = "grant";
pub const REVOKE: &str = "revoke";
pub const MAX_KINDS: usize = 16;
pub const RESERVED: &[&str] = &[crate::manifest::KIND, crate::pointer::KIND, KIND, REVOKE];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}

impl Access {
    pub const fn bits(self) -> u64 {
        match self {
            Self::Read => 1,
            Self::Write => 2,
            Self::ReadWrite => 3,
        }
    }

    pub const fn from_bits(bits: u64) -> Result<Self> {
        match bits {
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::ReadWrite),
            _ => Err(Error::Field("access")),
        }
    }

    pub const fn reads(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    pub const fn writes(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

impl core::fmt::Display for Access {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read write",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub app: PublicKey,
    pub kinds: Vec<String>,
    pub access: Access,
    pub expires: Option<u64>,
}

impl Grant {
    pub fn check(&self) -> Result<()> {
        if self.kinds.is_empty() || self.kinds.len() > MAX_KINDS {
            return Err(Error::Limit("kinds"));
        }
        if !self.kinds.windows(2).all(|w| w[0] < w[1]) {
            return Err(Error::Field("kinds"));
        }
        if self.kinds.iter().any(|k| !valid_kind(k) || RESERVED.contains(&k.as_str())) {
            return Err(Error::Field("kinds"));
        }
        Ok(())
    }

    pub fn covers(&self, kind: &str) -> bool {
        self.kinds.binary_search_by(|k| k.as_str().cmp(kind)).is_ok()
    }

    pub fn active(&self, at: u64) -> bool {
        self.expires.is_none_or(|e| at < e)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut m = vec![
            ("access".to_owned(), Value::Uint(self.access.bits())),
            ("app".to_owned(), Value::Bytes(self.app.bytes().to_vec())),
            (
                "kinds".to_owned(),
                Value::Array(self.kinds.iter().map(|k| Value::Text(k.clone())).collect()),
            ),
        ];
        if let Some(e) = self.expires {
            m.push(("expires".to_owned(), Value::Uint(e)));
        }
        Value::Map(m).encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let value = cbor::decode(body)?;
        let m = value.as_map().ok_or(Error::Encoding("grant is not a map"))?;
        cbor::only(m, &["access", "app", "expires", "kinds"])?;
        let grant = Self {
            app: PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "app")?, "app")?)?,
            kinds: cbor::field(m, "kinds")?
                .as_array()
                .ok_or(Error::Field("kinds"))?
                .iter()
                .map(|v| v.as_text().map(str::to_owned).ok_or(Error::Field("kinds")))
                .collect::<Result<Vec<_>>>()?,
            access: Access::from_bits(
                cbor::field(m, "access")?.as_uint().ok_or(Error::Field("access"))?,
            )?,
            expires: match cbor::optional(m, "expires") {
                Some(v) => Some(v.as_uint().ok_or(Error::Field("expires"))?),
                None => None,
            },
        };
        grant.check()?;
        Ok(grant)
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
        let grant = Self::decode(body)?;
        if grant.expires.is_some_and(|e| e <= record.created()) {
            return Err(Error::Field("expires"));
        }
        Ok(grant)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revoke {
    pub grant: Address,
}

impl Revoke {
    pub fn encode(&self) -> Vec<u8> {
        Value::Map(vec![("grant".to_owned(), Value::Bytes(self.grant.bytes().to_vec()))]).encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let value = cbor::decode(body)?;
        let m = value.as_map().ok_or(Error::Encoding("revoke is not a map"))?;
        cbor::only(m, &["grant"])?;
        Ok(Self { grant: Address::hash(cbor::bytes32(cbor::field(m, "grant")?, "grant")?) })
    }

    pub fn draft(&self, author: &PublicKey, signer: &PublicKey, created: u64) -> Draft {
        Draft {
            author: *author,
            signer: *signer,
            kind: REVOKE.to_owned(),
            created,
            refs: vec![self.grant],
            body: Body::Inline(self.encode()),
        }
    }

    pub fn from_record(record: &Record) -> Result<Self> {
        if record.kind() != REVOKE {
            return Err(Error::Field("kind"));
        }
        let Body::Inline(body) = record.body() else { return Err(Error::Field("body")) };
        let revoke = Self::decode(body)?;
        if !record.refs().contains(&revoke.grant) {
            return Err(Error::Field("refs"));
        }
        Ok(revoke)
    }
}
