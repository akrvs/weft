use crate::cbor::{self, Value};
use crate::record::Body;
use crate::{Draft, Error, PublicKey, Record, Result};

pub const KIND: &str = "follow";
pub const POINTER: &str = "follows";
pub const MAX_ENTRIES: usize = 512;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Follows {
    pub keys: Vec<PublicKey>,
}

impl Follows {
    pub fn check(&self) -> Result<()> {
        if self.keys.len() > MAX_ENTRIES {
            return Err(Error::Limit("follows"));
        }
        if !self.keys.windows(2).all(|w| w[0].bytes() < w[1].bytes()) {
            return Err(Error::Field("follows"));
        }
        Ok(())
    }

    pub fn contains(&self, key: &PublicKey) -> bool {
        self.position(key).is_ok()
    }

    pub fn insert(&mut self, key: PublicKey) -> Result<bool> {
        match self.position(&key) {
            Ok(_) => Ok(false),
            Err(_) if self.keys.len() >= MAX_ENTRIES => Err(Error::Limit("follows")),
            Err(i) => {
                self.keys.insert(i, key);
                Ok(true)
            }
        }
    }

    pub fn remove(&mut self, key: &PublicKey) -> bool {
        self.position(key).map(|i| self.keys.remove(i)).is_ok()
    }

    fn position(&self, key: &PublicKey) -> core::result::Result<usize, usize> {
        self.keys.binary_search_by(|k| k.bytes().cmp(key.bytes()))
    }

    pub fn encode(&self) -> Vec<u8> {
        Value::Map(vec![(
            "follows".to_owned(),
            Value::Array(self.keys.iter().map(|k| Value::Bytes(k.bytes().to_vec())).collect()),
        )])
        .encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let value = cbor::decode(body)?;
        let m = value.as_map().ok_or(Error::Encoding("follows is not a map"))?;
        cbor::only(m, &["follows"])?;
        let list = Self {
            keys: cbor::field(m, "follows")?
                .as_array()
                .ok_or(Error::Field("follows"))?
                .iter()
                .map(|v| PublicKey::from_bytes(&cbor::bytes32(v, "follows")?))
                .collect::<Result<Vec<_>>>()?,
        };
        list.check()?;
        Ok(list)
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
        Self::decode(body)
    }
}
