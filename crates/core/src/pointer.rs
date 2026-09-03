use core::cmp::Ordering;

use crate::cbor::{self, Value};
use crate::record::Body;
use crate::{Address, Draft, Error, PublicKey, Record, Result};

pub const KIND: &str = "pointer";
pub const MANIFEST: &str = "manifest";
pub const MAX_NAME: usize = 64;
pub const MAX_PREV: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pointer {
    pub name: String,
    pub target: Address,
    pub seq: u64,
    pub prev: Vec<Address>,
}

impl Pointer {
    pub fn check(&self) -> Result<()> {
        if self.name.is_empty() || self.name.len() > MAX_NAME {
            return Err(Error::Field("name"));
        }
        if self.prev.len() > MAX_PREV {
            return Err(Error::Limit("prev"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        Value::Map(vec![
            ("name".to_owned(), Value::Text(self.name.clone())),
            (
                "prev".to_owned(),
                Value::Array(self.prev.iter().map(|a| Value::Bytes(a.bytes().to_vec())).collect()),
            ),
            ("seq".to_owned(), Value::Uint(self.seq)),
            ("target".to_owned(), Value::Bytes(self.target.bytes().to_vec())),
        ])
        .encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let value = cbor::decode(body)?;
        let m = value.as_map().ok_or(Error::Encoding("pointer is not a map"))?;
        cbor::only(m, &["name", "prev", "seq", "target"])?;
        let pointer = Self {
            name: cbor::field(m, "name")?.as_text().ok_or(Error::Field("name"))?.to_owned(),
            target: Address::hash(cbor::bytes32(cbor::field(m, "target")?, "target")?),
            seq: cbor::field(m, "seq")?.as_uint().ok_or(Error::Field("seq"))?,
            prev: cbor::field(m, "prev")?
                .as_array()
                .ok_or(Error::Field("prev"))?
                .iter()
                .map(|v| cbor::bytes32(v, "prev").map(Address::hash))
                .collect::<Result<Vec<_>>>()?,
        };
        pointer.check()?;
        Ok(pointer)
    }

    pub fn draft(&self, author: &PublicKey, signer: &PublicKey, created: u64) -> Draft {
        Draft {
            author: *author,
            signer: *signer,
            kind: KIND.to_owned(),
            created,
            refs: self.prev.clone(),
            body: Body::Inline(self.encode()),
        }
    }

    pub fn from_record(record: &Record) -> Result<Self> {
        if record.kind() != KIND {
            return Err(Error::Field("kind"));
        }
        let Body::Inline(body) = record.body() else { return Err(Error::Field("body")) };
        let pointer = Self::decode(body)?;
        if pointer.name == MANIFEST && !record.self_signed() {
            return Err(Error::Unauthorized);
        }
        Ok(pointer)
    }

    pub fn compare(a: (&Record, &Self), b: (&Record, &Self)) -> Ordering {
        a.1.seq
            .cmp(&b.1.seq)
            .then(a.0.created().cmp(&b.0.created()))
            .then(b.0.address().cmp(&a.0.address()))
    }

    pub fn head<'a, I>(candidates: I) -> Option<(&'a Record, &'a Self)>
    where
        I: IntoIterator<Item = (&'a Record, &'a Self)>,
    {
        candidates.into_iter().max_by(|a, b| Self::compare(*a, *b))
    }
}
