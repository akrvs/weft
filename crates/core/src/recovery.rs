use core::cmp::Ordering;

use crate::cbor::{self, Value};
use crate::record::Body;
use crate::{Address, Draft, Error, Manifest, PublicKey, Record, Result};

pub const KIND: &str = "recovery";
pub const DOMAIN: &[u8] = b"weft/recovery/1";
pub const MAX_PREV: usize = 16;
pub const MAX_SIGS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub key: PublicKey,
    pub sig: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    pub to: PublicKey,
    pub seq: u64,
    pub prev: Vec<Address>,
    pub sigs: Vec<Signature>,
}

fn addresses(v: &[Address]) -> Value {
    Value::Array(v.iter().map(|a| Value::Bytes(a.bytes().to_vec())).collect())
}

pub fn message(author: &PublicKey, to: &PublicKey, seq: u64, prev: &[Address]) -> Vec<u8> {
    Value::Map(vec![
        ("author".to_owned(), Value::Bytes(author.bytes().to_vec())),
        ("prev".to_owned(), addresses(prev)),
        ("seq".to_owned(), Value::Uint(seq)),
        ("to".to_owned(), Value::Bytes(to.bytes().to_vec())),
    ])
    .encode()
}

impl Recovery {
    pub fn check(&self, author: &PublicKey) -> Result<()> {
        if &self.to == author {
            return Err(Error::Field("to"));
        }
        if self.prev.len() > MAX_PREV {
            return Err(Error::Limit("prev"));
        }
        if self.sigs.is_empty() || self.sigs.len() > MAX_SIGS {
            return Err(Error::Limit("sigs"));
        }
        if self.sigs.windows(2).any(|w| w[0].key >= w[1].key) {
            return Err(Error::Field("sigs"));
        }
        Ok(())
    }

    pub fn message(&self, author: &PublicKey) -> Vec<u8> {
        message(author, &self.to, self.seq, &self.prev)
    }

    pub fn authorize(&self, author: &PublicKey, manifest: &Manifest) -> Result<()> {
        let guardians = manifest.guardians.as_ref().ok_or(Error::Unauthorized)?;
        let message = self.message(author);
        for s in &self.sigs {
            if guardians.keys.binary_search(&s.key).is_err() {
                return Err(Error::Unauthorized);
            }
            s.key.verify_in(DOMAIN, &message, &s.sig)?;
        }
        if self.sigs.len() < guardians.threshold {
            return Err(Error::Threshold);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let sigs = self
            .sigs
            .iter()
            .map(|s| {
                Value::Map(vec![
                    ("key".to_owned(), Value::Bytes(s.key.bytes().to_vec())),
                    ("sig".to_owned(), Value::Bytes(s.sig.to_vec())),
                ])
            })
            .collect();
        Value::Map(vec![
            ("prev".to_owned(), addresses(&self.prev)),
            ("seq".to_owned(), Value::Uint(self.seq)),
            ("sigs".to_owned(), Value::Array(sigs)),
            ("to".to_owned(), Value::Bytes(self.to.bytes().to_vec())),
        ])
        .encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let value = cbor::decode(body)?;
        let m = value.as_map().ok_or(Error::Encoding("recovery is not a map"))?;
        cbor::only(m, &["prev", "seq", "sigs", "to"])?;
        Ok(Self {
            to: PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "to")?, "to")?)?,
            seq: cbor::field(m, "seq")?.as_uint().ok_or(Error::Field("seq"))?,
            prev: cbor::field(m, "prev")?
                .as_array()
                .ok_or(Error::Field("prev"))?
                .iter()
                .map(|v| cbor::bytes32(v, "prev").map(Address::hash))
                .collect::<Result<Vec<_>>>()?,
            sigs: cbor::field(m, "sigs")?
                .as_array()
                .ok_or(Error::Field("sigs"))?
                .iter()
                .map(decode_signature)
                .collect::<Result<Vec<_>>>()?,
        })
    }

    pub fn draft(&self, author: &PublicKey, created: u64) -> Draft {
        Draft {
            author: *author,
            signer: self.to,
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
        let recovery = Self::decode(body)?;
        recovery.check(record.author())?;
        if &recovery.to != record.signer() {
            return Err(Error::Field("to"));
        }
        Ok(recovery)
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

fn decode_signature(v: &Value) -> Result<Signature> {
    let m = v.as_map().ok_or(Error::Field("sigs"))?;
    cbor::only(m, &["key", "sig"])?;
    let sig = cbor::field(m, "sig")?
        .as_bytes()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .ok_or(Error::Field("sig"))?;
    let key = PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "key")?, "key")?)?;
    Ok(Signature { key, sig })
}
