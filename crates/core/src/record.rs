use crate::cbor::{self, Value};
use crate::{Address, Error, PublicKey, Result, SecretKey};

pub const MAX_INLINE: usize = 65_536;
pub const MAX_REFS: usize = 1024;
pub const MAX_KIND: usize = 32;

const FIELDS: &[&str] = &["author", "blob", "body", "created", "kind", "refs", "sig", "signer"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Inline(Vec<u8>),
    Blob(Address),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub author: PublicKey,
    pub signer: PublicKey,
    pub kind: String,
    pub created: u64,
    pub refs: Vec<Address>,
    pub body: Body,
}

impl Draft {
    pub fn sign(self, key: &SecretKey) -> Result<Record> {
        if key.public() != self.signer {
            return Err(Error::Unauthorized);
        }
        self.check()?;
        let sig = key.sign(&self.encode().encode());
        Ok(Record { draft: self, sig })
    }

    fn check(&self) -> Result<()> {
        if !valid_kind(&self.kind) {
            return Err(Error::Field("kind"));
        }
        if self.refs.len() > MAX_REFS {
            return Err(Error::Limit("refs"));
        }
        if self.refs.iter().any(|r| r.kind() != crate::address::Kind::Hash) {
            return Err(Error::Field("refs"));
        }
        match &self.body {
            Body::Inline(b) if b.len() > MAX_INLINE => Err(Error::Limit("body")),
            Body::Blob(a) if a.kind() != crate::address::Kind::Hash => Err(Error::Field("blob")),
            _ => Ok(()),
        }
    }

    fn encode(&self) -> Value {
        let mut m = vec![
            ("author".to_owned(), Value::Bytes(self.author.bytes().to_vec())),
            ("created".to_owned(), Value::Uint(self.created)),
            ("kind".to_owned(), Value::Text(self.kind.clone())),
            (
                "refs".to_owned(),
                Value::Array(self.refs.iter().map(|r| Value::Bytes(r.bytes().to_vec())).collect()),
            ),
            ("signer".to_owned(), Value::Bytes(self.signer.bytes().to_vec())),
        ];
        match &self.body {
            Body::Inline(b) => m.push(("body".to_owned(), Value::Bytes(b.clone()))),
            Body::Blob(a) => m.push(("blob".to_owned(), Value::Bytes(a.bytes().to_vec()))),
        }
        Value::Map(m)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    draft: Draft,
    sig: [u8; 64],
}

impl Record {
    pub fn author(&self) -> &PublicKey {
        &self.draft.author
    }

    pub fn signer(&self) -> &PublicKey {
        &self.draft.signer
    }

    pub fn kind(&self) -> &str {
        &self.draft.kind
    }

    pub fn created(&self) -> u64 {
        self.draft.created
    }

    pub fn refs(&self) -> &[Address] {
        &self.draft.refs
    }

    pub fn body(&self) -> &Body {
        &self.draft.body
    }

    pub fn signature(&self) -> &[u8; 64] {
        &self.sig
    }

    pub fn self_signed(&self) -> bool {
        self.draft.author == self.draft.signer
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let Value::Map(mut m) = self.draft.encode() else { return Vec::new() };
        m.push(("sig".to_owned(), Value::Bytes(self.sig.to_vec())));
        Value::Map(m).encode()
    }

    pub fn address(&self) -> Address {
        Address::of(&self.to_bytes())
    }

    pub fn check_signature(&self) -> Result<()> {
        self.draft.signer.verify(&self.draft.encode().encode(), &self.sig)
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let value = cbor::decode(buf)?;
        let m = value.as_map().ok_or(Error::Encoding("record is not a map"))?;
        cbor::only(m, FIELDS)?;
        let author = PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "author")?, "author")?)?;
        let signer = PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "signer")?, "signer")?)?;
        let kind = cbor::field(m, "kind")?.as_text().ok_or(Error::Field("kind"))?.to_owned();
        let created = cbor::field(m, "created")?.as_uint().ok_or(Error::Field("created"))?;
        let refs = cbor::field(m, "refs")?
            .as_array()
            .ok_or(Error::Field("refs"))?
            .iter()
            .map(|v| cbor::bytes32(v, "refs").map(Address::hash))
            .collect::<Result<Vec<_>>>()?;
        let body = match (cbor::optional(m, "body"), cbor::optional(m, "blob")) {
            (Some(b), None) => Body::Inline(b.as_bytes().ok_or(Error::Field("body"))?.to_vec()),
            (None, Some(h)) => Body::Blob(Address::hash(cbor::bytes32(h, "blob")?)),
            _ => return Err(Error::Field("body")),
        };
        let sig: [u8; 64] = cbor::field(m, "sig")?
            .as_bytes()
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::Field("sig"))?;
        let draft = Draft { author, signer, kind, created, refs, body };
        draft.check()?;
        Ok(Self { draft, sig })
    }
}

fn valid_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= MAX_KIND
        && kind.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
