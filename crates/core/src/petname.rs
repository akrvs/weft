use crate::cbor::{self, Value};
use crate::record::Body;
use crate::{Draft, Error, PublicKey, Record, Result};

pub const KIND: &str = "petname";
pub const POINTER: &str = "petnames";
pub const MAX_NAME: usize = 32;
pub const MAX_ENTRIES: usize = 512;

pub fn valid_petname(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_NAME
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Petname {
    pub name: String,
    pub key: PublicKey,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Petnames {
    pub names: Vec<Petname>,
}

impl Petnames {
    pub fn check(&self) -> Result<()> {
        if self.names.len() > MAX_ENTRIES {
            return Err(Error::Limit("names"));
        }
        if !self.names.iter().all(|p| valid_petname(&p.name)) {
            return Err(Error::Field("name"));
        }
        if !self.names.windows(2).all(|w| w[0].name < w[1].name) {
            return Err(Error::Field("names"));
        }
        Ok(())
    }

    pub fn key(&self, name: &str) -> Option<PublicKey> {
        self.position(name).ok().map(|i| self.names[i].key)
    }

    pub fn name(&self, key: &PublicKey) -> Option<&str> {
        self.names.iter().find(|p| &p.key == key).map(|p| p.name.as_str())
    }

    pub fn insert(&mut self, name: &str, key: PublicKey) -> Result<bool> {
        if !valid_petname(name) {
            return Err(Error::Field("name"));
        }
        match self.position(name) {
            Ok(_) => Ok(false),
            Err(_) if self.names.len() >= MAX_ENTRIES => Err(Error::Limit("names")),
            Err(i) => {
                self.names.insert(i, Petname { name: name.to_owned(), key });
                Ok(true)
            }
        }
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.position(name).map(|i| self.names.remove(i)).is_ok()
    }

    fn position(&self, name: &str) -> core::result::Result<usize, usize> {
        self.names.binary_search_by(|p| p.name.as_str().cmp(name))
    }

    pub fn encode(&self) -> Vec<u8> {
        Value::Map(vec![(
            "names".to_owned(),
            Value::Array(
                self.names
                    .iter()
                    .map(|p| {
                        Value::Map(vec![
                            ("key".to_owned(), Value::Bytes(p.key.bytes().to_vec())),
                            ("name".to_owned(), Value::Text(p.name.clone())),
                        ])
                    })
                    .collect(),
            ),
        )])
        .encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let value = cbor::decode(body)?;
        let m = value.as_map().ok_or(Error::Encoding("petnames is not a map"))?;
        cbor::only(m, &["names"])?;
        let list = Self {
            names: cbor::field(m, "names")?
                .as_array()
                .ok_or(Error::Field("names"))?
                .iter()
                .map(entry)
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

fn entry(v: &Value) -> Result<Petname> {
    let m = v.as_map().ok_or(Error::Field("names"))?;
    cbor::only(m, &["key", "name"])?;
    Ok(Petname {
        name: cbor::field(m, "name")?.as_text().ok_or(Error::Field("name"))?.to_owned(),
        key: PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "key")?, "key")?)?,
    })
}
