use crate::address::Kind;
use crate::cbor::{self, Value};
use crate::record::{Body, valid_kind};
use crate::{Address, Draft, Error, PublicKey, Record, Result};

pub const KIND: &str = "label";
pub const POINTER: &str = "labels";
pub const MAX_ENTRIES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Label {
    pub subject: Address,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Labels {
    pub labels: Vec<Label>,
}

impl Labels {
    pub fn check(&self) -> Result<()> {
        if self.labels.len() > MAX_ENTRIES {
            return Err(Error::Limit("labels"));
        }
        if !self.labels.iter().all(|l| valid_kind(&l.value)) {
            return Err(Error::Field("value"));
        }
        if !self.labels.windows(2).all(|w| w[0] < w[1]) {
            return Err(Error::Field("labels"));
        }
        Ok(())
    }

    pub fn on<'a>(
        &'a self,
        record: &'a Address,
        author: &'a Address,
    ) -> impl Iterator<Item = &'a str> + 'a {
        self.labels
            .iter()
            .filter(move |l| &l.subject == record || &l.subject == author)
            .map(|l| l.value.as_str())
    }

    pub fn insert(&mut self, label: Label) -> Result<bool> {
        if !valid_kind(&label.value) {
            return Err(Error::Field("value"));
        }
        match self.labels.binary_search(&label) {
            Ok(_) => Ok(false),
            Err(_) if self.labels.len() >= MAX_ENTRIES => Err(Error::Limit("labels")),
            Err(i) => {
                self.labels.insert(i, label);
                Ok(true)
            }
        }
    }

    pub fn remove(&mut self, label: &Label) -> bool {
        self.labels.binary_search(label).map(|i| self.labels.remove(i)).is_ok()
    }

    pub fn encode(&self) -> Vec<u8> {
        Value::Map(vec![(
            "labels".to_owned(),
            Value::Array(
                self.labels
                    .iter()
                    .map(|l| {
                        let side = match l.subject.kind() {
                            Kind::Key => "key",
                            Kind::Hash => "record",
                        };
                        Value::Map(vec![
                            (side.to_owned(), Value::Bytes(l.subject.bytes().to_vec())),
                            ("value".to_owned(), Value::Text(l.value.clone())),
                        ])
                    })
                    .collect(),
            ),
        )])
        .encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let value = cbor::decode(body)?;
        let m = value.as_map().ok_or(Error::Encoding("labels is not a map"))?;
        cbor::only(m, &["labels"])?;
        let list = Self {
            labels: cbor::field(m, "labels")?
                .as_array()
                .ok_or(Error::Field("labels"))?
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

fn entry(v: &Value) -> Result<Label> {
    let m = v.as_map().ok_or(Error::Field("labels"))?;
    cbor::only(m, &["key", "record", "value"])?;
    let subject = match (cbor::optional(m, "key"), cbor::optional(m, "record")) {
        (Some(k), None) => PublicKey::from_bytes(&cbor::bytes32(k, "key")?)?.address(),
        (None, Some(r)) => Address::hash(cbor::bytes32(r, "record")?),
        _ => return Err(Error::Field("subject")),
    };
    let value = cbor::field(m, "value")?.as_text().ok_or(Error::Field("value"))?.to_owned();
    Ok(Label { subject, value })
}
