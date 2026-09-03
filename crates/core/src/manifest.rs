use crate::cbor::{self, Value};
use crate::record::Body;
use crate::{Address, Draft, Error, PublicKey, Record, Result};

pub const KIND: &str = "manifest";
pub const MAX_DEVICES: usize = 256;
pub const MAX_LABEL: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub key: PublicKey,
    pub label: String,
    pub created: u64,
    pub expires: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub seq: u64,
    pub prev: Option<Address>,
    pub devices: Vec<Device>,
    pub revoked: Vec<PublicKey>,
}

impl Manifest {
    pub fn check(&self, root: &PublicKey) -> Result<()> {
        if self.devices.len() > MAX_DEVICES || self.revoked.len() > MAX_DEVICES {
            return Err(Error::Limit("devices"));
        }
        if !strictly_sorted(self.devices.iter().map(|d| &d.key)) {
            return Err(Error::Field("devices"));
        }
        if !strictly_sorted(self.revoked.iter()) {
            return Err(Error::Field("revoked"));
        }
        for d in &self.devices {
            if &d.key == root || self.revoked.binary_search(&d.key).is_ok() {
                return Err(Error::Field("devices"));
            }
            if d.label.is_empty() || d.label.len() > MAX_LABEL {
                return Err(Error::Field("label"));
            }
            if d.expires.is_some_and(|e| e <= d.created) {
                return Err(Error::Field("expires"));
            }
        }
        if self.revoked.binary_search(root).is_ok() {
            return Err(Error::Field("revoked"));
        }
        Ok(())
    }

    pub fn authorizes(&self, key: &PublicKey, at: u64) -> Result<()> {
        if self.revoked.binary_search(key).is_ok() {
            return Err(Error::Revoked);
        }
        let device = self
            .devices
            .binary_search_by(|d| d.key.cmp(key))
            .ok()
            .and_then(|i| self.devices.get(i))
            .ok_or(Error::Unauthorized)?;
        if at < device.created || device.expires.is_some_and(|e| at >= e) {
            return Err(Error::Expired);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let devices = self
            .devices
            .iter()
            .map(|d| {
                let mut m = vec![
                    ("created".to_owned(), Value::Uint(d.created)),
                    ("key".to_owned(), Value::Bytes(d.key.bytes().to_vec())),
                    ("label".to_owned(), Value::Text(d.label.clone())),
                ];
                if let Some(e) = d.expires {
                    m.push(("expires".to_owned(), Value::Uint(e)));
                }
                Value::Map(m)
            })
            .collect();
        let mut m = vec![
            ("devices".to_owned(), Value::Array(devices)),
            (
                "revoked".to_owned(),
                Value::Array(
                    self.revoked.iter().map(|k| Value::Bytes(k.bytes().to_vec())).collect(),
                ),
            ),
            ("seq".to_owned(), Value::Uint(self.seq)),
        ];
        if let Some(p) = self.prev {
            m.push(("prev".to_owned(), Value::Bytes(p.bytes().to_vec())));
        }
        Value::Map(m).encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let value = cbor::decode(body)?;
        let m = value.as_map().ok_or(Error::Encoding("manifest is not a map"))?;
        cbor::only(m, &["devices", "prev", "revoked", "seq"])?;
        let seq = cbor::field(m, "seq")?.as_uint().ok_or(Error::Field("seq"))?;
        let prev = match cbor::optional(m, "prev") {
            Some(v) => Some(Address::hash(cbor::bytes32(v, "prev")?)),
            None => None,
        };
        let devices = cbor::field(m, "devices")?
            .as_array()
            .ok_or(Error::Field("devices"))?
            .iter()
            .map(decode_device)
            .collect::<Result<Vec<_>>>()?;
        let revoked = cbor::field(m, "revoked")?
            .as_array()
            .ok_or(Error::Field("revoked"))?
            .iter()
            .map(|v| cbor::bytes32(v, "revoked").and_then(|b| PublicKey::from_bytes(&b)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { seq, prev, devices, revoked })
    }

    pub fn draft(&self, root: &PublicKey, created: u64) -> Draft {
        Draft {
            author: *root,
            signer: *root,
            kind: KIND.to_owned(),
            created,
            refs: self.prev.into_iter().collect(),
            body: Body::Inline(self.encode()),
        }
    }

    pub fn from_record(record: &Record) -> Result<Self> {
        if record.kind() != KIND {
            return Err(Error::Field("kind"));
        }
        if !record.self_signed() {
            return Err(Error::Unauthorized);
        }
        let Body::Inline(body) = record.body() else { return Err(Error::Field("body")) };
        let manifest = Self::decode(body)?;
        manifest.check(record.author())?;
        Ok(manifest)
    }
}

fn decode_device(v: &Value) -> Result<Device> {
    let m = v.as_map().ok_or(Error::Field("devices"))?;
    cbor::only(m, &["created", "expires", "key", "label"])?;
    Ok(Device {
        key: PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "key")?, "key")?)?,
        label: cbor::field(m, "label")?.as_text().ok_or(Error::Field("label"))?.to_owned(),
        created: cbor::field(m, "created")?.as_uint().ok_or(Error::Field("created"))?,
        expires: match cbor::optional(m, "expires") {
            Some(e) => Some(e.as_uint().ok_or(Error::Field("expires"))?),
            None => None,
        },
    })
}

fn strictly_sorted<'a, I: Iterator<Item = &'a PublicKey>>(iter: I) -> bool {
    let mut prev: Option<&PublicKey> = None;
    for k in iter {
        if prev.is_some_and(|p| p >= k) {
            return false;
        }
        prev = Some(k);
    }
    true
}
