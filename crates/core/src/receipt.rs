use crate::cbor::{self, Value};
use crate::record::Body;
use crate::{Address, Draft, Error, PublicKey, Record, Result, SecretKey};

pub const KIND: &str = "receipt";
pub const VOUCHER_DOMAIN: &[u8] = b"weft/voucher/1";
pub const MAX_RECORDS: usize = 64;
pub const MAX_VOUCHER: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Voucher {
    pub bank: PublicKey,
    pub to: PublicKey,
    pub cents: u64,
    pub nonce: [u8; 32],
    pub sig: [u8; 64],
}

impl Voucher {
    pub fn mint(bank: &SecretKey, to: PublicKey, cents: u64, nonce: [u8; 32]) -> Result<Self> {
        if cents == 0 {
            return Err(Error::Field("cents"));
        }
        let unsigned = Self { bank: bank.public(), to, cents, nonce, sig: [0; 64] };
        let sig = bank.sign_in(VOUCHER_DOMAIN, &unsigned.message().encode());
        Ok(Self { sig, ..unsigned })
    }

    fn message(&self) -> Value {
        Value::Map(vec![
            ("bank".to_owned(), Value::Bytes(self.bank.bytes().to_vec())),
            ("cents".to_owned(), Value::Uint(self.cents)),
            ("nonce".to_owned(), Value::Bytes(self.nonce.to_vec())),
            ("to".to_owned(), Value::Bytes(self.to.bytes().to_vec())),
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        let Value::Map(mut m) = self.message() else { return Vec::new() };
        m.push(("sig".to_owned(), Value::Bytes(self.sig.to_vec())));
        Value::Map(m).encode()
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() > MAX_VOUCHER {
            return Err(Error::Limit("voucher"));
        }
        let value = cbor::decode(buf)?;
        let m = value.as_map().ok_or(Error::Encoding("voucher is not a map"))?;
        cbor::only(m, &["bank", "cents", "nonce", "sig", "to"])?;
        let voucher = Self {
            bank: PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "bank")?, "bank")?)?,
            to: PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "to")?, "to")?)?,
            cents: cbor::field(m, "cents")?.as_uint().ok_or(Error::Field("cents"))?,
            nonce: cbor::bytes32(cbor::field(m, "nonce")?, "nonce")?,
            sig: cbor::field(m, "sig")?
                .as_bytes()
                .and_then(|b| b.try_into().ok())
                .ok_or(Error::Field("sig"))?,
        };
        if voucher.cents == 0 {
            return Err(Error::Field("cents"));
        }
        voucher.bank.verify_in(VOUCHER_DOMAIN, &voucher.message().encode(), &voucher.sig)?;
        Ok(voucher)
    }

    pub fn id(&self) -> Address {
        Address::of(&self.encode())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub relay: PublicKey,
    pub records: Vec<Address>,
    pub until: u64,
    pub voucher: Voucher,
}

impl Receipt {
    pub fn check(&self) -> Result<()> {
        if self.records.is_empty() || self.records.len() > MAX_RECORDS {
            return Err(Error::Limit("records"));
        }
        if !self.records.windows(2).all(|w| w[0] < w[1]) {
            return Err(Error::Field("records"));
        }
        if self.records.iter().any(|r| r.kind() != crate::address::Kind::Hash) {
            return Err(Error::Field("records"));
        }
        if self.voucher.to != self.relay {
            return Err(Error::Field("relay"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        Value::Map(vec![
            ("records".to_owned(), Value::Array(addresses(&self.records))),
            ("relay".to_owned(), Value::Bytes(self.relay.bytes().to_vec())),
            ("until".to_owned(), Value::Uint(self.until)),
            ("voucher".to_owned(), Value::Bytes(self.voucher.encode())),
        ])
        .encode()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let value = cbor::decode(body)?;
        let m = value.as_map().ok_or(Error::Encoding("receipt is not a map"))?;
        cbor::only(m, &["records", "relay", "until", "voucher"])?;
        let receipt = Self {
            relay: PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "relay")?, "relay")?)?,
            records: cbor::field(m, "records")?
                .as_array()
                .ok_or(Error::Field("records"))?
                .iter()
                .map(|v| cbor::bytes32(v, "records").map(Address::hash))
                .collect::<Result<Vec<_>>>()?,
            until: cbor::field(m, "until")?.as_uint().ok_or(Error::Field("until"))?,
            voucher: Voucher::decode(
                cbor::field(m, "voucher")?.as_bytes().ok_or(Error::Field("voucher"))?,
            )?,
        };
        receipt.check()?;
        Ok(receipt)
    }

    pub fn draft(&self, author: &PublicKey, signer: &PublicKey, created: u64) -> Draft {
        Draft {
            author: *author,
            signer: *signer,
            kind: KIND.to_owned(),
            created,
            refs: self.records.clone(),
            body: Body::Inline(self.encode()),
        }
    }

    pub fn from_record(record: &Record) -> Result<Self> {
        if record.kind() != KIND {
            return Err(Error::Field("kind"));
        }
        let Body::Inline(body) = record.body() else { return Err(Error::Field("body")) };
        let receipt = Self::decode(body)?;
        if receipt.until <= record.created() {
            return Err(Error::Field("until"));
        }
        if receipt.records.iter().any(|r| !record.refs().contains(r)) {
            return Err(Error::Field("refs"));
        }
        Ok(receipt)
    }
}

fn addresses(list: &[Address]) -> Vec<Value> {
    list.iter().map(|a| Value::Bytes(a.bytes().to_vec())).collect()
}
