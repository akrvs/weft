use iroh::endpoint::{RecvStream, SendStream};
use weft_core::cbor::{self, Value};
use weft_core::{Address, Error as CoreError, PublicKey};

use crate::error::net;
use crate::{Error, Result};

pub const ALPN: &[u8] = b"weft/relay/1";
pub const MAX_FRAME: usize = 1 << 20;
pub const MAX_BATCH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Put { records: Vec<Vec<u8>> },
    Get { address: Address },
    Head { author: PublicKey, name: String },
    Price,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Put { stored: Vec<Address>, rejected: Vec<(u64, String)> },
    Get { record: Option<Vec<u8>> },
    Head { pointer: Option<Vec<u8>>, manifest: Option<Vec<u8>> },
    Price { rate: u64, banks: Vec<PublicKey> },
    Error { why: String },
}

fn bytes32(a: &[u8; 32]) -> Value {
    Value::Bytes(a.to_vec())
}

fn opt_bytes(v: Option<&Vec<u8>>) -> Vec<(String, Value)> {
    v.map(|b| Value::Bytes(b.clone())).into_iter().map(|b| (String::new(), b)).collect()
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let m = match self {
            Self::Put { records } => vec![
                (
                    "records".to_owned(),
                    Value::Array(records.iter().map(|r| Value::Bytes(r.clone())).collect()),
                ),
                ("t".to_owned(), Value::Text("put".to_owned())),
            ],
            Self::Get { address } => {
                vec![
                    ("address".to_owned(), bytes32(address.bytes())),
                    ("t".to_owned(), Value::Text("get".to_owned())),
                ]
            }
            Self::Head { author, name } => vec![
                ("author".to_owned(), bytes32(author.bytes())),
                ("name".to_owned(), Value::Text(name.clone())),
                ("t".to_owned(), Value::Text("head".to_owned())),
            ],
            Self::Price => vec![("t".to_owned(), Value::Text("price".to_owned()))],
        };
        Value::Map(m).encode()
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let value = cbor::decode(buf)?;
        let m = value.as_map().ok_or(Error::Wire("request is not a map"))?;
        match cbor::field(m, "t")?.as_text().ok_or(CoreError::Field("t"))? {
            "put" => {
                cbor::only(m, &["records", "t"])?;
                let records = cbor::field(m, "records")?
                    .as_array()
                    .ok_or(CoreError::Field("records"))?
                    .iter()
                    .map(|v| {
                        v.as_bytes()
                            .map(<[u8]>::to_vec)
                            .ok_or(Error::Core(CoreError::Field("records")))
                    })
                    .collect::<Result<Vec<_>>>()?;
                if records.len() > MAX_BATCH {
                    return Err(Error::Wire("batch too large"));
                }
                Ok(Self::Put { records })
            }
            "get" => {
                cbor::only(m, &["address", "t"])?;
                Ok(Self::Get {
                    address: Address::hash(cbor::bytes32(cbor::field(m, "address")?, "address")?),
                })
            }
            "head" => {
                cbor::only(m, &["author", "name", "t"])?;
                let author =
                    PublicKey::from_bytes(&cbor::bytes32(cbor::field(m, "author")?, "author")?)?;
                let name =
                    cbor::field(m, "name")?.as_text().ok_or(CoreError::Field("name"))?.to_owned();
                if name.is_empty() || name.len() > weft_core::pointer::MAX_NAME {
                    return Err(Error::Core(CoreError::Field("name")));
                }
                Ok(Self::Head { author, name })
            }
            "price" => {
                cbor::only(m, &["t"])?;
                Ok(Self::Price)
            }
            _ => Err(Error::Wire("unknown request type")),
        }
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let mut m = match self {
            Self::Put { stored, rejected } => vec![
                (
                    "rejected".to_owned(),
                    Value::Array(
                        rejected
                            .iter()
                            .map(|(i, why)| {
                                Value::Array(vec![Value::Uint(*i), Value::Text(why.clone())])
                            })
                            .collect(),
                    ),
                ),
                (
                    "stored".to_owned(),
                    Value::Array(stored.iter().map(|a| bytes32(a.bytes())).collect()),
                ),
                ("t".to_owned(), Value::Text("put".to_owned())),
            ],
            Self::Get { record } => {
                let mut m = vec![("t".to_owned(), Value::Text("get".to_owned()))];
                m.extend(
                    opt_bytes(record.as_ref()).into_iter().map(|(_, v)| ("record".to_owned(), v)),
                );
                m
            }
            Self::Head { pointer, manifest } => {
                let mut m = vec![("t".to_owned(), Value::Text("head".to_owned()))];
                m.extend(
                    opt_bytes(pointer.as_ref()).into_iter().map(|(_, v)| ("pointer".to_owned(), v)),
                );
                m.extend(
                    opt_bytes(manifest.as_ref())
                        .into_iter()
                        .map(|(_, v)| ("manifest".to_owned(), v)),
                );
                m
            }
            Self::Price { rate, banks } => vec![
                (
                    "banks".to_owned(),
                    Value::Array(banks.iter().map(|b| bytes32(b.bytes())).collect()),
                ),
                ("rate".to_owned(), Value::Uint(*rate)),
                ("t".to_owned(), Value::Text("price".to_owned())),
            ],
            Self::Error { why } => {
                vec![
                    ("t".to_owned(), Value::Text("error".to_owned())),
                    ("why".to_owned(), Value::Text(why.clone())),
                ]
            }
        };
        m.sort_by(|a, b| a.0.cmp(&b.0));
        Value::Map(m).encode()
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let value = cbor::decode(buf)?;
        let m = value.as_map().ok_or(Error::Wire("response is not a map"))?;
        let bytes = |k: &str| {
            cbor::optional(m, k)
                .map(|v| v.as_bytes().map(<[u8]>::to_vec).ok_or(Error::Wire("bytes")))
        };
        match cbor::field(m, "t")?.as_text().ok_or(CoreError::Field("t"))? {
            "put" => {
                cbor::only(m, &["rejected", "stored", "t"])?;
                let stored = cbor::field(m, "stored")?
                    .as_array()
                    .ok_or(CoreError::Field("stored"))?
                    .iter()
                    .map(|v| cbor::bytes32(v, "stored").map(Address::hash))
                    .collect::<core::result::Result<Vec<_>, _>>()?;
                let rejected = cbor::field(m, "rejected")?
                    .as_array()
                    .ok_or(CoreError::Field("rejected"))?
                    .iter()
                    .map(|v| {
                        let pair = v.as_array().ok_or(Error::Wire("rejected"))?;
                        match pair {
                            [Value::Uint(i), Value::Text(why)] => Ok((*i, why.clone())),
                            _ => Err(Error::Wire("rejected")),
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Self::Put { stored, rejected })
            }
            "get" => {
                cbor::only(m, &["record", "t"])?;
                Ok(Self::Get { record: bytes("record").transpose()? })
            }
            "head" => {
                cbor::only(m, &["manifest", "pointer", "t"])?;
                Ok(Self::Head {
                    pointer: bytes("pointer").transpose()?,
                    manifest: bytes("manifest").transpose()?,
                })
            }
            "price" => {
                cbor::only(m, &["banks", "rate", "t"])?;
                let banks = cbor::field(m, "banks")?
                    .as_array()
                    .ok_or(CoreError::Field("banks"))?
                    .iter()
                    .map(|v| cbor::bytes32(v, "banks").and_then(|b| PublicKey::from_bytes(&b)))
                    .collect::<core::result::Result<Vec<_>, _>>()?;
                let rate = cbor::field(m, "rate")?.as_uint().ok_or(CoreError::Field("rate"))?;
                Ok(Self::Price { rate, banks })
            }
            "error" => {
                cbor::only(m, &["t", "why"])?;
                Ok(Self::Error {
                    why: cbor::field(m, "why")?
                        .as_text()
                        .ok_or(CoreError::Field("why"))?
                        .to_owned(),
                })
            }
            _ => Err(Error::Wire("unknown response type")),
        }
    }
}

pub async fn send(stream: &mut SendStream, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| Error::Wire("frame too large"))?;
    if payload.len() > MAX_FRAME {
        return Err(Error::Wire("frame too large"));
    }
    stream.write_all(&len.to_be_bytes()).await.map_err(net)?;
    stream.write_all(payload).await.map_err(net)?;
    stream.finish().map_err(net)?;
    Ok(())
}

pub async fn recv(stream: &mut RecvStream) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(net)?;
    let len =
        usize::try_from(u32::from_be_bytes(head)).map_err(|_| Error::Wire("frame too large"))?;
    if len > MAX_FRAME {
        return Err(Error::Wire("frame too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.map_err(net)?;
    Ok(buf)
}
