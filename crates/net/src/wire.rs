use iroh::endpoint::{RecvStream, SendStream};
use weft_core::cbor::{self, Value};
use weft_core::{Address, Error as CoreError, PublicKey};

use crate::error::net;
use crate::{Error, Result};

pub const ALPN: &[u8] = b"weft/relay/1";
pub const MAX_FRAME: usize = 1 << 20;
pub const MAX_BATCH: usize = 64;
pub const MAX_CENTS: u64 = 1_000_000_000;
pub const MAX_BOLT11: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Put { records: Vec<Vec<u8>> },
    Get { address: Address },
    Head { author: PublicKey, name: String },
    Price,
    Size { address: Address },
    Invoice { cents: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Put { stored: Vec<Address>, rejected: Vec<(u64, String)> },
    Get { record: Option<Vec<u8>> },
    Head { pointer: Option<Vec<u8>>, manifest: Option<Vec<u8>> },
    Price { rate: u64, banks: Vec<PublicKey>, sats: u64 },
    Size { bytes: Option<u64> },
    Invoice { bolt11: String, hash: [u8; 32], expires: u64 },
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
            Self::Size { address } => {
                vec![
                    ("address".to_owned(), bytes32(address.bytes())),
                    ("t".to_owned(), Value::Text("size".to_owned())),
                ]
            }
            Self::Invoice { cents } => vec![
                ("cents".to_owned(), Value::Uint(*cents)),
                ("t".to_owned(), Value::Text("invoice".to_owned())),
            ],
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
            "size" => {
                cbor::only(m, &["address", "t"])?;
                Ok(Self::Size {
                    address: Address::hash(cbor::bytes32(cbor::field(m, "address")?, "address")?),
                })
            }
            "invoice" => {
                cbor::only(m, &["cents", "t"])?;
                let cents = cbor::field(m, "cents")?.as_uint().ok_or(CoreError::Field("cents"))?;
                if cents == 0 || cents > MAX_CENTS {
                    return Err(Error::Wire("cents out of range"));
                }
                Ok(Self::Invoice { cents })
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
            Self::Price { rate, banks, sats } => vec![
                (
                    "banks".to_owned(),
                    Value::Array(banks.iter().map(|b| bytes32(b.bytes())).collect()),
                ),
                ("rate".to_owned(), Value::Uint(*rate)),
                ("sats".to_owned(), Value::Uint(*sats)),
                ("t".to_owned(), Value::Text("price".to_owned())),
            ],
            Self::Invoice { bolt11, hash, expires } => vec![
                ("bolt11".to_owned(), Value::Text(bolt11.clone())),
                ("expires".to_owned(), Value::Uint(*expires)),
                ("hash".to_owned(), bytes32(hash)),
                ("t".to_owned(), Value::Text("invoice".to_owned())),
            ],
            Self::Size { bytes } => {
                let mut m = vec![("t".to_owned(), Value::Text("size".to_owned()))];
                m.extend(bytes.map(|b| ("bytes".to_owned(), Value::Uint(b))));
                m
            }
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
                cbor::only(m, &["banks", "rate", "sats", "t"])?;
                let banks = cbor::field(m, "banks")?
                    .as_array()
                    .ok_or(CoreError::Field("banks"))?
                    .iter()
                    .map(|v| cbor::bytes32(v, "banks").and_then(|b| PublicKey::from_bytes(&b)))
                    .collect::<core::result::Result<Vec<_>, _>>()?;
                let rate = cbor::field(m, "rate")?.as_uint().ok_or(CoreError::Field("rate"))?;
                let sats = cbor::field(m, "sats")?.as_uint().ok_or(CoreError::Field("sats"))?;
                Ok(Self::Price { rate, banks, sats })
            }
            "invoice" => {
                cbor::only(m, &["bolt11", "expires", "hash", "t"])?;
                let bolt11 =
                    cbor::field(m, "bolt11")?.as_text().ok_or(CoreError::Field("bolt11"))?;
                if bolt11.is_empty() || bolt11.len() > MAX_BOLT11 {
                    return Err(Error::Wire("bolt11 out of range"));
                }
                Ok(Self::Invoice {
                    bolt11: bolt11.to_owned(),
                    hash: cbor::bytes32(cbor::field(m, "hash")?, "hash")?,
                    expires: cbor::field(m, "expires")?
                        .as_uint()
                        .ok_or(CoreError::Field("expires"))?,
                })
            }
            "size" => {
                cbor::only(m, &["bytes", "t"])?;
                let bytes = cbor::optional(m, "bytes")
                    .map(|v| v.as_uint().ok_or(Error::Wire("bytes")))
                    .transpose()?;
                Ok(Self::Size { bytes })
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn size_round_trips_and_rejects_the_rest() {
        let address = Address::of(b"blob");
        let request = Request::Size { address };
        assert_eq!(Request::decode(&request.encode()).unwrap(), request);
        for response in [Response::Size { bytes: Some(300_000) }, Response::Size { bytes: None }] {
            assert_eq!(Response::decode(&response.encode()).unwrap(), response);
        }
        let extra = Value::Map(vec![
            ("address".to_owned(), bytes32(address.bytes())),
            ("t".to_owned(), Value::Text("size".to_owned())),
            ("x".to_owned(), Value::Uint(1)),
        ]);
        assert!(Request::decode(&extra.encode()).is_err());
        let short = Value::Map(vec![
            ("address".to_owned(), Value::Bytes(vec![0; 31])),
            ("t".to_owned(), Value::Text("size".to_owned())),
        ]);
        assert!(Request::decode(&short.encode()).is_err());
        let text = Value::Map(vec![
            ("bytes".to_owned(), Value::Text("1".to_owned())),
            ("t".to_owned(), Value::Text("size".to_owned())),
        ]);
        assert!(Response::decode(&text.encode()).is_err());
    }

    #[test]
    fn invoice_round_trips_and_rejects_the_rest() {
        let request = Request::Invoice { cents: 40 };
        assert_eq!(Request::decode(&request.encode()).unwrap(), request);
        let response = Response::Invoice { bolt11: "lnbc1".into(), hash: [7; 32], expires: 9 };
        assert_eq!(Response::decode(&response.encode()).unwrap(), response);
        let price = Response::Price { rate: 1, banks: vec![], sats: 10 };
        assert_eq!(Response::decode(&price.encode()).unwrap(), price);
        for cents in [0, MAX_CENTS + 1] {
            assert!(Request::decode(&Request::Invoice { cents }.encode()).is_err());
        }
        let long =
            Response::Invoice { bolt11: "l".repeat(MAX_BOLT11 + 1), hash: [7; 32], expires: 9 };
        assert!(Response::decode(&long.encode()).is_err());
        let empty = Response::Invoice { bolt11: String::new(), hash: [7; 32], expires: 9 };
        assert!(Response::decode(&empty.encode()).is_err());
        let short = Value::Map(vec![
            ("bolt11".to_owned(), Value::Text("lnbc1".to_owned())),
            ("expires".to_owned(), Value::Uint(9)),
            ("hash".to_owned(), Value::Bytes(vec![0; 31])),
            ("t".to_owned(), Value::Text("invoice".to_owned())),
        ]);
        assert!(Response::decode(&short.encode()).is_err());
        let old_price = Value::Map(vec![
            ("banks".to_owned(), Value::Array(vec![])),
            ("rate".to_owned(), Value::Uint(1)),
            ("t".to_owned(), Value::Text("price".to_owned())),
        ]);
        assert!(Response::decode(&old_price.encode()).is_err());
    }
}
