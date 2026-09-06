use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use weft_core::cbor::{self, Value};
use weft_core::record::{MAX_INLINE, MAX_KIND, MAX_REFS, valid_kind};
use weft_core::{Address, Error as CoreError, PublicKey};

use crate::{Error, Result};

pub const DOMAIN: &[u8] = b"weft/store/1";
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Auth { app: PublicKey, sig: [u8; 64] },
    List { kind: String },
    Get { address: Address },
    Put { kind: String, body: Vec<u8>, refs: Vec<Address> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Hello { nonce: [u8; 32] },
    Ok,
    List { addresses: Vec<Address> },
    Get { record: Vec<u8> },
    Put { address: Address },
    Error { why: String },
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn addresses(a: &[Address]) -> Value {
    Value::Array(a.iter().map(|a| bytes(a.bytes())).collect())
}

fn hashes(v: &Value, name: &'static str) -> Result<Vec<Address>> {
    v.as_array()
        .ok_or(CoreError::Field(name))?
        .iter()
        .map(|v| cbor::bytes32(v, name).map(Address::hash).map_err(Error::Core))
        .collect()
}

fn kind(m: &[(String, Value)]) -> Result<String> {
    let k = cbor::field(m, "kind")?.as_text().ok_or(CoreError::Field("kind"))?;
    if k.len() > MAX_KIND || !valid_kind(k) {
        return Err(Error::Core(CoreError::Field("kind")));
    }
    Ok(k.to_owned())
}

fn decode_map(buf: &[u8], what: &'static str) -> Result<Vec<(String, Value)>> {
    let value = cbor::decode(buf)?;
    Ok(value.as_map().ok_or(Error::Wire(what))?.to_vec())
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let m = match self {
            Self::Auth { app, sig } => {
                vec![
                    ("app".to_owned(), bytes(app.bytes())),
                    ("sig".to_owned(), bytes(sig)),
                    ("t".to_owned(), text("auth")),
                ]
            }
            Self::List { kind } => {
                vec![("kind".to_owned(), text(kind)), ("t".to_owned(), text("list"))]
            }
            Self::Get { address } => {
                vec![("address".to_owned(), bytes(address.bytes())), ("t".to_owned(), text("get"))]
            }
            Self::Put { kind, body, refs } => vec![
                ("body".to_owned(), bytes(body)),
                ("kind".to_owned(), text(kind)),
                ("refs".to_owned(), addresses(refs)),
                ("t".to_owned(), text("put")),
            ],
        };
        Value::Map(m).encode()
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let m = decode_map(buf, "request is not a map")?;
        match cbor::field(&m, "t")?.as_text().ok_or(CoreError::Field("t"))? {
            "auth" => {
                cbor::only(&m, &["app", "sig", "t"])?;
                let app = PublicKey::from_bytes(&cbor::bytes32(cbor::field(&m, "app")?, "app")?)?;
                let sig = cbor::field(&m, "sig")?
                    .as_bytes()
                    .and_then(|b| <[u8; 64]>::try_from(b).ok())
                    .ok_or(CoreError::Field("sig"))?;
                Ok(Self::Auth { app, sig })
            }
            "list" => {
                cbor::only(&m, &["kind", "t"])?;
                Ok(Self::List { kind: kind(&m)? })
            }
            "get" => {
                cbor::only(&m, &["address", "t"])?;
                Ok(Self::Get {
                    address: Address::hash(cbor::bytes32(cbor::field(&m, "address")?, "address")?),
                })
            }
            "put" => {
                cbor::only(&m, &["body", "kind", "refs", "t"])?;
                let body = cbor::field(&m, "body")?.as_bytes().ok_or(CoreError::Field("body"))?;
                if body.len() > MAX_INLINE {
                    return Err(Error::Core(CoreError::Limit("body")));
                }
                let refs = hashes(cbor::field(&m, "refs")?, "refs")?;
                if refs.len() > MAX_REFS {
                    return Err(Error::Core(CoreError::Limit("refs")));
                }
                Ok(Self::Put { kind: kind(&m)?, body: body.to_vec(), refs })
            }
            _ => Err(Error::Wire("unknown request type")),
        }
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let m = match self {
            Self::Hello { nonce } => {
                vec![("nonce".to_owned(), bytes(nonce)), ("t".to_owned(), text("hello"))]
            }
            Self::Ok => vec![("t".to_owned(), text("ok"))],
            Self::List { addresses: a } => {
                vec![("addresses".to_owned(), addresses(a)), ("t".to_owned(), text("list"))]
            }
            Self::Get { record } => {
                vec![("record".to_owned(), bytes(record)), ("t".to_owned(), text("get"))]
            }
            Self::Put { address } => {
                vec![("address".to_owned(), bytes(address.bytes())), ("t".to_owned(), text("put"))]
            }
            Self::Error { why } => {
                vec![("t".to_owned(), text("error")), ("why".to_owned(), text(why))]
            }
        };
        Value::Map(m).encode()
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let m = decode_map(buf, "response is not a map")?;
        match cbor::field(&m, "t")?.as_text().ok_or(CoreError::Field("t"))? {
            "hello" => {
                cbor::only(&m, &["nonce", "t"])?;
                Ok(Self::Hello { nonce: cbor::bytes32(cbor::field(&m, "nonce")?, "nonce")? })
            }
            "ok" => {
                cbor::only(&m, &["t"])?;
                Ok(Self::Ok)
            }
            "list" => {
                cbor::only(&m, &["addresses", "t"])?;
                Ok(Self::List { addresses: hashes(cbor::field(&m, "addresses")?, "addresses")? })
            }
            "get" => {
                cbor::only(&m, &["record", "t"])?;
                let record =
                    cbor::field(&m, "record")?.as_bytes().ok_or(CoreError::Field("record"))?;
                Ok(Self::Get { record: record.to_vec() })
            }
            "put" => {
                cbor::only(&m, &["address", "t"])?;
                Ok(Self::Put {
                    address: Address::hash(cbor::bytes32(cbor::field(&m, "address")?, "address")?),
                })
            }
            "error" => {
                cbor::only(&m, &["t", "why"])?;
                let why = cbor::field(&m, "why")?.as_text().ok_or(CoreError::Field("why"))?;
                Ok(Self::Error { why: why.to_owned() })
            }
            _ => Err(Error::Wire("unknown response type")),
        }
    }
}

pub async fn send<W: AsyncWrite + Unpin>(stream: &mut W, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| Error::Wire("frame too large"))?;
    if payload.len() > MAX_FRAME {
        return Err(Error::Wire("frame too large"));
    }
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn recv<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Option<Vec<u8>>> {
    let mut head = [0u8; 4];
    match stream.read_exact(&mut head).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len =
        usize::try_from(u32::from_be_bytes(head)).map_err(|_| Error::Wire("frame too large"))?;
    if len > MAX_FRAME {
        return Err(Error::Wire("frame too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Some(buf))
}
