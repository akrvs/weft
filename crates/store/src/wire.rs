use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use weft_core::cbor::{self, Value};
use weft_core::pointer::MAX_NAME;
use weft_core::record::{MAX_INLINE, MAX_KIND, MAX_REFS, valid_kind};
use weft_core::{Address, Error as CoreError, PublicKey};

use crate::{Error, Result};

pub const DOMAIN: &[u8] = b"weft/store/1";
pub const MAX_FRAME: usize = 1 << 20;
pub const MAX_CHALLENGE: usize = 1024;
pub const MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Auth { app: PublicKey, sig: [u8; 64] },
    List { kind: String },
    Get { address: Address },
    Put { kind: String, body: Vec<u8>, refs: Vec<Address> },
    Login { challenge: Vec<u8> },
    Kinds,
    Grants,
    Revoke { grant: Address },
    Publish { body: Vec<u8>, name: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Hello { nonce: [u8; 32] },
    Ok,
    List { addresses: Vec<Address> },
    Get { record: Vec<u8> },
    Put { address: Address },
    Login { proof: Vec<u8> },
    Kinds { kinds: Vec<(String, u64)> },
    Grants { records: Vec<Vec<u8>> },
    Publish { records: Vec<Vec<u8>> },
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

fn kind_text(k: &str) -> Result<String> {
    if k.len() > MAX_KIND || !valid_kind(k) {
        return Err(Error::Core(CoreError::Field("kind")));
    }
    Ok(k.to_owned())
}

fn kind(m: &[(String, Value)]) -> Result<String> {
    kind_text(cbor::field(m, "kind")?.as_text().ok_or(CoreError::Field("kind"))?)
}

fn records(r: &[Vec<u8>]) -> Value {
    Value::Array(r.iter().map(|r| bytes(r)).collect())
}

fn entries<'a>(v: &'a Value, name: &'static str) -> Result<&'a [Value]> {
    let items = v.as_array().ok_or(CoreError::Field(name))?;
    if items.len() > MAX_ENTRIES {
        return Err(Error::Core(CoreError::Limit(name)));
    }
    Ok(items)
}

fn record_list(m: &[(String, Value)]) -> Result<Vec<Vec<u8>>> {
    entries(cbor::field(m, "records")?, "records")?
        .iter()
        .map(|v| v.as_bytes().map(<[u8]>::to_vec).ok_or(Error::Core(CoreError::Field("records"))))
        .collect()
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
            Self::Login { challenge } => {
                vec![("challenge".to_owned(), bytes(challenge)), ("t".to_owned(), text("login"))]
            }
            Self::Kinds => vec![("t".to_owned(), text("kinds"))],
            Self::Grants => vec![("t".to_owned(), text("grants"))],
            Self::Revoke { grant } => {
                vec![("grant".to_owned(), bytes(grant.bytes())), ("t".to_owned(), text("revoke"))]
            }
            Self::Publish { body, name } => {
                let mut m = vec![("body".to_owned(), bytes(body))];
                if let Some(name) = name {
                    m.push(("name".to_owned(), text(name)));
                }
                m.push(("t".to_owned(), text("publish")));
                m
            }
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
            "login" => {
                cbor::only(&m, &["challenge", "t"])?;
                let challenge = cbor::field(&m, "challenge")?
                    .as_bytes()
                    .ok_or(CoreError::Field("challenge"))?;
                if challenge.len() > MAX_CHALLENGE {
                    return Err(Error::Core(CoreError::Limit("challenge")));
                }
                Ok(Self::Login { challenge: challenge.to_vec() })
            }
            "kinds" => {
                cbor::only(&m, &["t"])?;
                Ok(Self::Kinds)
            }
            "grants" => {
                cbor::only(&m, &["t"])?;
                Ok(Self::Grants)
            }
            "revoke" => {
                cbor::only(&m, &["grant", "t"])?;
                Ok(Self::Revoke {
                    grant: Address::hash(cbor::bytes32(cbor::field(&m, "grant")?, "grant")?),
                })
            }
            "publish" => {
                cbor::only(&m, &["body", "name", "t"])?;
                let body = cbor::field(&m, "body")?.as_bytes().ok_or(CoreError::Field("body"))?;
                if body.len() > MAX_INLINE {
                    return Err(Error::Core(CoreError::Limit("body")));
                }
                let name = match cbor::optional(&m, "name") {
                    None => None,
                    Some(v) => {
                        let n = v.as_text().ok_or(CoreError::Field("name"))?;
                        if n.is_empty() || n.len() > MAX_NAME {
                            return Err(Error::Core(CoreError::Field("name")));
                        }
                        Some(n.to_owned())
                    }
                };
                Ok(Self::Publish { body: body.to_vec(), name })
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
            Self::Login { proof } => {
                vec![("proof".to_owned(), bytes(proof)), ("t".to_owned(), text("login"))]
            }
            Self::Kinds { kinds } => {
                let kinds = kinds
                    .iter()
                    .map(|(k, n)| Value::Array(vec![text(k), Value::Uint(*n)]))
                    .collect();
                vec![("kinds".to_owned(), Value::Array(kinds)), ("t".to_owned(), text("kinds"))]
            }
            Self::Grants { records: r } => {
                vec![("records".to_owned(), records(r)), ("t".to_owned(), text("grants"))]
            }
            Self::Publish { records: r } => {
                vec![("records".to_owned(), records(r)), ("t".to_owned(), text("publish"))]
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
            "login" => {
                cbor::only(&m, &["proof", "t"])?;
                let proof =
                    cbor::field(&m, "proof")?.as_bytes().ok_or(CoreError::Field("proof"))?;
                if proof.len() > weft_core::login::MAX_PROOF {
                    return Err(Error::Core(CoreError::Limit("proof")));
                }
                Ok(Self::Login { proof: proof.to_vec() })
            }
            "kinds" => {
                cbor::only(&m, &["kinds", "t"])?;
                let kinds = entries(cbor::field(&m, "kinds")?, "kinds")?
                    .iter()
                    .map(|v| match v.as_array() {
                        Some([k, n]) => Ok((
                            kind_text(k.as_text().ok_or(CoreError::Field("kinds"))?)?,
                            n.as_uint().ok_or(CoreError::Field("kinds"))?,
                        )),
                        _ => Err(Error::Core(CoreError::Field("kinds"))),
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Self::Kinds { kinds })
            }
            "grants" => {
                cbor::only(&m, &["records", "t"])?;
                Ok(Self::Grants { records: record_list(&m)? })
            }
            "publish" => {
                cbor::only(&m, &["records", "t"])?;
                Ok(Self::Publish { records: record_list(&m)? })
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
