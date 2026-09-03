use crate::{Error, Result};

const MAX_DEPTH: u8 = 8;
const MAX_ITEMS: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl Value {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Uint(n) => head(out, 0, *n),
            Self::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Self::Text(s) => {
                head(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Self::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.write(out);
                }
            }
            Self::Map(entries) => {
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (Self::Text(k.clone()).encode(), v.encode()))
                    .collect();
                encoded.sort_by(|a, b| a.0.cmp(&b.0));
                encoded.dedup_by(|a, b| a.0 == b.0);
                head(out, 5, encoded.len() as u64);
                for (k, v) in encoded {
                    out.extend_from_slice(&k);
                    out.extend_from_slice(&v);
                }
            }
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(String, Value)]> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.push(m | 0x18);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(m | 0x19);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 0x1a);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 0x1b);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

pub fn decode(buf: &[u8]) -> Result<Value> {
    let mut r = Reader { buf, pos: 0 };
    let v = r.value(0)?;
    if r.pos == buf.len() { Ok(v) } else { Err(Error::Encoding("trailing bytes")) }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Encoding("length overflow"))?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Encoding("truncated"))?;
        self.pos = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8> {
        self.take(1)?.first().copied().ok_or(Error::Encoding("truncated"))
    }

    fn head(&mut self) -> Result<(u8, u64)> {
        let b = self.byte()?;
        let major = b >> 5;
        let info = b & 0x1f;
        let n = match info {
            0..=23 => u64::from(info),
            24 => {
                let n = u64::from(self.byte()?);
                if n < 24 {
                    return Err(Error::Encoding("non-minimal length"));
                }
                n
            }
            25 => {
                let n = u64::from(u16::from_be_bytes(fixed(self.take(2)?)?));
                if n <= 0xff {
                    return Err(Error::Encoding("non-minimal length"));
                }
                n
            }
            26 => {
                let n = u64::from(u32::from_be_bytes(fixed(self.take(4)?)?));
                if n <= 0xffff {
                    return Err(Error::Encoding("non-minimal length"));
                }
                n
            }
            27 => {
                let n = u64::from_be_bytes(fixed(self.take(8)?)?);
                if n <= 0xffff_ffff {
                    return Err(Error::Encoding("non-minimal length"));
                }
                n
            }
            _ => return Err(Error::Encoding("indefinite or reserved length")),
        };
        Ok((major, n))
    }

    fn len(n: u64) -> Result<usize> {
        usize::try_from(n).map_err(|_| Error::Encoding("length overflow"))
    }

    fn value(&mut self, depth: u8) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(Error::Encoding("nesting too deep"));
        }
        let (major, n) = self.head()?;
        match major {
            0 => Ok(Value::Uint(n)),
            2 => Ok(Value::Bytes(self.take(Self::len(n)?)?.to_vec())),
            3 => {
                let raw = self.take(Self::len(n)?)?;
                let s = core::str::from_utf8(raw).map_err(|_| Error::Encoding("invalid utf-8"))?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => {
                if n > MAX_ITEMS {
                    return Err(Error::Encoding("array too long"));
                }
                let next = depth.saturating_add(1);
                let mut items = Vec::with_capacity(Self::len(n)?);
                for _ in 0..n {
                    items.push(self.value(next)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                if n > MAX_ITEMS {
                    return Err(Error::Encoding("map too long"));
                }
                let next = depth.saturating_add(1);
                let mut entries = Vec::with_capacity(Self::len(n)?);
                let mut last: Option<&[u8]> = None;
                for _ in 0..n {
                    let start = self.pos;
                    let Value::Text(key) = self.value(next)? else {
                        return Err(Error::Encoding("map key is not text"));
                    };
                    let raw = self.buf.get(start..self.pos).ok_or(Error::Encoding("truncated"))?;
                    if last.is_some_and(|prev| prev >= raw) {
                        return Err(Error::Encoding("map keys not in canonical order"));
                    }
                    last = Some(raw);
                    entries.push((key, self.value(next)?));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(Error::Encoding("unsupported major type")),
        }
    }
}

fn fixed<const N: usize>(s: &[u8]) -> Result<[u8; N]> {
    s.try_into().map_err(|_| Error::Encoding("truncated"))
}

pub fn field<'a>(map: &'a [(String, Value)], key: &'static str) -> Result<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v).ok_or(Error::Field(key))
}

pub fn optional<'a>(map: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

pub fn only(map: &[(String, Value)], allowed: &[&str]) -> Result<()> {
    if map.iter().all(|(k, _)| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(Error::Encoding("unknown field"))
    }
}

pub fn bytes32(v: &Value, name: &'static str) -> Result<[u8; 32]> {
    v.as_bytes().and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or(Error::Field(name))
}
