use core::fmt;
use core::str::FromStr;

use data_encoding::BASE32_NOPAD;

use crate::{Error, Result};

const LEN: usize = 37;
const CHECK: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Kind {
    Key = 1,
    Hash = 2,
}

impl Kind {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            1 => Ok(Self::Key),
            2 => Ok(Self::Hash),
            _ => Err(Error::Address("unknown version")),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address {
    kind: Kind,
    bytes: [u8; 32],
}

impl Address {
    pub const fn key(bytes: [u8; 32]) -> Self {
        Self { kind: Kind::Key, bytes }
    }

    pub const fn hash(bytes: [u8; 32]) -> Self {
        Self { kind: Kind::Hash, bytes }
    }

    pub fn of(data: &[u8]) -> Self {
        Self::hash(*blake3::hash(data).as_bytes())
    }

    pub const fn kind(&self) -> Kind {
        self.kind
    }

    pub const fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    fn checksum(kind: Kind, bytes: &[u8; 32]) -> [u8; CHECK] {
        let mut h = blake3::Hasher::new();
        h.update(&[kind as u8]);
        h.update(bytes);
        let mut out = [0u8; CHECK];
        h.finalize_xof().fill(&mut out);
        out
    }

    fn raw(&self) -> [u8; LEN] {
        let mut raw = [0u8; LEN];
        raw[0] = self.kind as u8;
        raw[1..33].copy_from_slice(&self.bytes);
        raw[33..].copy_from_slice(&Self::checksum(self.kind, &self.bytes));
        raw
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = BASE32_NOPAD.encode(&self.raw());
        s.make_ascii_lowercase();
        f.write_str(&s)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 60 || !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
            return Err(Error::Address("malformed"));
        }
        let raw = BASE32_NOPAD
            .decode(s.to_ascii_uppercase().as_bytes())
            .map_err(|_| Error::Address("malformed"))?;
        let raw: [u8; LEN] = raw.try_into().map_err(|_| Error::Address("malformed"))?;
        let kind = Kind::from_byte(raw[0])?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw[1..33]);
        if raw[33..] != Self::checksum(kind, &bytes) {
            return Err(Error::Address("checksum mismatch"));
        }
        Ok(Self { kind, bytes })
    }
}
