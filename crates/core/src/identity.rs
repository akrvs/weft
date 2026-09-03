use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::{Address, Error, Result};

pub const DOMAIN: &[u8] = b"weft/record/1";

pub struct SecretKey(SigningKey);

impl SecretKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(&framed(message)).to_bytes()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({})", self.public().address())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| Error::Key)?;
        if key.is_weak() {
            return Err(Error::Key);
        }
        Ok(Self(key))
    }

    pub fn bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn address(&self) -> Address {
        Address::key(*self.bytes())
    }

    pub fn verify(&self, message: &[u8], sig: &[u8; 64]) -> Result<()> {
        let sig = Signature::from_bytes(sig);
        self.0.verify_strict(&framed(message), &sig).map_err(|_| Error::Signature)
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.bytes().cmp(other.bytes())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.address())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.address().fmt(f)
    }
}

fn framed(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len().saturating_add(1).saturating_add(message.len()));
    out.extend_from_slice(DOMAIN);
    out.push(0);
    out.extend_from_slice(message);
    out
}
