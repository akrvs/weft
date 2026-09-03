use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use weft_core::cbor::{self, Value};
use weft_core::{PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::fail::{Result, fail};
use crate::fs;

const M_COST: u32 = 65_536;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
const FIELDS: &[&str] =
    &["alg", "created", "ct", "expires", "label", "m", "nonce", "p", "pub", "salt", "t", "v"];

#[derive(Debug, Clone)]
pub struct Meta {
    pub public: PublicKey,
    pub label: String,
    pub created: u64,
    pub expires: Option<u64>,
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn derive(pass: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| e.to_string())?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass, salt, key.as_mut())
        .map_err(|e| e.to_string())?;
    Ok(key)
}

fn cipher(kek: &[u8; 32]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(kek).map_err(|_| "key length".into())
}

fn header(meta: &Meta, salt: &[u8], nonce: &[u8]) -> Vec<(String, Value)> {
    let mut m = vec![
        ("alg".to_owned(), Value::Text("argon2id".to_owned())),
        ("created".to_owned(), Value::Uint(meta.created)),
        ("label".to_owned(), Value::Text(meta.label.clone())),
        ("m".to_owned(), Value::Uint(u64::from(M_COST))),
        ("nonce".to_owned(), Value::Bytes(nonce.to_vec())),
        ("p".to_owned(), Value::Uint(u64::from(P_COST))),
        ("pub".to_owned(), Value::Bytes(meta.public.bytes().to_vec())),
        ("salt".to_owned(), Value::Bytes(salt.to_vec())),
        ("t".to_owned(), Value::Uint(u64::from(T_COST))),
        ("v".to_owned(), Value::Uint(1)),
    ];
    if let Some(e) = meta.expires {
        m.push(("expires".to_owned(), Value::Uint(e)));
    }
    m
}

pub fn generate(
    path: &Path,
    pass: &[u8],
    label: &str,
    created: u64,
    expires: Option<u64>,
) -> Result<Meta> {
    let seed: [u8; 32] = random()?;
    let key = SecretKey::from_seed(seed);
    let meta = Meta { public: key.public(), label: label.to_owned(), created, expires };
    let salt: [u8; 16] = random()?;
    let nonce: [u8; 24] = random()?;
    let head = header(&meta, &salt, &nonce);
    let aad = Value::Map(head.clone()).encode();
    let kek = derive(pass, &salt, M_COST, T_COST, P_COST)?;
    let mut buf = key.seed().to_vec();
    cipher(&kek)?
        .encrypt_in_place(&XNonce::from(nonce), &aad, &mut buf)
        .map_err(|_| "encryption failed")?;
    let mut full = head;
    full.push(("ct".to_owned(), Value::Bytes(buf)));
    fs::write_private(path, &Value::Map(full).encode())?;
    Ok(meta)
}

fn parse(path: &Path) -> Result<(Vec<(String, Value)>, Meta)> {
    let value = cbor::decode(&std::fs::read(path)?)?;
    let m = value.as_map().ok_or("key file is not a map")?.to_vec();
    cbor::only(&m, FIELDS)?;
    if cbor::field(&m, "v")?.as_uint() != Some(1)
        || cbor::field(&m, "alg")?.as_text() != Some("argon2id")
    {
        return fail("unsupported key file");
    }
    let meta = Meta {
        public: PublicKey::from_bytes(&cbor::bytes32(cbor::field(&m, "pub")?, "pub")?)?,
        label: cbor::field(&m, "label")?.as_text().ok_or("label")?.to_owned(),
        created: cbor::field(&m, "created")?.as_uint().ok_or("created")?,
        expires: cbor::optional(&m, "expires").and_then(Value::as_uint),
    };
    Ok((m, meta))
}

pub fn meta(path: &Path) -> Result<Meta> {
    parse(path).map(|(_, m)| m)
}

pub fn open(path: &Path, pass: &[u8]) -> Result<SecretKey> {
    let (m, meta) = parse(path)?;
    let cost = |k: &'static str| -> Result<u32> {
        u32::try_from(cbor::field(&m, k)?.as_uint().ok_or(k)?).map_err(|_| k.into())
    };
    let salt = cbor::field(&m, "salt")?.as_bytes().ok_or("salt")?;
    let nonce = cbor::field(&m, "nonce")?.as_bytes().ok_or("nonce")?;
    if nonce.len() != 24 {
        return fail("nonce");
    }
    let mut buf = cbor::field(&m, "ct")?.as_bytes().ok_or("ct")?.to_vec();
    let aad: Vec<(String, Value)> = m.iter().filter(|(k, _)| k != "ct").cloned().collect();
    let kek = derive(pass, salt, cost("m")?, cost("t")?, cost("p")?)?;
    let nonce = XNonce::try_from(nonce).map_err(|_| "nonce")?;
    cipher(&kek)?
        .decrypt_in_place(&nonce, &Value::Map(aad).encode(), &mut buf)
        .map_err(|_| "wrong passphrase or corrupted key file")?;
    let seed: [u8; 32] = buf.as_slice().try_into().map_err(|_| "seed length")?;
    let key = SecretKey::from_seed(seed);
    if key.public() != meta.public {
        return fail("key file public key mismatch");
    }
    Ok(key)
}
