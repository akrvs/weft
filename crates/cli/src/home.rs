use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use weft_core::{Device, Manifest, PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::fail::{Fail, Result, fail};
use crate::fs;
use crate::keystore::{self, Meta};
use crate::store::Store;

pub const ROOT: &str = "root";

#[derive(Debug)]
pub struct Home {
    dir: PathBuf,
}

impl Home {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn default_dir() -> PathBuf {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .unwrap_or_else(|| PathBuf::from("."))
            .join("weft")
    }

    pub fn store(&self) -> Store {
        Store::new(self.dir.join("records"))
    }

    fn root_path(&self) -> PathBuf {
        self.dir.join("root.key")
    }

    fn device_path(&self, label: &str) -> PathBuf {
        self.dir.join("devices").join(format!("{label}.key"))
    }

    fn revoked_path(&self) -> PathBuf {
        self.dir.join("revoked")
    }

    pub fn exists(&self) -> bool {
        self.root_path().is_file()
    }

    pub fn init(&self, pass: &[u8]) -> Result<Meta> {
        if self.exists() {
            return fail(format!("identity already exists at {}", self.dir.display()));
        }
        fs::ensure_dir(&self.dir)?;
        keystore::generate(&self.root_path(), pass, ROOT, now()?, None)
    }

    pub fn root_meta(&self) -> Result<Meta> {
        if !self.exists() {
            return fail(format!("no identity at {}; run `weft init`", self.dir.display()));
        }
        keystore::meta(&self.root_path())
    }

    pub fn root(&self) -> Result<PublicKey> {
        Ok(self.root_meta()?.public)
    }

    pub fn open(&self, label: &str, pass: &[u8]) -> Result<SecretKey> {
        let path = if label == ROOT { self.root_path() } else { self.device_path(label) };
        if !path.is_file() {
            return fail(format!("no key labelled {label}"));
        }
        keystore::open(&path, pass)
    }

    pub fn add_device(&self, label: &str, pass: &[u8], expires: Option<u64>) -> Result<Meta> {
        if !valid_label(label) {
            return fail("label must be 1 to 64 characters of a-z, 0-9, - or _");
        }
        self.open(ROOT, pass)?;
        let path = self.device_path(label);
        if path.exists() {
            return fail(format!("device {label} already exists"));
        }
        let created = now()?;
        if expires.is_some_and(|e| e <= created) {
            return fail("expiry must be in the future");
        }
        keystore::generate(&path, pass, label, created, expires)
    }

    pub fn devices(&self) -> Result<Vec<Meta>> {
        let dir = self.dir.join("devices");
        let mut out = Vec::new();
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) == Some("key") {
                    out.push(keystore::meta(&path)?);
                }
            }
        }
        out.sort_by_key(|m| m.public);
        Ok(out)
    }

    pub fn revoked(&self) -> Result<Vec<PublicKey>> {
        let path = self.revoked_path();
        let mut out = Vec::new();
        if path.is_file() {
            for line in std::fs::read_to_string(path)?.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let addr: weft_core::Address = line.parse()?;
                out.push(PublicKey::from_bytes(addr.bytes())?);
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    pub fn revoke(&self, label: &str) -> Result<PublicKey> {
        let path = self.device_path(label);
        if !path.is_file() {
            return fail(format!("no device labelled {label}"));
        }
        let meta = keystore::meta(&path)?;
        let mut text = if self.revoked_path().is_file() {
            std::fs::read_to_string(self.revoked_path())?
        } else {
            String::new()
        };
        text.push_str(&meta.public.address().to_string());
        text.push('\n');
        fs::write(&self.revoked_path(), text.as_bytes())?;
        std::fs::remove_file(path)?;
        Ok(meta.public)
    }

    pub fn manifest(
        &self,
        prev: Option<&Manifest>,
        prev_address: Option<weft_core::Address>,
    ) -> Result<Manifest> {
        let devices = self
            .devices()?
            .into_iter()
            .map(|m| Device {
                key: m.public,
                label: m.label,
                created: m.created,
                expires: m.expires,
            })
            .collect();
        let manifest = Manifest {
            seq: prev.map_or(1, |p| p.seq.saturating_add(1)),
            prev: prev_address,
            devices,
            revoked: self.revoked()?,
        };
        manifest.check(&self.root()?)?;
        Ok(manifest)
    }

    fn relays_path(&self) -> PathBuf {
        self.dir.join("relays")
    }

    pub fn relays(&self) -> Result<Vec<iroh::EndpointId>> {
        let path = self.relays_path();
        if !path.is_file() {
            return Ok(Vec::new());
        }
        std::fs::read_to_string(path)?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| l.parse::<iroh::EndpointId>().map_err(|e| Fail(e.to_string())))
            .collect()
    }

    pub fn add_relay(&self, id: iroh::EndpointId) -> Result<()> {
        let mut relays = self.relays()?;
        if relays.contains(&id) {
            return Ok(());
        }
        relays.push(id);
        let text = relays.iter().fold(String::new(), |mut t, r| {
            use std::fmt::Write;
            let _ = writeln!(t, "{r}");
            t
        });
        fs::write(&self.relays_path(), text.as_bytes())
    }

    pub fn blob_path(&self, address: &weft_core::Address) -> PathBuf {
        self.dir.join("blobs").join(address.to_string())
    }

    pub fn keep_blob(&self, address: &weft_core::Address, data: &[u8]) -> Result<()> {
        let path = self.blob_path(address);
        if path.is_file() {
            return Ok(());
        }
        fs::write(&path, data)
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs())
}

pub fn passphrase(confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(p) = std::env::var("WEFT_PASSPHRASE") {
        return Ok(Zeroizing::new(p.into_bytes()));
    }
    let first = Zeroizing::new(rpassword::prompt_password("passphrase: ")?);
    if first.is_empty() {
        return fail("passphrase must not be empty");
    }
    if confirm {
        let second = Zeroizing::new(rpassword::prompt_password("confirm passphrase: ")?);
        if *first != *second {
            return fail("passphrases do not match");
        }
    }
    Ok(Zeroizing::new(first.as_bytes().to_vec()))
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}
