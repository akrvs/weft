use std::fmt::Debug;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use data_encoding::HEXLOWER;
use weft_core::receipt::payment_hash;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    pub bolt11: String,
    pub hash: [u8; 32],
}

pub type Issued<'a> = Pin<Box<dyn Future<Output = Result<Invoice>> + Send + 'a>>;

pub trait Node: Debug + Send + Sync {
    fn invoice(&self, msat: u64, expiry: u64) -> Issued<'_>;
}

#[derive(Debug)]
pub struct Fake {
    dir: PathBuf,
}

impl Fake {
    pub fn new(dir: &Path) -> Result<Self> {
        let dir = dir.join("preimages");
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(&dir).map_err(store)?;
        Ok(Self { dir })
    }

    pub fn preimage(dir: &Path, hash: &[u8; 32]) -> Result<[u8; 32]> {
        let text = std::fs::read_to_string(dir.join("preimages").join(HEXLOWER.encode(hash)))
            .map_err(store)?;
        decode_preimage(text.trim())
    }
}

pub fn decode_preimage(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 {
        return Err(Error::Wire("preimage is not 64 hex characters"));
    }
    let bytes = HEXLOWER
        .decode(text.to_ascii_lowercase().as_bytes())
        .map_err(|_| Error::Wire("preimage is not hex"))?;
    bytes.try_into().map_err(|_| Error::Wire("preimage is not 32 bytes"))
}

impl Node for Fake {
    fn invoice(&self, _msat: u64, _expiry: u64) -> Issued<'_> {
        Box::pin(async move {
            let mut preimage = [0u8; 32];
            getrandom::fill(&mut preimage).map_err(|e| Error::Store(e.to_string()))?;
            let hash = payment_hash(&preimage);
            let name = HEXLOWER.encode(&hash);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.dir.join(&name))
                .map_err(store)?;
            writeln!(file, "{}", HEXLOWER.encode(&preimage)).map_err(store)?;
            Ok(Invoice { bolt11: format!("fake{name}"), hash })
        })
    }
}

fn store(e: impl std::fmt::Display) -> Error {
    Error::Store(e.to_string())
}
