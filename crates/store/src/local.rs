use std::path::PathBuf;

use tokio::sync::Mutex;
use weft_core::{Address, PublicKey, Record};
use weft_home::{Fail, Reads};

use crate::gate::{browser_key, browser_key_path, socket_path};
use crate::{Client, Error, Result};

pub const POOL: usize = 4;

#[derive(Debug)]
pub struct Local {
    home: PathBuf,
    idle: Mutex<Vec<Client>>,
}

impl Local {
    pub fn new(home: PathBuf) -> Self {
        Self { home, idle: Mutex::new(Vec::new()) }
    }

    async fn connect(&self) -> Result<Client> {
        if !browser_key_path(&self.home).exists() {
            return Err(Error::Down);
        }
        let key = browser_key(&self.home)?;
        match Client::connect(&socket_path(&self.home), &key).await {
            Err(Error::Io(_)) => Err(Error::Down),
            other => other,
        }
    }

    pub async fn call<T, F>(&self, f: F) -> Result<T>
    where
        F: AsyncFnOnce(&mut Client) -> Result<T> + Clone,
    {
        let taken = self.idle.lock().await.pop();
        let reused = taken.is_some();
        let mut client = match taken {
            Some(c) => c,
            None => self.connect().await?,
        };
        let mut result = f.clone()(&mut client).await;
        if reused && matches!(result, Err(Error::Io(_) | Error::Wire(_))) {
            client = self.connect().await?;
            result = f(&mut client).await;
        }
        if !matches!(result, Err(Error::Io(_) | Error::Wire(_) | Error::Down)) {
            let mut idle = self.idle.lock().await;
            if idle.len() < POOL {
                idle.push(client);
            }
        }
        result
    }
}

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        Self(e.to_string())
    }
}

impl Reads for Local {
    async fn record(&self, address: Address) -> weft_home::Result<Option<Record>> {
        Ok(self.call(async |c| c.record(address).await).await?)
    }

    async fn manifest(&self, author: PublicKey) -> weft_home::Result<Option<Record>> {
        Ok(self.call(async |c| c.manifest(author).await).await?)
    }

    async fn pointers(&self, author: PublicKey, name: &str) -> weft_home::Result<Vec<Record>> {
        Ok(self.call(async |c| c.pointers(author, name).await).await?)
    }

    async fn blob(&self, address: Address) -> weft_home::Result<Option<Vec<u8>>> {
        Ok(self.call(async |c| c.blob(address).await).await?)
    }

    async fn keep(&self, record: &Record) -> weft_home::Result<()> {
        Ok(self.call(async |c| c.keep(record).await).await?)
    }

    async fn keep_blob(&self, address: Address, data: &[u8]) -> weft_home::Result<()> {
        Ok(self.call(async |c| c.keep_blob(address, data).await).await?)
    }
}
