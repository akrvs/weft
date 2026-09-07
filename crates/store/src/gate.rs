use std::path::{Path, PathBuf};

use weft_core::{
    Address, Body, Challenge, Draft, Grant, Manifest, Pointer, Proof, PublicKey, Record, Revoke,
    SecretKey, grant, login, verify,
};
use weft_home::{Home, Store};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const SOCKET: &str = "store.sock";
pub const BROWSER_KEY: &str = "browser.key";
pub const PAGE: &str = "page";

pub fn socket_path(home: &Path) -> PathBuf {
    home.join(SOCKET)
}

pub fn browser_key_path(home: &Path) -> PathBuf {
    home.join(BROWSER_KEY)
}

pub fn browser_key(home: &Path) -> Result<SecretKey> {
    let bytes = Zeroizing::new(std::fs::read(browser_key_path(home))?);
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Home("browser key is not 32 bytes".to_owned()))?;
    Ok(SecretKey::from_seed(seed))
}

pub fn create_browser_key(home: &Path) -> Result<SecretKey> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|e| Error::Io(e.to_string()))?;
    weft_home::fs::write_private(&browser_key_path(home), seed.as_ref())?;
    Ok(SecretKey::from_seed(*seed))
}

#[derive(Debug)]
pub struct Gate {
    home: Home,
    root: PublicKey,
    key: SecretKey,
    browser: PublicKey,
}

struct Snapshot {
    records: Vec<Record>,
    manifest: Option<Manifest>,
    now: u64,
}

impl Snapshot {
    fn grants(&self, root: &PublicKey) -> Vec<(&Record, Grant)> {
        Store::grants(&self.records, root, self.manifest.as_ref(), self.now)
    }
}

impl Gate {
    pub fn new(home: Home, root: PublicKey, key: SecretKey, browser: PublicKey) -> Self {
        Self { home, root, key, browser }
    }

    pub fn home(&self) -> &Home {
        &self.home
    }

    pub fn signer(&self) -> PublicKey {
        self.key.public()
    }

    fn snapshot(&self) -> Result<Snapshot> {
        let records = self.home.store().all()?;
        let manifest = Store::manifest(&records, &self.root);
        Ok(Snapshot { records, manifest, now: weft_home::now()? })
    }

    fn privileged(&self, app: &PublicKey) -> Result<()> {
        if app == &self.browser { Ok(()) } else { Err(Error::Refused("browser only")) }
    }

    fn allow(&self, snap: &Snapshot, app: &PublicKey, kind: &str, write: bool) -> Result<()> {
        if grant::RESERVED.contains(&kind) {
            return Err(Error::Refused("reserved kind"));
        }
        if app == &self.browser {
            return Ok(());
        }
        let permitted = snap.grants(&self.root).iter().any(|(_, g)| {
            &g.app == app
                && g.covers(kind)
                && if write { g.access.writes() } else { g.access.reads() }
        });
        if permitted { Ok(()) } else { Err(Error::Refused("no active grant")) }
    }

    fn own<'a>(&self, snap: &'a Snapshot) -> impl Iterator<Item = &'a Record> {
        let root = self.root;
        let manifest = snap.manifest.as_ref();
        snap.records.iter().filter(move |r| r.author() == &root && verify(r, manifest).is_ok())
    }

    fn draft(&self, snap: &Snapshot, kind: &str, refs: Vec<Address>, body: Vec<u8>) -> Draft {
        Draft {
            author: self.root,
            signer: self.key.public(),
            kind: kind.to_owned(),
            created: snap.now,
            refs,
            body: Body::Inline(body),
        }
    }

    fn sign(&self, snap: &Snapshot, draft: Draft) -> Result<Record> {
        let record = draft.sign(&self.key)?;
        verify(&record, snap.manifest.as_ref())?;
        Ok(record)
    }

    fn keep(&self, snap: &Snapshot, draft: Draft) -> Result<Record> {
        let record = self.sign(snap, draft)?;
        self.home.store().put(&record)?;
        Ok(record)
    }

    pub fn list(&self, app: &PublicKey, kind: &str) -> Result<Vec<Address>> {
        let snap = self.snapshot()?;
        self.allow(&snap, app, kind, false)?;
        let mut out: Vec<Address> =
            self.own(&snap).filter(|r| r.kind() == kind).map(Record::address).collect();
        out.sort_unstable();
        Ok(out)
    }

    pub fn get(&self, app: &PublicKey, address: &Address) -> Result<Vec<u8>> {
        let snap = self.snapshot()?;
        let record = self
            .own(&snap)
            .find(|r| &r.address() == address)
            .ok_or(Error::Refused("no such record"))?;
        self.allow(&snap, app, record.kind(), false)?;
        Ok(record.to_bytes())
    }

    pub fn put(
        &self,
        app: &PublicKey,
        kind: &str,
        body: Vec<u8>,
        refs: Vec<Address>,
    ) -> Result<Address> {
        let snap = self.snapshot()?;
        self.allow(&snap, app, kind, true)?;
        Ok(self.keep(&snap, self.draft(&snap, kind, refs, body))?.address())
    }

    pub fn login(&self, app: &PublicKey, challenge: &[u8]) -> Result<Vec<u8>> {
        let snap = self.snapshot()?;
        self.allow(&snap, app, login::KIND, true)?;
        let challenge = Challenge::decode(challenge)?;
        let record = self.sign(&snap, challenge.draft(&self.root, &self.key.public(), snap.now))?;
        let manifest = Store::manifest_record(&snap.records, &self.root).cloned();
        Ok(Proof { login: record, manifest }.encode())
    }

    pub fn kinds(&self, app: &PublicKey) -> Result<Vec<(String, u64)>> {
        self.privileged(app)?;
        let snap = self.snapshot()?;
        let mut out: Vec<(String, u64)> = Vec::new();
        for r in self.own(&snap) {
            match out.iter_mut().find(|(k, _)| k == r.kind()) {
                Some((_, n)) => *n += 1,
                None => out.push((r.kind().to_owned(), 1)),
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    pub fn grants(&self, app: &PublicKey) -> Result<Vec<Record>> {
        self.privileged(app)?;
        let snap = self.snapshot()?;
        Ok(snap.grants(&self.root).into_iter().map(|(r, _)| r.clone()).collect())
    }

    pub fn revoke(&self, app: &PublicKey, grant: Address) -> Result<Address> {
        self.privileged(app)?;
        let snap = self.snapshot()?;
        if !snap.grants(&self.root).iter().any(|(r, _)| r.address() == grant) {
            return Err(Error::Refused("no such grant"));
        }
        let draft = Revoke { grant }.draft(&self.root, &self.key.public(), snap.now);
        Ok(self.keep(&snap, draft)?.address())
    }

    pub fn publish(
        &self,
        app: &PublicKey,
        body: Vec<u8>,
        name: Option<&str>,
    ) -> Result<Vec<Record>> {
        self.privileged(app)?;
        let snap = self.snapshot()?;
        let page = self.sign(&snap, self.draft(&snap, PAGE, vec![], body))?;
        let mut out = vec![page];
        if let Some(name) = name {
            let existing = Store::pointers(&snap.records, &self.root, name, snap.manifest.as_ref());
            let seq = existing.iter().map(|(_, p)| p.seq).max().map_or(1, |s| s.saturating_add(1));
            let prev = Store::head(&existing).map(|(r, _)| r.address()).into_iter().collect();
            let pointer = Pointer { name: name.to_owned(), target: out[0].address(), seq, prev };
            out.push(self.sign(&snap, pointer.draft(&self.root, &self.key.public(), snap.now))?);
        }
        for record in &out {
            self.home.store().put(record)?;
        }
        Ok(out)
    }

    pub fn verify_auth(app: &PublicKey, nonce: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
        app.verify_in(crate::wire::DOMAIN, nonce, sig).map_err(|_| Error::Refused("bad auth"))
    }
}
