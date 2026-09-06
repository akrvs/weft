use std::path::{Path, PathBuf};

use weft_core::{
    Address, Body, Challenge, Draft, Grant, Manifest, Proof, PublicKey, Record, SecretKey, grant,
    login, verify,
};
use weft_home::{Home, Store};

use crate::{Error, Result};

pub const SOCKET: &str = "store.sock";

pub fn socket_path(home: &Path) -> PathBuf {
    home.join(SOCKET)
}

#[derive(Debug)]
pub struct Gate {
    home: Home,
    root: PublicKey,
    key: SecretKey,
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
    pub fn new(home: Home, root: PublicKey, key: SecretKey) -> Self {
        Self { home, root, key }
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

    fn allow(&self, snap: &Snapshot, app: &PublicKey, kind: &str, write: bool) -> Result<()> {
        if grant::RESERVED.contains(&kind) {
            return Err(Error::Refused("reserved kind"));
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
        let draft = Draft {
            author: self.root,
            signer: self.key.public(),
            kind: kind.to_owned(),
            created: snap.now,
            refs,
            body: Body::Inline(body),
        };
        let record = draft.sign(&self.key)?;
        verify(&record, snap.manifest.as_ref())?;
        self.home.store().put(&record)?;
        Ok(record.address())
    }

    pub fn login(&self, app: &PublicKey, challenge: &[u8]) -> Result<Vec<u8>> {
        let snap = self.snapshot()?;
        self.allow(&snap, app, login::KIND, true)?;
        let challenge = Challenge::decode(challenge)?;
        let record = challenge.draft(&self.root, &self.key.public(), snap.now).sign(&self.key)?;
        verify(&record, snap.manifest.as_ref())?;
        let manifest = Store::manifest_record(&snap.records, &self.root).cloned();
        Ok(Proof { login: record, manifest }.encode())
    }

    pub fn verify_auth(app: &PublicKey, nonce: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
        app.verify_in(crate::wire::DOMAIN, nonce, sig).map_err(|_| Error::Refused("bad auth"))
    }
}
