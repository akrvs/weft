use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use weft_core::{
    Address, Body, Challenge, Draft, Grant, Manifest, Pointer, Proof, PublicKey, Record, Revoke,
    SecretKey, grant, login, manifest, verify,
};
use weft_home::{Home, Snapshot, Store};
use zeroize::Zeroizing;

use crate::wire::MAX_CHUNK;
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
    weft_home::fs::replace_private(&browser_key_path(home), seed.as_ref())?;
    Ok(SecretKey::from_seed(*seed))
}

#[derive(Debug)]
pub struct Gate {
    home: Home,
    root: PublicKey,
    key: SecretKey,
    browser: PublicKey,
}

struct View {
    snap: Snapshot,
    manifest: Option<Manifest>,
    now: u64,
}

impl View {
    fn grants(&self, root: &PublicKey) -> Vec<(&Record, Grant)> {
        self.snap.grants(root, self.manifest.as_ref(), self.now)
    }

    fn own<'a>(&'a self, root: &PublicKey) -> impl Iterator<Item = &'a Record> {
        self.snap.own(root, self.manifest.as_ref())
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

    fn view(&self) -> Result<View> {
        let snap = self.home.store().snapshot()?;
        let manifest = snap.manifest(&self.root);
        Ok(View { snap, manifest, now: weft_home::now()? })
    }

    fn privileged(&self, app: &PublicKey) -> Result<()> {
        if app == &self.browser { Ok(()) } else { Err(Error::Refused("browser only")) }
    }

    fn allow(&self, view: &View, app: &PublicKey, kind: &str, write: bool) -> Result<()> {
        if grant::RESERVED.contains(&kind) {
            return Err(Error::Refused("reserved kind"));
        }
        if app == &self.browser {
            return Ok(());
        }
        let permitted = view.grants(&self.root).iter().any(|(_, g)| {
            &g.app == app
                && g.covers(kind)
                && if write { g.access.writes() } else { g.access.reads() }
        });
        if permitted { Ok(()) } else { Err(Error::Refused("no active grant")) }
    }

    fn draft(&self, view: &View, kind: &str, refs: Vec<Address>, body: Vec<u8>) -> Draft {
        Draft {
            author: self.root,
            signer: self.key.public(),
            kind: kind.to_owned(),
            created: view.now,
            refs,
            body: Body::Inline(body),
        }
    }

    fn sign(&self, view: &View, draft: Draft) -> Result<Record> {
        let record = draft.sign(&self.key)?;
        verify(&record, view.manifest.as_ref())?;
        Ok(record)
    }

    fn keep_signed(&self, view: &View, draft: Draft) -> Result<Record> {
        let record = self.sign(view, draft)?;
        self.home.store().put(&record)?;
        Ok(record)
    }

    pub fn list(&self, app: &PublicKey, kind: &str) -> Result<Vec<Address>> {
        let view = self.view()?;
        self.allow(&view, app, kind, false)?;
        let mut out: Vec<Address> =
            view.own(&self.root).filter(|r| r.kind() == kind).map(Record::address).collect();
        out.sort_unstable();
        Ok(out)
    }

    pub fn get(&self, app: &PublicKey, address: &Address) -> Result<Vec<u8>> {
        let view = self.view()?;
        let record = view
            .own(&self.root)
            .find(|r| &r.address() == address)
            .ok_or(Error::Refused("no such record"))?;
        self.allow(&view, app, record.kind(), false)?;
        Ok(record.to_bytes())
    }

    pub fn put(
        &self,
        app: &PublicKey,
        kind: &str,
        body: Vec<u8>,
        refs: Vec<Address>,
    ) -> Result<Address> {
        let view = self.view()?;
        self.allow(&view, app, kind, true)?;
        Ok(self.keep_signed(&view, self.draft(&view, kind, refs, body))?.address())
    }

    pub fn login(&self, app: &PublicKey, challenge: &[u8]) -> Result<Vec<u8>> {
        let view = self.view()?;
        self.allow(&view, app, login::KIND, true)?;
        let challenge = Challenge::decode(challenge)?;
        let record = self.sign(&view, challenge.draft(&self.root, &self.key.public(), view.now))?;
        let manifest = view.snap.manifest_record(&self.root).cloned();
        Ok(Proof { login: record, manifest }.encode())
    }

    pub fn kinds(&self, app: &PublicKey) -> Result<Vec<(String, u64)>> {
        self.privileged(app)?;
        let view = self.view()?;
        let mut out: Vec<(String, u64)> = Vec::new();
        for r in view.own(&self.root) {
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
        let view = self.view()?;
        Ok(view.grants(&self.root).into_iter().map(|(r, _)| r.clone()).collect())
    }

    pub fn revoke(&self, app: &PublicKey, grant: Address) -> Result<Address> {
        self.privileged(app)?;
        let view = self.view()?;
        if !view.grants(&self.root).iter().any(|(r, _)| r.address() == grant) {
            return Err(Error::Refused("no such grant"));
        }
        let draft = Revoke { grant }.draft(&self.root, &self.key.public(), view.now);
        Ok(self.keep_signed(&view, draft)?.address())
    }

    pub fn publish(
        &self,
        app: &PublicKey,
        body: Vec<u8>,
        name: Option<&str>,
    ) -> Result<Vec<Record>> {
        self.privileged(app)?;
        let view = self.view()?;
        let page = self.sign(&view, self.draft(&view, PAGE, vec![], body))?;
        let mut out = vec![page];
        if let Some(name) = name {
            let existing = view.snap.pointers(&self.root, name, view.manifest.as_ref());
            let seq = existing.iter().map(|(_, p)| p.seq).max().map_or(1, |s| s.saturating_add(1));
            let prev = Store::head(&existing).map(|(r, _)| r.address()).into_iter().collect();
            let pointer = Pointer { name: name.to_owned(), target: out[0].address(), seq, prev };
            out.push(self.sign(&view, pointer.draft(&self.root, &self.key.public(), view.now))?);
        }
        for record in &out {
            self.home.store().put(record)?;
        }
        Ok(out)
    }

    pub fn record(&self, app: &PublicKey, address: Address) -> Result<Option<Vec<u8>>> {
        self.privileged(app)?;
        Ok(self.home.store().record(address)?.map(|r| r.to_bytes()))
    }

    pub fn manifest(&self, app: &PublicKey, author: &PublicKey) -> Result<Option<Vec<u8>>> {
        self.privileged(app)?;
        Ok(self.home.store().snapshot()?.manifest_record(author).map(Record::to_bytes))
    }

    pub fn pointers(&self, app: &PublicKey, author: &PublicKey, name: &str) -> Result<Vec<Record>> {
        self.privileged(app)?;
        let snap = self.home.store().snapshot()?;
        let manifest = snap.manifest(author);
        Ok(snap
            .pointers(author, name, manifest.as_ref())
            .into_iter()
            .map(|(r, _)| r.clone())
            .collect())
    }

    pub fn blob(
        &self,
        app: &PublicKey,
        address: &Address,
        offset: u64,
    ) -> Result<Option<(u64, Vec<u8>)>> {
        self.privileged(app)?;
        let mut file = match std::fs::File::open(self.home.blob_path(address)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let total = file.metadata()?.len();
        if offset > total {
            return Err(Error::Refused("offset past the end"));
        }
        let want = usize::try_from(total - offset).map_or(MAX_CHUNK, |rest| rest.min(MAX_CHUNK));
        file.seek(SeekFrom::Start(offset))?;
        let mut chunk = vec![0u8; want];
        file.read_exact(&mut chunk)?;
        Ok(Some((total, chunk)))
    }

    pub fn keep_blob(
        &self,
        app: &PublicKey,
        address: &Address,
        total: u64,
        offset: u64,
        chunk: &[u8],
    ) -> Result<()> {
        self.privileged(app)?;
        let len = u64::try_from(chunk.len()).map_err(|_| Error::Wire("chunk too large"))?;
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= total)
            .ok_or(Error::Refused("chunk past the end"))?;
        if chunk.is_empty() && end < total {
            return Err(Error::Refused("empty chunk"));
        }
        if self.home.blob_path(address).is_file() {
            return Ok(());
        }
        let part = self.home.store().part_path(address);
        let mut file = if offset == 0 {
            if let Some(parent) = part.parent() {
                weft_home::fs::ensure_dir(parent)?;
            }
            OpenOptions::new().write(true).create(true).truncate(true).mode(0o644).open(&part)?
        } else {
            let file = match OpenOptions::new().append(true).open(&part) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error::Refused("no blob in progress"));
                }
                Err(e) => return Err(e.into()),
            };
            if file.metadata()?.len() != offset {
                return Err(Error::Refused("offset is not the part length"));
            }
            file
        };
        file.write_all(chunk)?;
        if end < total {
            return Ok(());
        }
        drop(file);
        let data = std::fs::read(&part)?;
        let kept = self.home.keep_blob(address, &data);
        let _ = std::fs::remove_file(&part);
        Ok(kept?)
    }

    pub fn keep(&self, app: &PublicKey, record: &[u8]) -> Result<()> {
        self.privileged(app)?;
        let record = Record::from_bytes(record)?;
        let manifest = if record.kind() == manifest::KIND {
            None
        } else {
            self.home.store().snapshot()?.manifest(record.author())
        };
        verify(&record, manifest.as_ref())?;
        self.home.store().put(&record)?;
        Ok(())
    }

    pub fn verify_auth(app: &PublicKey, nonce: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
        app.verify_in(crate::wire::DOMAIN, nonce, sig).map_err(|_| Error::Refused("bad auth"))
    }
}
