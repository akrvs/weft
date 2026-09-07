#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use weft_core::{
    Access, Address, Body, Challenge, Device, Draft, Grant, Manifest, Pointer, Record, Revoke,
    SecretKey, verify,
};
use weft_home::{Home, Reads, Store};
use weft_store::wire::{self, DOMAIN, MAX_BLOB, MAX_CHUNK, MAX_RECORD, Request, Response};
use weft_store::{Client, Error, Gate, Local};

const T0: u64 = 1_000;

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

struct World {
    dir: PathBuf,
    root: SecretKey,
    device: SecretKey,
    app: SecretKey,
    browser: SecretKey,
    socket: PathBuf,
}

impl World {
    fn start(name: &str, gate_key: u8) -> Self {
        let dir = std::env::temp_dir().join(format!("weft-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = key(1);
        let device = key(2);
        let app = key(3);
        let browser = key(6);
        let manifest = Manifest {
            seq: 1,
            prev: None,
            devices: vec![Device {
                key: device.public(),
                label: "store".into(),
                created: T0,
                expires: None,
            }],
            revoked: vec![],
        };
        let store = Store::new(dir.clone());
        store.put(&manifest.draft(&root.public(), T0).sign(&root).unwrap()).unwrap();
        let socket = dir.join("store.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let gate = Arc::new(Gate::new(
            Home::new(dir.clone()),
            root.public(),
            key(gate_key),
            browser.public(),
        ));
        tokio::spawn(async move {
            let _ = weft_store::serve(gate, listener).await;
        });
        Self { dir, root, device, app, browser, socket }
    }

    fn store(&self) -> Store {
        Store::new(self.dir.clone())
    }

    fn all(&self) -> Vec<Record> {
        self.store().snapshot().unwrap().records().cloned().collect()
    }

    fn manifest(&self) -> Manifest {
        self.store().snapshot().unwrap().manifest(&self.root.public()).unwrap()
    }

    fn put(&self, record: &Record) -> Address {
        self.store().put(record).unwrap();
        record.address()
    }

    fn note(&self, text: &str) -> Address {
        self.put(
            &Draft {
                author: self.root.public(),
                signer: self.device.public(),
                kind: "note".into(),
                created: T0 + 1,
                refs: vec![],
                body: Body::Inline(text.as_bytes().to_vec()),
            }
            .sign(&self.device)
            .unwrap(),
        )
    }

    fn grant(&self, kinds: &[&str], access: Access, expires: Option<u64>) -> Address {
        let grant = Grant {
            app: self.app.public(),
            kinds: kinds.iter().map(|k| (*k).to_owned()).collect(),
            access,
            expires,
        };
        self.put(
            &grant
                .draft(&self.root.public(), &self.device.public(), T0 + 1)
                .sign(&self.device)
                .unwrap(),
        )
    }

    fn revoke(&self, grant: Address) {
        let revoke = Revoke { grant };
        self.put(
            &revoke
                .draft(&self.root.public(), &self.root.public(), T0 + 2)
                .sign(&self.root)
                .unwrap(),
        );
    }

    async fn client(&self) -> Client {
        Client::connect(&self.socket, &self.app).await.unwrap()
    }

    async fn browser(&self) -> Client {
        Client::connect(&self.socket, &self.browser).await.unwrap()
    }
}

fn refused(result: Result<impl core::fmt::Debug, Error>, why: &str) {
    match result {
        Err(Error::Remote(text)) => assert!(text.contains(why), "{text}"),
        other => panic!("expected refusal {why}, got {other:?}"),
    }
}

#[tokio::test]
async fn handshake_rejects_bad_first_message_and_bad_signature() {
    let w = World::start("handshake", 2);
    let mut raw = UnixStream::connect(&w.socket).await.unwrap();
    let hello = Response::decode(&wire::recv(&mut raw).await.unwrap().unwrap()).unwrap();
    let Response::Hello { nonce } = hello else { panic!() };
    wire::send(&mut raw, &Request::List { kind: "note".into() }.encode()).await.unwrap();
    let Response::Error { why } =
        Response::decode(&wire::recv(&mut raw).await.unwrap().unwrap()).unwrap()
    else {
        panic!()
    };
    assert!(why.contains("auth first"));

    let mut raw = UnixStream::connect(&w.socket).await.unwrap();
    let Response::Hello { nonce: fresh } =
        Response::decode(&wire::recv(&mut raw).await.unwrap().unwrap()).unwrap()
    else {
        panic!()
    };
    assert_ne!(nonce, fresh);
    let forged = key(4).sign_in(DOMAIN, &fresh);
    wire::send(&mut raw, &Request::Auth { app: w.app.public(), sig: forged }.encode())
        .await
        .unwrap();
    let Response::Error { why } =
        Response::decode(&wire::recv(&mut raw).await.unwrap().unwrap()).unwrap()
    else {
        panic!()
    };
    assert!(why.contains("bad auth"));

    let mut raw = UnixStream::connect(&w.socket).await.unwrap();
    let Response::Hello { nonce: fresh } =
        Response::decode(&wire::recv(&mut raw).await.unwrap().unwrap()).unwrap()
    else {
        panic!()
    };
    let replayed = w.app.sign_in(DOMAIN, &nonce);
    wire::send(&mut raw, &Request::Auth { app: w.app.public(), sig: replayed }.encode())
        .await
        .unwrap();
    let Response::Error { why } =
        Response::decode(&wire::recv(&mut raw).await.unwrap().unwrap()).unwrap()
    else {
        panic!()
    };
    assert!(why.contains("bad auth"), "{fresh:?}");
}

#[tokio::test]
async fn grants_gate_every_request() {
    let w = World::start("gate", 2);
    let note = w.note("hello");
    let mut c = w.client().await;
    refused(c.list("note").await, "no active grant");
    refused(c.get(note).await, "no active grant");
    refused(c.put("note", b"x".to_vec(), vec![]).await, "no active grant");

    let read = w.grant(&["note"], Access::Read, None);
    assert_eq!(c.list("note").await.unwrap(), vec![note]);
    assert_eq!(c.get(note).await.unwrap().body(), &Body::Inline(b"hello".to_vec()));
    refused(c.list("page").await, "no active grant");
    refused(c.put("note", b"x".to_vec(), vec![]).await, "no active grant");
    refused(c.list("grant").await, "reserved kind");
    refused(c.get(Address::of(b"nothing")).await, "no such record");

    w.revoke(read);
    refused(c.list("note").await, "no active grant");
    refused(c.get(note).await, "no active grant");

    w.grant(&["note"], Access::ReadWrite, None);
    let written = c.put("note", b"from the app".to_vec(), vec![note]).await.unwrap();
    let mut listed = c.list("note").await.unwrap();
    listed.sort_unstable();
    let mut expected = vec![note, written];
    expected.sort_unstable();
    assert_eq!(listed, expected);
    let record = c.get(written).await.unwrap();
    assert_eq!(record.signer(), &w.device.public());
    assert_eq!(record.author(), &w.root.public());
    assert_eq!(record.refs(), &[note]);
    verify(&record, Some(&w.manifest())).unwrap();
    refused(c.put("pointer", b"x".to_vec(), vec![]).await, "reserved kind");
}

#[tokio::test]
async fn expired_and_foreign_grants_do_not_count() {
    let w = World::start("expired", 2);
    w.note("hello");
    w.grant(&["note"], Access::Read, Some(T0 + 2));
    let mut c = w.client().await;
    refused(c.list("note").await, "no active grant");
    let other = Grant {
        app: key(4).public(),
        kinds: vec!["note".into()],
        access: Access::ReadWrite,
        expires: None,
    };
    w.put(&other.draft(&w.root.public(), &w.root.public(), T0 + 1).sign(&w.root).unwrap());
    refused(c.list("note").await, "no active grant");
    let stranger = Grant {
        app: w.app.public(),
        kinds: vec!["note".into()],
        access: Access::ReadWrite,
        expires: None,
    };
    w.put(&stranger.draft(&w.root.public(), &key(4).public(), T0 + 1).sign(&key(4)).unwrap());
    refused(c.list("note").await, "no active grant");
}

#[tokio::test]
async fn unauthorized_device_cannot_write() {
    let w = World::start("unauthorized", 5);
    w.grant(&["note"], Access::ReadWrite, None);
    let mut c = w.client().await;
    assert_eq!(c.list("note").await.unwrap(), Vec::<Address>::new());
    refused(c.put("note", b"x".to_vec(), vec![]).await, "not authorized");
}

#[tokio::test]
async fn login_needs_a_write_grant_and_stores_nothing() {
    let w = World::start("login", 2);
    let challenge =
        Challenge { service: "http://127.0.0.1:8080".into(), nonce: [9; 32], expires: u64::MAX };
    let mut c = w.client().await;
    refused(c.login(&challenge).await, "no active grant");
    let read = w.grant(&["login"], Access::Read, None);
    refused(c.login(&challenge).await, "no active grant");
    w.revoke(read);
    w.grant(&["login", "note"], Access::ReadWrite, None);
    let before = w.all().len();
    let proof = c.login(&challenge).await.unwrap();
    let login = proof.verify("http://127.0.0.1:8080", T0 + 5, None).unwrap();
    assert_eq!(login.author, w.root.public());
    assert_eq!(login.signer, w.device.public());
    assert_eq!(login.challenge, challenge);
    assert!(proof.verify("http://127.0.0.1:8081", T0 + 5, None).is_err());
    assert_eq!(w.all().len(), before);
    refused(c.put("login", challenge.encode(), vec![]).await, "never stored");
    assert!(c.list("login").await.unwrap().is_empty());
    let bad = Challenge { service: "HTTP://X".into(), ..challenge };
    refused(c.login(&bad).await, "service");
}

#[tokio::test]
async fn browser_is_privileged_and_applications_are_not() {
    let w = World::start("browser", 2);
    let note = w.note("hello");
    let mut app = w.client().await;
    refused(app.kinds().await, "browser only");
    refused(app.grants().await, "browser only");
    refused(app.revoke(note).await, "browser only");
    refused(app.publish(b"# x".to_vec(), None).await, "browser only");

    let mut b = w.browser().await;
    assert_eq!(b.kinds().await.unwrap(), vec![("manifest".to_owned(), 1), ("note".to_owned(), 1)]);
    assert_eq!(b.list("note").await.unwrap(), vec![note]);
    assert_eq!(b.get(note).await.unwrap().body(), &Body::Inline(b"hello".to_vec()));
    let written = b.put("note", b"from the browser".to_vec(), vec![]).await.unwrap();
    assert_eq!(b.get(written).await.unwrap().signer(), &w.device.public());
    refused(b.list("grant").await, "reserved kind");
    refused(b.put("pointer", b"x".to_vec(), vec![]).await, "reserved kind");
    let challenge =
        Challenge { service: "http://127.0.0.1:8080".into(), nonce: [7; 32], expires: u64::MAX };
    refused(b.put("login", challenge.encode(), vec![]).await, "never stored");
    assert!(b.grants().await.unwrap().is_empty());
    refused(b.revoke(note).await, "no such grant");

    let proof = b.login(&challenge).await.unwrap();
    let login = proof.verify("http://127.0.0.1:8080", T0 + 5, None).unwrap();
    assert_eq!(login.author, w.root.public());
    assert_eq!(login.signer, w.device.public());

    let grant = w.grant(&["note"], Access::Read, None);
    assert_eq!(app.list("note").await.unwrap().len(), 2);
    let grants = b.grants().await.unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].address(), grant);
    assert_eq!(Grant::from_record(&grants[0]).unwrap().app, w.app.public());
    let revoke = b.revoke(grant).await.unwrap();
    let all = w.all();
    let record = all.iter().find(|r| r.address() == revoke).unwrap();
    assert_eq!(record.kind(), "revoke");
    assert_eq!(Revoke::from_record(record).unwrap().grant, grant);
    assert_eq!(record.refs(), &[grant]);
    assert!(b.grants().await.unwrap().is_empty());
    refused(app.list("note").await, "no active grant");
    refused(b.revoke(grant).await, "no such grant");
}

#[tokio::test]
async fn publish_signs_a_page_and_the_next_pointer() {
    let w = World::start("publish", 2);
    let mut b = w.browser().await;
    let alone = b.publish(b"# alone".to_vec(), None).await.unwrap();
    assert_eq!(alone.len(), 1);
    assert_eq!(alone[0].kind(), "page");
    assert_eq!(alone[0].author(), &w.root.public());
    assert_eq!(alone[0].signer(), &w.device.public());

    let first = b.publish(b"# one".to_vec(), Some("home")).await.unwrap();
    assert_eq!(first.len(), 2);
    let pointer = Pointer::from_record(&first[1]).unwrap();
    assert_eq!(pointer.name, "home");
    assert_eq!(pointer.target, first[0].address());
    assert_eq!(pointer.seq, 1);
    assert!(pointer.prev.is_empty());

    let second = b.publish(b"# two".to_vec(), Some("home")).await.unwrap();
    let pointer = Pointer::from_record(&second[1]).unwrap();
    assert_eq!(pointer.seq, 2);
    assert_eq!(pointer.prev, vec![first[1].address()]);
    assert_eq!(pointer.target, second[0].address());

    let snap = w.store().snapshot().unwrap();
    let manifest = snap.manifest(&w.root.public()).unwrap();
    for r in alone.iter().chain(&first).chain(&second) {
        verify(r, Some(&manifest)).unwrap();
        assert!(snap.find(r.address()).is_some());
    }
    let heads = snap.pointers(&w.root.public(), "home", Some(&manifest));
    assert_eq!(Store::head(&heads).unwrap().1.target, second[0].address());
    assert_eq!(b.kinds().await.unwrap()[1], ("page".to_owned(), 3));
    assert_eq!(b.kinds().await.unwrap()[2], ("pointer".to_owned(), 2));
}

#[tokio::test]
async fn unauthorized_device_cannot_publish_or_revoke() {
    let w = World::start("unauthorized-browser", 5);
    let grant = w.grant(&["note"], Access::Read, None);
    let mut b = w.browser().await;
    refused(b.publish(b"# x".to_vec(), Some("home")).await, "not authorized");
    refused(b.revoke(grant).await, "not authorized");
    assert!(w.all().iter().all(|r| r.kind() != "page"));
}

#[test]
fn browser_key_file_is_created_once() {
    let dir = std::env::temp_dir().join(format!("weft-store-{}-key", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let created = weft_store::create_browser_key(&dir).unwrap();
    let path = weft_store::browser_key_path(&dir);
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 32);
    assert_eq!(weft_store::browser_key(&dir).unwrap().public(), created.public());
    assert!(weft_store::create_browser_key(&dir).is_err());
    assert_eq!(weft_store::browser_key(&dir).unwrap().public(), created.public());
    std::fs::write(&path, [0u8; 31]).unwrap();
    assert!(weft_store::browser_key(&dir).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wire_rejects_malformed_frames() {
    use weft_core::cbor::Value;
    let map = |pairs: Vec<(&str, Value)>| {
        Value::Map(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()).encode()
    };
    let app = key(3).public();
    for (buf, why) in [
        (
            map(vec![("t", Value::Text("list".into())), ("kind", Value::Text("Note".into()))]),
            "bad kind",
        ),
        (
            map(vec![("t", Value::Text("list".into())), ("kind", Value::Text(String::new()))]),
            "empty kind",
        ),
        (
            map(vec![
                ("t", Value::Text("list".into())),
                ("kind", Value::Text("note".into())),
                ("x", Value::Uint(1)),
            ]),
            "unknown field",
        ),
        (
            map(vec![("t", Value::Text("get".into())), ("address", Value::Bytes(vec![0; 31]))]),
            "short address",
        ),
        (
            map(vec![
                ("t", Value::Text("auth".into())),
                ("app", Value::Bytes(app.bytes().to_vec())),
                ("sig", Value::Bytes(vec![0; 63])),
            ]),
            "short sig",
        ),
        (
            map(vec![
                ("t", Value::Text("put".into())),
                ("kind", Value::Text("note".into())),
                ("body", Value::Bytes(vec![0; 65_537])),
                ("refs", Value::Array(vec![])),
            ]),
            "body too large",
        ),
        (
            map(vec![
                ("t", Value::Text("put".into())),
                ("kind", Value::Text("note".into())),
                ("body", Value::Bytes(vec![])),
                ("refs", Value::Array(vec![Value::Uint(1)])),
            ]),
            "bad ref",
        ),
        (
            map(vec![
                ("t", Value::Text("login".into())),
                ("challenge", Value::Bytes(vec![0; 1025])),
            ]),
            "challenge too large",
        ),
        (
            map(vec![("t", Value::Text("kinds".into())), ("x", Value::Uint(1))]),
            "unknown field on kinds",
        ),
        (
            map(vec![("t", Value::Text("revoke".into())), ("grant", Value::Bytes(vec![0; 31]))]),
            "short grant",
        ),
        (
            map(vec![
                ("t", Value::Text("publish".into())),
                ("body", Value::Bytes(vec![0; 65_537])),
            ]),
            "publish body too large",
        ),
        (
            map(vec![
                ("t", Value::Text("publish".into())),
                ("body", Value::Bytes(vec![])),
                ("name", Value::Text(String::new())),
            ]),
            "empty name",
        ),
        (
            map(vec![
                ("t", Value::Text("publish".into())),
                ("body", Value::Bytes(vec![])),
                ("name", Value::Text("n".repeat(65))),
            ]),
            "long name",
        ),
        (
            map(vec![
                ("t", Value::Text("keep".into())),
                ("record", Value::Bytes(vec![0; MAX_RECORD + 1])),
            ]),
            "record over the limit",
        ),
        (
            map(vec![
                ("t", Value::Text("blob".into())),
                ("address", Value::Bytes(vec![0; 32])),
                ("offset", Value::Uint(MAX_BLOB + 1)),
            ]),
            "offset over the limit",
        ),
        (
            map(vec![
                ("t", Value::Text("pointers".into())),
                ("author", Value::Bytes(vec![0; 32])),
                ("name", Value::Text(String::new())),
            ]),
            "empty pointer name",
        ),
        (
            map(vec![("t", Value::Text("manifest".into())), ("author", Value::Bytes(vec![0; 31]))]),
            "short author",
        ),
        (map(vec![("t", Value::Text("drop".into()))]), "unknown type"),
        (Value::Array(vec![]).encode(), "not a map"),
        (vec![0xa1, 0x61, 0x74, 0x64, 0x6c, 0x69, 0x73, 0x74, 0x00], "trailing bytes"),
    ] {
        assert!(Request::decode(&buf).is_err(), "{why}");
    }
    let round = Request::Publish { body: b"x".to_vec(), name: Some("home".into()) };
    assert_eq!(Request::decode(&round.encode()).unwrap(), round);
    let round = Request::Publish { body: b"x".to_vec(), name: None };
    assert_eq!(Request::decode(&round.encode()).unwrap(), round);
    for round in [
        Request::Record { address: Address::of(b"r") },
        Request::Manifest { author: key(1).public() },
        Request::Pointers { author: key(1).public(), name: "home".into() },
        Request::Blob { address: Address::of(b"b"), offset: 7 },
        Request::Keep { record: vec![1, 2, 3] },
    ] {
        assert_eq!(Request::decode(&round.encode()).unwrap(), round);
    }
}

#[test]
fn wire_rejects_malformed_responses() {
    use weft_core::cbor::Value;
    let map = |pairs: Vec<(&str, Value)>| {
        Value::Map(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()).encode()
    };
    assert!(
        Response::decode(&map(vec![
            ("t", Value::Text("hello".into())),
            ("nonce", Value::Bytes(vec![0; 16]))
        ]))
        .is_err()
    );
    for (buf, why) in [
        (
            map(vec![
                ("t", Value::Text("kinds".into())),
                ("kinds", Value::Array(vec![Value::Array(vec![Value::Text("Note".into())])])),
            ]),
            "kinds entry not a pair",
        ),
        (
            map(vec![
                ("t", Value::Text("kinds".into())),
                (
                    "kinds",
                    Value::Array(vec![Value::Array(vec![
                        Value::Text("Note".into()),
                        Value::Uint(1),
                    ])]),
                ),
            ]),
            "kinds bad kind",
        ),
        (
            map(vec![
                ("t", Value::Text("grants".into())),
                ("records", Value::Array(vec![Value::Uint(1)])),
            ]),
            "grants not bytes",
        ),
        (
            map(vec![
                ("t", Value::Text("publish".into())),
                ("records", Value::Array(vec![Value::Bytes(vec![]); 4097])),
            ]),
            "too many records",
        ),
        (
            map(vec![
                ("t", Value::Text("blob".into())),
                ("total", Value::Uint(MAX_BLOB + 1)),
                ("chunk", Value::Bytes(vec![])),
            ]),
            "total over the limit",
        ),
        (
            map(vec![
                ("t", Value::Text("blob".into())),
                ("total", Value::Uint(1)),
                ("chunk", Value::Bytes(vec![0; MAX_CHUNK + 1])),
            ]),
            "chunk over the limit",
        ),
        (
            map(vec![("t", Value::Text("missing".into())), ("x", Value::Uint(1))]),
            "missing with a field",
        ),
    ] {
        assert!(Response::decode(&buf).is_err(), "{why}");
    }
    for round in [
        Response::Missing,
        Response::Records { records: vec![vec![1], vec![2]] },
        Response::Blob { total: 9, chunk: vec![0; 4] },
    ] {
        assert_eq!(Response::decode(&round.encode()).unwrap(), round);
    }
    let round = Response::Kinds { kinds: vec![("note".into(), 2)] };
    assert_eq!(Response::decode(&round.encode()).unwrap(), round);
    let put = Request::Put { kind: "note".into(), body: vec![1, 2], refs: vec![Address::of(b"r")] };
    assert_eq!(Request::decode(&put.encode()).unwrap(), put);
    let list = Response::List { addresses: vec![Address::of(b"a")] };
    assert_eq!(Response::decode(&list.encode()).unwrap(), list);
}

fn foreign() -> (SecretKey, Record, Record, Record) {
    let root = key(7);
    let device = key(8);
    let manifest = Manifest {
        seq: 1,
        prev: None,
        devices: vec![Device {
            key: device.public(),
            label: "d".into(),
            created: T0,
            expires: None,
        }],
        revoked: vec![],
    }
    .draft(&root.public(), T0)
    .sign(&root)
    .unwrap();
    let page = Draft {
        author: root.public(),
        signer: device.public(),
        kind: "page".into(),
        created: T0 + 1,
        refs: vec![],
        body: Body::Inline(b"# far away".to_vec()),
    }
    .sign(&device)
    .unwrap();
    let pointer = Pointer { name: "home".into(), target: page.address(), seq: 1, prev: vec![] }
        .draft(&root.public(), &device.public(), T0 + 2)
        .sign(&device)
        .unwrap();
    (root, manifest, page, pointer)
}

async fn raw(w: &World, key: &SecretKey, request: &Request) -> Response {
    let mut stream = UnixStream::connect(&w.socket).await.unwrap();
    let hello = wire::recv(&mut stream).await.unwrap().unwrap();
    let Response::Hello { nonce } = Response::decode(&hello).unwrap() else { panic!() };
    let auth = Request::Auth { app: key.public(), sig: key.sign_in(DOMAIN, &nonce) };
    wire::send(&mut stream, &auth.encode()).await.unwrap();
    wire::recv(&mut stream).await.unwrap().unwrap();
    wire::send(&mut stream, &request.encode()).await.unwrap();
    Response::decode(&wire::recv(&mut stream).await.unwrap().unwrap()).unwrap()
}

#[tokio::test]
async fn reads_are_browser_only() {
    let w = World::start("reads-browser-only", 2);
    let (root, manifest, page, _) = foreign();
    let mut c = w.client().await;
    refused(c.record(page.address()).await, "browser only");
    refused(c.manifest(root.public()).await, "browser only");
    refused(c.pointers(root.public(), "home").await, "browser only");
    refused(c.blob(Address::of(b"x")).await, "browser only");
    refused(c.keep(&manifest).await, "browser only");
    assert!(w.all().iter().all(|r| r.address() != manifest.address()));
}

#[tokio::test]
async fn keep_verifies_before_storing() {
    let w = World::start("keep-verifies", 2);
    let (root, manifest, page, pointer) = foreign();
    let mut b = w.browser().await;
    assert!(matches!(b.keep(&page).await, Err(Error::Remote(_))));
    assert!(b.record(page.address()).await.unwrap().is_none());
    assert!(b.manifest(root.public()).await.unwrap().is_none());
    b.keep(&manifest).await.unwrap();
    b.keep(&page).await.unwrap();
    b.keep(&pointer).await.unwrap();
    assert_eq!(b.record(page.address()).await.unwrap().unwrap(), page);
    assert_eq!(b.manifest(root.public()).await.unwrap().unwrap(), manifest);
    assert_eq!(b.pointers(root.public(), "home").await.unwrap(), vec![pointer]);
    assert!(b.pointers(root.public(), "other").await.unwrap().is_empty());
    let challenge =
        Challenge { service: "http://127.0.0.1:8080".into(), nonce: [9; 32], expires: T0 + 100 };
    let login = challenge.draft(&w.root.public(), &w.root.public(), T0 + 3).sign(&w.root).unwrap();
    refused(b.keep(&login).await, "never stored");
    let mut forged = page.to_bytes();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let reply = raw(&w, &w.browser, &Request::Keep { record: forged }).await;
    assert!(matches!(reply, Response::Error { .. }));
}

#[tokio::test]
async fn blobs_cross_in_chunks() {
    let w = World::start("blob-chunks", 2);
    let data: Vec<u8> = (0..MAX_CHUNK + 1000).map(|i| u8::try_from(i % 251).unwrap()).collect();
    let address = Address::of(&data);
    Home::new(w.dir.clone()).keep_blob(&address, &data).unwrap();
    let mut b = w.browser().await;
    assert_eq!(b.blob(address).await.unwrap().unwrap(), data);
    assert!(b.blob(Address::of(b"nowhere")).await.unwrap().is_none());
    let first = raw(&w, &w.browser, &Request::Blob { address, offset: 0 }).await;
    let Response::Blob { total, chunk } = first else { panic!("{first:?}") };
    assert_eq!(total, data.len() as u64);
    assert_eq!(chunk.len(), MAX_CHUNK);
    let last = raw(&w, &w.browser, &Request::Blob { address, offset: total }).await;
    assert_eq!(last, Response::Blob { total, chunk: vec![] });
    let past = raw(&w, &w.browser, &Request::Blob { address, offset: total + 1 }).await;
    assert!(matches!(past, Response::Error { .. }));
}

#[tokio::test]
async fn local_reads_over_the_socket_and_reports_a_missing_daemon() {
    let w = World::start("local-reads", 2);
    let (root, manifest, page, pointer) = foreign();
    std::fs::write(w.dir.join("browser.key"), [6u8; 32]).unwrap();
    let local = Local::new(w.dir.clone());
    assert!(local.record(page.address()).await.unwrap().is_none());
    local.keep(&manifest).await.unwrap();
    local.keep(&page).await.unwrap();
    local.keep(&pointer).await.unwrap();
    assert_eq!(local.record(page.address()).await.unwrap().unwrap(), page);
    assert_eq!(local.manifest(root.public()).await.unwrap().unwrap(), manifest);
    assert_eq!(local.pointers(root.public(), "home").await.unwrap(), vec![pointer]);
    let data = b"blob bytes".to_vec();
    let address = Address::of(&data);
    Home::new(w.dir.clone()).keep_blob(&address, &data).unwrap();
    assert_eq!(local.blob(address).await.unwrap().unwrap(), data);
    let dead = std::env::temp_dir().join(format!("weft-store-{}-dead", std::process::id()));
    let _ = std::fs::remove_dir_all(&dead);
    std::fs::create_dir_all(&dead).unwrap();
    let down = Local::new(dead.clone());
    assert_eq!(down.blob(address).await.unwrap_err().to_string(), Error::Down.to_string());
    std::fs::write(dead.join("browser.key"), [6u8; 32]).unwrap();
    assert_eq!(down.blob(address).await.unwrap_err().to_string(), Error::Down.to_string());
}
