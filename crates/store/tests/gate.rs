#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use weft_core::{
    Access, Address, Body, Device, Draft, Grant, Manifest, Record, Revoke, SecretKey, verify,
};
use weft_home::{Home, Store};
use weft_store::wire::{self, DOMAIN, Request, Response};
use weft_store::{Client, Error, Gate};

const T0: u64 = 1_000;

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

struct World {
    dir: PathBuf,
    root: SecretKey,
    device: SecretKey,
    app: SecretKey,
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
        let store = Store::new(dir.join("records"));
        store.put(&manifest.draft(&root.public(), T0).sign(&root).unwrap()).unwrap();
        let socket = dir.join("store.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let gate = Arc::new(Gate::new(Home::new(dir.clone()), root.public(), key(gate_key)));
        tokio::spawn(async move {
            let _ = weft_store::serve(gate, listener).await;
        });
        Self { dir, root, device, app, socket }
    }

    fn store(&self) -> Store {
        Store::new(self.dir.join("records"))
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
    let all = w.store().all().unwrap();
    let manifest = Store::manifest(&all, &w.root.public()).unwrap();
    verify(&record, Some(&manifest)).unwrap();
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
        (map(vec![("t", Value::Text("drop".into()))]), "unknown type"),
        (Value::Array(vec![]).encode(), "not a map"),
        (vec![0xa1, 0x61, 0x74, 0x64, 0x6c, 0x69, 0x73, 0x74, 0x00], "trailing bytes"),
    ] {
        assert!(Request::decode(&buf).is_err(), "{why}");
    }
    assert!(
        Response::decode(&map(vec![
            ("t", Value::Text("hello".into())),
            ("nonce", Value::Bytes(vec![0; 16]))
        ]))
        .is_err()
    );
    let put = Request::Put { kind: "note".into(), body: vec![1, 2], refs: vec![Address::of(b"r")] };
    assert_eq!(Request::decode(&put.encode()).unwrap(), put);
    let list = Response::List { addresses: vec![Address::of(b"a")] };
    assert_eq!(Response::decode(&list.encode()).unwrap(), list);
}
