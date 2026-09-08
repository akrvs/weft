#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use weft_core::{Address, Body, Device, Draft, Manifest, SecretKey};
use weft_home::Store;

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

#[test]
fn snapshots_see_every_writer_and_skip_files_that_lie() {
    let dir = std::env::temp_dir().join(format!("weft-home-{}-snapshots", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let root = key(1);
    let device = key(2);
    let a = Store::new(dir.clone());
    let b = Store::new(dir.clone());
    let manifest = Manifest {
        seq: 1,
        prev: None,
        devices: vec![Device {
            key: device.public(),
            label: "d".into(),
            created: 1,
            expires: None,
        }],
        revoked: vec![],
    }
    .draft(&root.public(), 1)
    .sign(&root)
    .unwrap();
    a.put(&manifest).unwrap();
    assert_eq!(b.snapshot().unwrap().records().count(), 1);
    let note = Draft {
        author: root.public(),
        signer: device.public(),
        kind: "note".into(),
        created: 2,
        refs: vec![],
        body: Body::Inline(b"n".to_vec()),
    }
    .sign(&device)
    .unwrap();
    b.put(&note).unwrap();
    let snap = a.snapshot().unwrap();
    assert_eq!(snap.records().count(), 2);
    let m = snap.manifest(&root.public()).unwrap();
    assert_eq!(snap.own(&root.public(), Some(&m)).count(), 2);
    assert_eq!(snap.own(&root.public(), None).count(), 1);
    assert_eq!(a.record(note.address()).unwrap().unwrap(), note);
    let records = dir.join("records");
    std::fs::write(records.join(format!("{}.weft", Address::of(b"liar"))), note.to_bytes())
        .unwrap();
    std::fs::write(records.join("junk.weft"), b"junk").unwrap();
    std::fs::write(records.join("readme.txt"), b"x").unwrap();
    let snap = a.snapshot().unwrap();
    assert_eq!(snap.records().count(), 2);
    assert!(a.record(Address::of(b"liar")).unwrap().is_none());
    assert!(a.record(Address::of(b"absent")).unwrap().is_none());
    assert!(snap.find(note.address()).is_some());
    assert!(a.blob(&Address::of(b"none")).unwrap().is_none());
    assert!(a.keep_blob(&Address::of(b"bytes"), b"other").is_err());
    assert!(a.blob(&Address::of(b"bytes")).unwrap().is_none());
    a.keep_blob(&Address::of(b"bytes"), b"bytes").unwrap();
    assert_eq!(b.blob(&Address::of(b"bytes")).unwrap().unwrap(), b"bytes");
    std::fs::remove_file(records.join(format!("{}.weft", note.address()))).unwrap();
    assert!(a.record(note.address()).unwrap().is_some());
    assert_eq!(a.snapshot().unwrap().records().count(), 1);
    assert!(a.record(note.address()).unwrap().is_none());
}
