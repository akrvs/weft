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
        guardians: None,
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

#[test]
fn stale_parts_are_swept_and_blobs_are_not() {
    let dir = std::env::temp_dir().join(format!("weft-home-{}-parts", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("blobs")).unwrap();
    let store = Store::new(dir.clone());
    let old = store.part_path(&Address::of(b"old"));
    let fresh = store.part_path(&Address::of(b"fresh"));
    std::fs::write(&old, b"o").unwrap();
    std::fs::write(&fresh, b"f").unwrap();
    store.keep_blob(&Address::of(b"blob"), b"blob").unwrap();
    let ago = std::time::SystemTime::now()
        - weft_home::store::PART_TTL
        - std::time::Duration::from_secs(1);
    std::fs::File::open(&old).unwrap().set_modified(ago).unwrap();
    assert_eq!(store.snapshot().unwrap().records().count(), 0);
    assert!(!old.exists());
    assert!(fresh.exists());
    assert_eq!(store.sweep_parts(None).unwrap(), 1);
    assert!(!fresh.exists());
    assert_eq!(store.blob(&Address::of(b"blob")).unwrap().unwrap(), b"blob");
    assert_eq!(store.sweep_parts(None).unwrap(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_cache_stays_under_its_cap_and_reads_fall_through_to_disk() {
    let dir = std::env::temp_dir().join(format!("weft-home-{}-cap", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let root = key(1);
    let notes: Vec<_> = (0..8u8)
        .map(|n| {
            Draft {
                author: root.public(),
                signer: root.public(),
                kind: "note".into(),
                created: u64::from(n) + 1,
                refs: vec![],
                body: Body::Inline(vec![n; 64]),
            }
            .sign(&root)
            .unwrap()
        })
        .collect();
    let one = notes[0].to_bytes().len() as u64;
    let store = Store::with_cache(dir.clone(), one * 3);
    for note in &notes {
        store.put(note).unwrap();
    }
    assert_eq!(store.snapshot().unwrap().records().count(), 8);
    assert!(store.cached_bytes() <= one * 3, "{} cached", store.cached_bytes());
    for note in &notes {
        assert_eq!(store.record(note.address()).unwrap().unwrap(), *note);
        assert!(store.cached_bytes() <= one * 3);
    }
    let hot = notes[0].address();
    store.record(hot).unwrap();
    store.record(notes[1].address()).unwrap();
    store.record(hot).unwrap();
    store.record(notes[2].address()).unwrap();
    let records = dir.join("records");
    std::fs::remove_file(records.join(format!("{hot}.weft"))).unwrap();
    std::fs::remove_file(records.join(format!("{}.weft", notes[1].address()))).unwrap();
    assert!(store.record(hot).unwrap().is_some(), "a refreshed record outlives an older one");
    store.record(notes[3].address()).unwrap();
    assert!(store.record(notes[1].address()).unwrap().is_none(), "the oldest was evicted");
    assert!(store.record(hot).unwrap().is_some());
    assert_eq!(store.snapshot().unwrap().records().count(), 6);
    assert!(store.record(hot).unwrap().is_none());
    let unlimited = Store::with_cache(dir.clone(), 0);
    assert_eq!(unlimited.snapshot().unwrap().records().count(), 6);
    assert_eq!(unlimited.cached_bytes(), one * 6);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_index_is_reused_until_the_directory_changes_and_loads_on_demand() {
    let dir = std::env::temp_dir().join(format!("weft-home-{}-index", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let root = key(1);
    let note = |n: u8| {
        Draft {
            author: root.public(),
            signer: root.public(),
            kind: "note".into(),
            created: u64::from(n) + 1,
            refs: vec![],
            body: Body::Inline(vec![n; 64]),
        }
        .sign(&root)
        .unwrap()
    };
    let notes: Vec<_> = (0..4u8).map(note).collect();
    let store = Store::with_cache(dir.clone(), 1);
    for n in &notes {
        store.put(n).unwrap();
    }
    let records = dir.join("records");
    let settled = std::time::SystemTime::now() - std::time::Duration::from_secs(5);
    let dir_file = std::fs::File::open(&records).unwrap();
    dir_file.set_modified(settled).unwrap();
    assert_eq!(store.snapshot().unwrap().len(), 4);

    let fifth = note(9);
    store.put(&fifth).unwrap();
    dir_file.set_modified(settled).unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.len(), 4, "an unchanged mtime reuses the index");
    assert!(snap.find(fifth.address()).is_none());
    dir_file.set_modified(std::time::SystemTime::now()).unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.len(), 5, "a changed mtime walks again");
    assert!(snap.find(fifth.address()).is_some());
    assert_eq!(store.cached_bytes(), 0, "a walk keeps nothing past the cap");

    dir_file.set_modified(settled).unwrap();
    assert_eq!(store.snapshot().unwrap().len(), 5);
    for n in notes.iter().chain([&fifth]) {
        std::fs::remove_file(records.join(format!("{}.weft", n.address()))).unwrap();
    }
    dir_file.set_modified(settled).unwrap();
    let snap = store.snapshot().unwrap();
    assert_eq!(snap.len(), 5, "metadata comes from the index");
    assert_eq!(snap.records().count(), 0, "records load from disk when asked");
    assert!(snap.own(&root.public(), None).next().is_none());
    dir_file.set_modified(std::time::SystemTime::now()).unwrap();
    assert!(store.snapshot().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
