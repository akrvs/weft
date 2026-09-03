#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use std::str::FromStr;

use weft_core::address::Kind;
use weft_core::{
    Address, Body, Device, Draft, Error, Manifest, Pointer, PublicKey, SecretKey, verify,
};

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

fn manifest(root: &SecretKey, device: &SecretKey) -> (Manifest, weft_core::Record) {
    let m = Manifest {
        seq: 1,
        prev: None,
        devices: vec![Device {
            key: device.public(),
            label: "laptop".into(),
            created: 1_000,
            expires: Some(2_000),
        }],
        revoked: vec![],
    };
    let r = m.draft(&root.public(), 1_000).sign(root).unwrap();
    (m, r)
}

fn page(root: &SecretKey, signer: &SecretKey, created: u64) -> weft_core::Record {
    Draft {
        author: root.public(),
        signer: signer.public(),
        kind: "page".into(),
        created,
        refs: vec![],
        body: Body::Inline(b"hello".to_vec()),
    }
    .sign(signer)
    .unwrap()
}

#[test]
fn address_roundtrip_and_checksum() {
    let a = Address::key(*key(1).public().bytes());
    let s = a.to_string();
    assert_eq!(s.len(), 60);
    assert_eq!(Address::from_str(&s).unwrap(), a);
    let mut broken = s.clone().into_bytes();
    broken[10] = if broken[10] == b'a' { b'b' } else { b'a' };
    assert_eq!(
        Address::from_str(std::str::from_utf8(&broken).unwrap()).unwrap_err(),
        Error::Address("checksum mismatch")
    );
    assert!(Address::from_str(&s.to_uppercase()).is_err());
    assert_eq!(Address::of(b"x").kind(), Kind::Hash);
}

#[test]
fn record_bytes_are_canonical_and_stable() {
    let root = key(1);
    let r = page(&root, &root, 5);
    let bytes = r.to_bytes();
    let back = weft_core::Record::from_bytes(&bytes).unwrap();
    assert_eq!(back, r);
    assert_eq!(back.address(), r.address());
    assert_eq!(verify(&r, None).unwrap().kind, "page");
}

#[test]
fn tampering_breaks_signature() {
    let root = key(1);
    let mut bytes = page(&root, &root, 5).to_bytes();
    let i = bytes.len() - 1;
    bytes[i] ^= 1;
    let r = weft_core::Record::from_bytes(&bytes).unwrap();
    assert_eq!(verify(&r, None).unwrap_err(), Error::Signature);
}

#[test]
fn device_authorization_window() {
    let root = key(1);
    let dev = key(2);
    let (m, mr) = manifest(&root, &dev);
    assert!(verify(&mr, None).is_ok());
    assert_eq!(verify(&page(&root, &dev, 1_500), None).unwrap_err(), Error::Unauthorized);
    assert!(verify(&page(&root, &dev, 1_500), Some(&m)).is_ok());
    assert_eq!(verify(&page(&root, &dev, 999), Some(&m)).unwrap_err(), Error::Expired);
    assert_eq!(verify(&page(&root, &dev, 2_000), Some(&m)).unwrap_err(), Error::Expired);
    assert_eq!(verify(&page(&root, &key(3), 1_500), Some(&m)).unwrap_err(), Error::Unauthorized);
}

#[test]
fn revocation_wins() {
    let root = key(1);
    let dev = key(2);
    let m = Manifest { seq: 2, prev: None, devices: vec![], revoked: vec![dev.public()] };
    assert_eq!(verify(&page(&root, &dev, 1_500), Some(&m)).unwrap_err(), Error::Revoked);
    let bad = Manifest {
        seq: 3,
        prev: None,
        devices: vec![Device { key: dev.public(), label: "x".into(), created: 1, expires: None }],
        revoked: vec![dev.public()],
    };
    assert!(bad.check(&root.public()).is_err());
}

#[test]
fn manifest_must_be_root_signed() {
    let root = key(1);
    let dev = key(2);
    let m = Manifest { seq: 1, prev: None, devices: vec![], revoked: vec![] };
    let mut d = m.draft(&root.public(), 1);
    d.signer = dev.public();
    let r = d.sign(&dev).unwrap();
    assert_eq!(verify(&r, None).unwrap_err(), Error::Unauthorized);
    let p = Pointer { name: "manifest".into(), target: r.address(), seq: 1, prev: vec![] };
    let pr = p.draft(&root.public(), &dev.public(), 1).sign(&dev).unwrap();
    assert_eq!(verify(&pr, None).unwrap_err(), Error::Unauthorized);
}

#[test]
fn pointer_head_selection() {
    let root = key(1);
    let target = Address::of(b"t");
    let mk = |seq, created| {
        let p = Pointer { name: "home".into(), target, seq, prev: vec![] };
        let r = p.draft(&root.public(), &root.public(), created).sign(&root).unwrap();
        (r, p)
    };
    let a = mk(1, 10);
    let b = mk(2, 5);
    let c = mk(2, 7);
    let head = Pointer::head([(&a.0, &a.1), (&b.0, &b.1), (&c.0, &c.1)]).unwrap();
    assert_eq!(head.0, &c.0);
}

#[test]
fn rejects_weak_keys_and_bad_fields() {
    assert!(PublicKey::from_bytes(&[0u8; 32]).is_err());
    let root = key(1);
    let d = Draft {
        author: root.public(),
        signer: root.public(),
        kind: "Page".into(),
        created: 0,
        refs: vec![],
        body: Body::Inline(vec![]),
    };
    assert_eq!(d.sign(&root).unwrap_err(), Error::Field("kind"));
}
