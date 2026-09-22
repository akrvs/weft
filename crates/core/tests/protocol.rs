#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use std::str::FromStr;

use weft_core::address::Kind;
use weft_core::recovery::{self, Signature};
use weft_core::{
    Address, Body, Device, Draft, Error, Guardians, Manifest, Pointer, PublicKey, Recovery,
    SecretKey, verify,
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
        guardians: None,
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
    let m = Manifest {
        seq: 2,
        prev: None,
        devices: vec![],
        revoked: vec![dev.public()],
        guardians: None,
    };
    assert_eq!(verify(&page(&root, &dev, 1_500), Some(&m)).unwrap_err(), Error::Revoked);
    let bad = Manifest {
        seq: 3,
        prev: None,
        devices: vec![Device { key: dev.public(), label: "x".into(), created: 1, expires: None }],
        revoked: vec![dev.public()],
        guardians: None,
    };
    assert!(bad.check(&root.public()).is_err());
}

#[test]
fn manifest_must_be_root_signed() {
    let root = key(1);
    let dev = key(2);
    let m = Manifest { seq: 1, prev: None, devices: vec![], revoked: vec![], guardians: None };
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

fn guarded(root: &SecretKey, guardians: &[&SecretKey], threshold: usize) -> Manifest {
    let mut keys: Vec<PublicKey> = guardians.iter().map(|k| k.public()).collect();
    keys.sort_unstable();
    Manifest {
        seq: 1,
        prev: None,
        devices: vec![],
        revoked: vec![],
        guardians: Some(Guardians { keys, threshold }),
    }
    .draft(&root.public(), 1)
    .sign(root)
    .map(|r| Manifest::from_record(&r).unwrap())
    .unwrap()
}

fn recover(
    root: &SecretKey,
    to: &SecretKey,
    seq: u64,
    prev: Vec<Address>,
    signers: &[&SecretKey],
    created: u64,
) -> (weft_core::Record, Recovery) {
    let message = recovery::message(&root.public(), &to.public(), seq, &prev);
    let mut sigs: Vec<Signature> = signers
        .iter()
        .map(|k| Signature { key: k.public(), sig: k.sign_in(recovery::DOMAIN, &message) })
        .collect();
    sigs.sort_by_key(|s| s.key);
    let r = Recovery { to: to.public(), seq, prev, sigs };
    (r.draft(&root.public(), created).sign(to).unwrap(), r)
}

#[test]
fn recovery_needs_threshold_of_guardians() {
    let root = key(1);
    let to = key(2);
    let g = [key(5), key(6), key(7)];
    let m = guarded(&root, &[&g[0], &g[1], &g[2]], 2);
    let (ok, _) = recover(&root, &to, 1, vec![], &[&g[0], &g[2]], 10);
    let verified = verify(&ok, Some(&m)).unwrap();
    assert_eq!(verified.author, root.public().address());
    assert_eq!(verified.signer, to.public().address());
    let (one, _) = recover(&root, &to, 1, vec![], &[&g[1]], 10);
    assert_eq!(verify(&one, Some(&m)).unwrap_err(), Error::Threshold);
    assert_eq!(verify(&ok, None).unwrap_err(), Error::Unauthorized);
    let plain = Manifest { guardians: None, ..m.clone() };
    assert_eq!(verify(&ok, Some(&plain)).unwrap_err(), Error::Unauthorized);
    let (stranger, _) = recover(&root, &to, 1, vec![], &[&g[0], &key(9)], 10);
    assert_eq!(verify(&stranger, Some(&m)).unwrap_err(), Error::Unauthorized);
    let (wrong_seq, _) = recover(&root, &to, 1, vec![], &[&g[0], &g[1]], 10);
    let mut body = Recovery::from_record(&wrong_seq).unwrap();
    body.seq = 2;
    let resigned = body.draft(&root.public(), 10).sign(&to).unwrap();
    assert_eq!(verify(&resigned, Some(&m)).unwrap_err(), Error::Signature);
}

#[test]
fn recovery_is_never_grantable_and_signed_by_the_new_root() {
    assert!(weft_core::grant::RESERVED.contains(&recovery::KIND));
    let root = key(1);
    let to = key(2);
    let g = [key(5), key(6)];
    let m = guarded(&root, &[&g[0], &g[1]], 1);
    let (_, body) = recover(&root, &to, 1, vec![], &[&g[0]], 10);
    let mut d = body.draft(&root.public(), 10);
    d.signer = root.public();
    let by_root = d.sign(&root).unwrap();
    assert_eq!(verify(&by_root, Some(&m)).unwrap_err(), Error::Field("to"));
    let mut d = body.draft(&root.public(), 10);
    d.signer = g[1].public();
    let by_guardian = d.sign(&g[1]).unwrap();
    assert_eq!(verify(&by_guardian, Some(&m)).unwrap_err(), Error::Field("to"));
}

#[test]
fn recovery_head_selection() {
    let root = key(1);
    let g = [key(5), key(6)];
    let a = recover(&root, &key(2), 1, vec![], &[&g[0]], 10);
    let b = recover(&root, &key(3), 2, vec![a.0.address()], &[&g[1]], 5);
    let c = recover(&root, &key(4), 2, vec![a.0.address()], &[&g[0]], 7);
    let head = Recovery::head([(&a.0, &a.1), (&b.0, &b.1), (&c.0, &c.1)]).unwrap();
    assert_eq!(head.0, &c.0);
    assert_eq!(c.0.refs(), &[a.0.address()]);
}

#[test]
fn guardian_lists_are_checked() {
    let root = key(1);
    let g = |keys: Vec<PublicKey>, threshold| Manifest {
        seq: 1,
        prev: None,
        devices: vec![],
        revoked: vec![],
        guardians: Some(Guardians { keys, threshold }),
    };
    assert!(g(vec![key(5).public()], 1).check(&root.public()).is_ok());
    assert_eq!(g(vec![], 1).check(&root.public()), Err(Error::Limit("guardians")));
    assert_eq!(g(vec![key(5).public()], 0).check(&root.public()), Err(Error::Field("threshold")));
    assert_eq!(g(vec![key(5).public()], 2).check(&root.public()), Err(Error::Field("threshold")));
    assert_eq!(g(vec![root.public()], 1).check(&root.public()), Err(Error::Field("guardians")));
    let mut two = vec![key(5).public(), key(6).public()];
    two.sort_unstable();
    two.reverse();
    assert_eq!(g(two, 1).check(&root.public()), Err(Error::Field("guardians")));
    let m = g(vec![key(5).public()], 1);
    assert_eq!(Manifest::decode(&m.encode()).unwrap(), m);
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

#[test]
fn lists_edit_in_order() {
    use weft_core::{Label, Labels, Petnames};
    let a = key(1).public();
    let b = key(2).public();
    let mut names = Petnames::default();
    assert!(names.insert("zed", a).unwrap());
    assert!(names.insert("amy", b).unwrap());
    assert!(!names.insert("amy", a).unwrap());
    assert_eq!(names.key("amy"), Some(b));
    assert!(names.insert("Amy", a).is_err());
    assert!(names.insert("a.b", a).is_err());
    names.check().unwrap();
    assert_eq!(Petnames::decode(&names.encode()).unwrap(), names);
    assert!(names.remove("zed") && !names.remove("zed"));
    for i in 0..511 {
        names.insert(&format!("n{i}"), a).unwrap();
    }
    assert_eq!(names.insert("over", a), Err(Error::Limit("names")));

    let record = Address::of(b"r");
    let mut labels = Labels::default();
    assert!(labels.insert(Label { subject: record, value: "spam".into() }).unwrap());
    assert!(labels.insert(Label { subject: a.address(), value: "spam".into() }).unwrap());
    assert!(!labels.insert(Label { subject: record, value: "spam".into() }).unwrap());
    assert!(labels.insert(Label { subject: record, value: "no-go".into() }).is_err());
    assert_eq!(labels.labels[0].subject, a.address());
    assert_eq!(Labels::decode(&labels.encode()).unwrap(), labels);
    assert!(labels.remove(&Label { subject: record, value: "spam".into() }));
    assert_eq!(labels.labels.len(), 1);
}
