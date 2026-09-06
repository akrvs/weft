#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use weft_core::cbor::Value;
use weft_core::{Address, Body, Draft, Error, Receipt, SecretKey, Voucher, verify};

fn key(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

fn voucher(cents: u64) -> Voucher {
    Voucher::mint(&key(9), key(7).public(), cents, [1; 32]).unwrap()
}

fn receipt(records: Vec<Address>, until: u64) -> Receipt {
    Receipt { relay: key(7).public(), records, until, voucher: voucher(5) }
}

fn signed(receipt: &Receipt, created: u64) -> weft_core::Record {
    let root = key(1);
    receipt.draft(&root.public(), &root.public(), created).sign(&root).unwrap()
}

#[test]
fn voucher_roundtrip_and_id() {
    let v = voucher(5);
    let bytes = v.encode();
    assert!(bytes.len() <= weft_core::receipt::MAX_VOUCHER);
    let back = Voucher::decode(&bytes).unwrap();
    assert_eq!(back, v);
    assert_eq!(back.id(), Address::of(&bytes));
}

#[test]
fn voucher_rejects_tampering_zero_and_unknown_fields() {
    let v = voucher(5);
    let mut bytes = v.encode();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(Voucher::decode(&bytes), Err(Error::Signature));
    assert_eq!(Voucher::mint(&key(9), key(7).public(), 0, [1; 32]), Err(Error::Field("cents")));
    let forged = Voucher { cents: 500, ..v.clone() };
    assert_eq!(Voucher::decode(&forged.encode()), Err(Error::Signature));
    let mut m = vec![
        ("bank".to_owned(), Value::Bytes(v.bank.bytes().to_vec())),
        ("cents".to_owned(), Value::Uint(5)),
        ("memo".to_owned(), Value::Text("hi".into())),
        ("nonce".to_owned(), Value::Bytes(vec![1; 32])),
        ("sig".to_owned(), Value::Bytes(v.sig.to_vec())),
        ("to".to_owned(), Value::Bytes(v.to.bytes().to_vec())),
    ];
    assert_eq!(
        Voucher::decode(&Value::Map(m.clone()).encode()),
        Err(Error::Encoding("unknown field"))
    );
    m.remove(2);
    m[1].1 = Value::Uint(0);
    assert_eq!(Voucher::decode(&Value::Map(m).encode()), Err(Error::Field("cents")));
    assert_eq!(Voucher::decode(&[0; 257]), Err(Error::Limit("voucher")));
}

#[test]
fn receipt_roundtrip_and_verify() {
    let a = Address::of(b"a");
    let b = Address::of(b"b");
    let mut records = vec![a, b];
    records.sort();
    let r = receipt(records, 2_000);
    let record = signed(&r, 1_000);
    assert_eq!(Receipt::from_record(&record).unwrap(), r);
    assert_eq!(Receipt::decode(&r.encode()).unwrap(), r);
    let verified = verify(&record, None).unwrap();
    assert_eq!(verified.kind, "receipt");
}

#[test]
fn receipt_rejects_bad_shapes() {
    let a = Address::of(b"a");
    let b = Address::of(b"b");
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    assert_eq!(receipt(vec![], 2_000).check(), Err(Error::Limit("records")));
    let many: Vec<_> = (0..65u8).map(|i| Address::of(&[i])).collect();
    assert_eq!(receipt(many, 2_000).check(), Err(Error::Limit("records")));
    assert_eq!(receipt(vec![hi, lo], 2_000).check(), Err(Error::Field("records")));
    assert_eq!(receipt(vec![lo, lo], 2_000).check(), Err(Error::Field("records")));
    assert_eq!(
        receipt(vec![key(3).public().address()], 2_000).check(),
        Err(Error::Field("records"))
    );
    let wrong_relay = Receipt { relay: key(8).public(), ..receipt(vec![lo], 2_000) };
    assert_eq!(wrong_relay.check(), Err(Error::Field("relay")));
    assert_eq!(Receipt::decode(&wrong_relay.encode()), Err(Error::Field("relay")));
    let past = signed(&receipt(vec![lo], 1_000), 1_000);
    assert_eq!(Receipt::from_record(&past), Err(Error::Field("until")));
    assert_eq!(verify(&past, None), Err(Error::Field("until")));
    let root = key(1);
    let no_ref = Draft {
        author: root.public(),
        signer: root.public(),
        kind: "receipt".into(),
        created: 1_000,
        refs: vec![],
        body: Body::Inline(receipt(vec![lo], 2_000).encode()),
    }
    .sign(&root)
    .unwrap();
    assert_eq!(verify(&no_ref, None), Err(Error::Field("refs")));
    let forged =
        Receipt { voucher: Voucher { cents: 999, ..voucher(5) }, ..receipt(vec![lo], 2_000) };
    assert_eq!(verify(&signed(&forged, 1_000), None), Err(Error::Signature));
}

#[test]
fn receipt_is_reserved() {
    assert!(weft_core::grant::RESERVED.contains(&"receipt"));
}
