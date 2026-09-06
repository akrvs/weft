#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use std::str::FromStr;

use serde_json::Value;
use weft_core::{Address, Manifest, Record, SecretKey, verify};

fn load(name: &str) -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/");
    serde_json::from_str(&std::fs::read_to_string(format!("{path}{name}.json")).unwrap()).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn to_hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

#[test]
fn keys() {
    for v in load("keys")["keys"].as_array().unwrap() {
        let seed: [u8; 32] = hex(v["seed"].as_str().unwrap()).try_into().unwrap();
        let k = SecretKey::from_seed(seed);
        assert_eq!(to_hex(k.public().bytes()), v["public"].as_str().unwrap());
        assert_eq!(k.public().address().to_string(), v["address"].as_str().unwrap());
    }
}

#[test]
fn addresses() {
    let v = load("addresses");
    for a in v["valid"].as_array().unwrap() {
        let addr = Address::from_str(a["text"].as_str().unwrap()).unwrap();
        assert_eq!(to_hex(addr.bytes()), a["payload"].as_str().unwrap());
        assert_eq!(addr.to_string(), a["text"].as_str().unwrap());
    }
    for a in v["invalid"].as_array().unwrap() {
        assert!(Address::from_str(a["text"].as_str().unwrap()).is_err(), "{}", a["why"]);
    }
}

#[test]
fn cbor() {
    let v = load("cbor");
    for c in v["canonical"].as_array().unwrap() {
        let bytes = hex(c["hex"].as_str().unwrap());
        assert_eq!(weft_core::cbor::decode(&bytes).unwrap().encode(), bytes);
    }
    for c in v["rejected"].as_array().unwrap() {
        assert!(weft_core::cbor::decode(&hex(c["hex"].as_str().unwrap())).is_err(), "{}", c["why"]);
    }
}

fn manifest() -> Manifest {
    let v = load("records");
    let manifest_record = Record::from_bytes(&hex(v["manifest"]["hex"].as_str().unwrap())).unwrap();
    assert_eq!(manifest_record.address().to_string(), v["manifest"]["address"].as_str().unwrap());
    Manifest::from_record(&manifest_record).unwrap()
}

#[test]
fn records() {
    check_records(&load("records"), &manifest());
}

#[test]
fn grants() {
    let v = load("grants");
    check_records(&v, &manifest());
    let first = Record::from_bytes(&hex(v["records"][0]["hex"].as_str().unwrap())).unwrap();
    let grant = weft_core::Grant::from_record(&first).unwrap();
    assert!(grant.covers("note") && grant.covers("page") && !grant.covers("photo"));
    assert!(grant.access.reads() && grant.access.writes());
    assert!(grant.active(1_769_999_999) && !grant.active(1_770_000_000));
    let revoke = Record::from_bytes(&hex(v["records"][13]["hex"].as_str().unwrap())).unwrap();
    assert_eq!(weft_core::Revoke::from_record(&revoke).unwrap().grant, first.address());
}

#[test]
fn receipts() {
    let v = load("receipts");
    check_records(&v, &manifest());
    for r in v["vouchers"].as_array().unwrap() {
        let name = r["name"].as_str().unwrap();
        let bytes = hex(r["hex"].as_str().unwrap());
        match (weft_core::Voucher::decode(&bytes), r["error"].as_str()) {
            (Ok(voucher), None) => {
                assert_eq!(voucher.encode(), bytes, "{name}");
                assert_eq!(voucher.id().to_string(), r["id"].as_str().unwrap(), "{name}");
                assert_eq!(voucher.cents, r["cents"].as_u64().unwrap(), "{name}");
            }
            (Err(e), Some(expected)) => assert_eq!(e.to_string(), expected, "{name}"),
            (result, _) => panic!("{name}: {result:?}"),
        }
    }
    let first = Record::from_bytes(&hex(v["records"][0]["hex"].as_str().unwrap())).unwrap();
    let receipt = weft_core::Receipt::from_record(&first).unwrap();
    assert_eq!(receipt.records.len(), 2);
    assert_eq!(receipt.voucher.cents, 5);
}

fn check_records(v: &Value, manifest: &Manifest) {
    for r in v["records"].as_array().unwrap() {
        let name = r["name"].as_str().unwrap();
        let bytes = hex(r["hex"].as_str().unwrap());
        let record = Record::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(record.to_bytes(), bytes, "{name}");
        assert_eq!(record.address().to_string(), r["address"].as_str().unwrap(), "{name}");
        let with_manifest = r["manifest"].as_bool().unwrap();
        let result = verify(&record, with_manifest.then_some(manifest));
        match r["error"].as_str() {
            None => assert!(result.is_ok(), "{name}: {result:?}"),
            Some(e) => assert_eq!(result.unwrap_err().to_string(), e, "{name}"),
        }
    }
}

#[test]
fn login() {
    use weft_core::{Challenge, Device, Proof};
    let v = load("login");
    check_records(&v, &manifest());
    let c = &v["challenge"];
    let challenge = Challenge::from_text(c["text"].as_str().unwrap()).unwrap();
    assert_eq!(challenge.service, c["service"].as_str().unwrap());
    assert_eq!(to_hex(&challenge.nonce), c["nonce"].as_str().unwrap());
    assert_eq!(challenge.expires, c["expires"].as_u64().unwrap());
    assert_eq!(challenge.to_text(), c["text"].as_str().unwrap());
    for b in v["bad_challenges"].as_array().unwrap() {
        assert!(Challenge::from_text(b["text"].as_str().unwrap()).is_err(), "{}", b["why"]);
    }
    for p in v["proofs"].as_array().unwrap() {
        let name = p["name"].as_str().unwrap();
        let proof = Proof::from_text(p["text"].as_str().unwrap()).unwrap();
        assert_eq!(proof.to_text(), p["text"].as_str().unwrap(), "{name}");
        let result = proof.verify(p["service"].as_str().unwrap(), p["now"].as_u64().unwrap(), None);
        match p["error"].as_str() {
            None => assert_eq!(
                result.unwrap().author.address().to_string(),
                p["author"].as_str().unwrap(),
                "{name}"
            ),
            Some(e) => assert_eq!(result.unwrap_err().to_string(), e, "{name}"),
        }
    }
    let good = v["proofs"].as_array().unwrap()[0].clone();
    let proof = Proof::from_text(good["text"].as_str().unwrap()).unwrap();
    let service = good["service"].as_str().unwrap();
    let now = good["now"].as_u64().unwrap();
    let mut newer = manifest();
    newer.seq = 2;
    newer.revoked.push(*proof.login.signer());
    newer.revoked.sort_unstable();
    newer.devices.retain(|d| &d.key != proof.login.signer());
    assert!(proof.verify(service, now, Some(&newer)).is_err());
    let older = Manifest {
        seq: 0,
        devices: vec![Device {
            key: SecretKey::from_seed([9u8; 32]).public(),
            label: "x".into(),
            created: 0,
            expires: None,
        }],
        ..manifest()
    };
    assert!(proof.verify(service, now, Some(&older)).is_ok());
}
