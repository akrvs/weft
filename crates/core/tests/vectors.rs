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

#[test]
fn records() {
    let v = load("records");
    let manifest_bytes = hex(v["manifest"]["hex"].as_str().unwrap());
    let manifest_record = Record::from_bytes(&manifest_bytes).unwrap();
    assert_eq!(manifest_record.address().to_string(), v["manifest"]["address"].as_str().unwrap());
    let manifest = Manifest::from_record(&manifest_record).unwrap();
    for r in v["records"].as_array().unwrap() {
        let name = r["name"].as_str().unwrap();
        let bytes = hex(r["hex"].as_str().unwrap());
        let record = Record::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(record.to_bytes(), bytes, "{name}");
        assert_eq!(record.address().to_string(), r["address"].as_str().unwrap(), "{name}");
        let with_manifest = r["manifest"].as_bool().unwrap();
        let result = verify(&record, with_manifest.then_some(&manifest));
        match r["error"].as_str() {
            None => assert!(result.is_ok(), "{name}: {result:?}"),
            Some(e) => assert_eq!(result.unwrap_err().to_string(), e, "{name}"),
        }
    }
}
