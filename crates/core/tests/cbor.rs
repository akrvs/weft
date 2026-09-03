#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use weft_core::cbor::{Value, decode};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn roundtrip_sorts_and_dedups_keys() {
    let v = Value::Map(vec![
        ("zz".into(), Value::Uint(1)),
        ("a".into(), Value::Bytes(vec![1, 2])),
        ("b".into(), Value::Array(vec![Value::Text("x".into())])),
        ("a".into(), Value::Uint(9)),
    ]);
    let bytes = v.encode();
    let back = decode(&bytes).unwrap();
    assert_eq!(back.encode(), bytes);
    let m = back.as_map().unwrap();
    assert_eq!(m.len(), 3);
    assert_eq!(m[0].0, "a");
    assert_eq!(m[1].0, "b");
    assert_eq!(m[2].0, "zz");
}

#[test]
fn integers_take_shortest_form() {
    for (n, expect) in [
        (0u64, "00"),
        (23, "17"),
        (24, "1818"),
        (255, "18ff"),
        (256, "190100"),
        (65535, "19ffff"),
        (65536, "1a00010000"),
        (u64::from(u32::MAX), "1affffffff"),
        (u64::from(u32::MAX) + 1, "1b0000000100000000"),
    ] {
        assert_eq!(Value::Uint(n).encode(), hex(expect), "{n}");
        assert_eq!(decode(&hex(expect)).unwrap(), Value::Uint(n));
    }
}

#[test]
fn rejects_non_canonical_input() {
    for (h, why) in [
        ("1800", "non-minimal 1 byte"),
        ("190001", "non-minimal 2 byte"),
        ("1a00000001", "non-minimal 4 byte"),
        ("1b0000000000000001", "non-minimal 8 byte"),
        ("5f4101ff", "indefinite bytes"),
        ("9fff", "indefinite array"),
        ("a26162016161 02", "unsorted keys"),
        ("a2616101616102", "duplicate keys"),
        ("a10101", "non-text key"),
        ("20", "negative int"),
        ("f6", "null"),
        ("f5", "bool"),
        ("fb3ff0000000000000", "float"),
        ("c0", "tag"),
        ("0000", "trailing"),
        ("61ff", "invalid utf-8"),
        ("42", "truncated"),
        ("8181818181818181818100", "too deep"),
    ] {
        let h: String = h.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(decode(&hex(&h)).is_err(), "{why}");
    }
}
