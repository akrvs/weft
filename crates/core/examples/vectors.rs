#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use serde_json::{Value, json};
use weft_core::{Address, Body, Device, Draft, Manifest, Pointer, Record, SecretKey, verify};

fn hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

fn entry(name: &str, record: &Record, manifest: Option<&Manifest>) -> Value {
    let error = verify(record, manifest).err().map(|e| e.to_string());
    json!({
        "name": name,
        "hex": hex(&record.to_bytes()),
        "address": record.address().to_string(),
        "manifest": manifest.is_some(),
        "error": error,
    })
}

fn write(name: &str, value: &Value) {
    let path = format!("{}/../../vectors/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let mut text = serde_json::to_string_pretty(value).unwrap();
    text.push('\n');
    std::fs::write(path, text).unwrap();
}

#[allow(clippy::too_many_lines)]
fn main() {
    let seeds: Vec<[u8; 32]> = (1u8..=4).map(|n| [n; 32]).collect();
    let keys: Vec<SecretKey> = seeds.iter().map(|s| SecretKey::from_seed(*s)).collect();
    write(
        "keys",
        &json!({ "keys": seeds.iter().zip(&keys).map(|(s, k)| json!({
            "seed": hex(s),
            "public": hex(k.public().bytes()),
            "address": k.public().address().to_string(),
        })).collect::<Vec<_>>() }),
    );

    let hash = Address::of(b"weft");
    let key_addr = keys[0].public().address();
    let mut wrong_check = key_addr.to_string();
    wrong_check.replace_range(59..60, if wrong_check.ends_with('a') { "b" } else { "a" });
    write(
        "addresses",
        &json!({
            "valid": [
                { "kind": "key", "payload": hex(key_addr.bytes()), "text": key_addr.to_string() },
                { "kind": "hash", "payload": hex(hash.bytes()), "text": hash.to_string() },
            ],
            "invalid": [
                { "text": wrong_check, "why": "checksum mismatch" },
                { "text": key_addr.to_string().to_uppercase(), "why": "uppercase" },
                { "text": &key_addr.to_string()[1..], "why": "wrong length" },
                { "text": "", "why": "empty" },
                { "text": "a".repeat(60), "why": "unknown version or bad checksum" },
            ]
        }),
    );

    write(
        "cbor",
        &json!({
            "canonical": [
                { "hex": "00", "why": "zero" },
                { "hex": "17", "why": "23 in one byte" },
                { "hex": "1818", "why": "24 needs two bytes" },
                { "hex": "190100", "why": "256" },
                { "hex": "1a00010000", "why": "65536" },
                { "hex": "1b0000000100000000", "why": "2^32" },
                { "hex": "40", "why": "empty bytes" },
                { "hex": "60", "why": "empty text" },
                { "hex": "80", "why": "empty array" },
                { "hex": "a0", "why": "empty map" },
                { "hex": "a26161016162820203", "why": "sorted keys, nested array" },
                { "hex": "a3616101616202626161 03".replace(' ', ""), "why": "shorter keys sort first" },
            ],
            "rejected": [
                { "hex": "1800", "why": "non-minimal one byte" },
                { "hex": "190001", "why": "non-minimal two byte" },
                { "hex": "1a00000001", "why": "non-minimal four byte" },
                { "hex": "1b0000000000000001", "why": "non-minimal eight byte" },
                { "hex": "5f4101ff", "why": "indefinite length bytes" },
                { "hex": "9fff", "why": "indefinite length array" },
                { "hex": "bfff", "why": "indefinite length map" },
                { "hex": "a2616201616102", "why": "keys out of order" },
                { "hex": "a2616101616102", "why": "duplicate key" },
                { "hex": "a2626161 03 616101".replace(' ', ""), "why": "longer key before shorter" },
                { "hex": "a10101", "why": "integer key" },
                { "hex": "20", "why": "negative integer" },
                { "hex": "f6", "why": "null" },
                { "hex": "f4", "why": "false" },
                { "hex": "fb3ff0000000000000", "why": "float" },
                { "hex": "c11a514b67b0", "why": "tag" },
                { "hex": "0000", "why": "trailing bytes" },
                { "hex": "61ff", "why": "invalid utf-8" },
                { "hex": "4201", "why": "truncated bytes" },
                { "hex": "8181818181818181818100", "why": "nesting deeper than 8" },
            ]
        }),
    );

    let root = &keys[0];
    let device = &keys[1];
    let stranger = &keys[2];
    let manifest = Manifest {
        seq: 1,
        prev: None,
        devices: vec![Device {
            key: device.public(),
            label: "laptop".into(),
            created: 1_756_000_000,
            expires: Some(1_788_000_000),
        }],
        revoked: vec![stranger.public()],
    };
    let manifest_record = manifest.draft(&root.public(), 1_756_000_000).sign(root).unwrap();
    let page = |signer: &SecretKey, created: u64| {
        Draft {
            author: root.public(),
            signer: signer.public(),
            kind: "page".into(),
            created,
            refs: vec![manifest_record.address()],
            body: Body::Inline(b"<h1>weft</h1>".to_vec()),
        }
        .sign(signer)
        .unwrap()
    };
    let by_device = page(device, 1_760_000_000);
    let blob = Draft {
        author: root.public(),
        signer: root.public(),
        kind: "file".into(),
        created: 1_760_000_001,
        refs: vec![],
        body: Body::Blob(Address::of(b"a large blob")),
    }
    .sign(root)
    .unwrap();
    let home = Pointer { name: "home".into(), target: by_device.address(), seq: 1, prev: vec![] };
    let home_record =
        home.draft(&root.public(), &device.public(), 1_760_000_002).sign(device).unwrap();
    let home2 = Pointer {
        name: "home".into(),
        target: blob.address(),
        seq: 2,
        prev: vec![home_record.address()],
    };
    let second = home2.draft(&root.public(), &root.public(), 1_760_000_003).sign(root).unwrap();
    let mpointer = Pointer {
        name: "manifest".into(),
        target: manifest_record.address(),
        seq: 1,
        prev: vec![],
    };
    let mpointer_root =
        mpointer.draft(&root.public(), &root.public(), 1_756_000_001).sign(root).unwrap();
    let mpointer_device =
        mpointer.draft(&root.public(), &device.public(), 1_756_000_001).sign(device).unwrap();
    let mut tampered = by_device.to_bytes();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let tampered = Record::from_bytes(&tampered).unwrap();

    write(
        "records",
        &json!({
            "root_seed": hex(&seeds[0]),
            "device_seed": hex(&seeds[1]),
            "manifest": { "hex": hex(&manifest_record.to_bytes()), "address": manifest_record.address().to_string() },
            "records": [
                entry("manifest self-signed", &manifest_record, None),
                entry("page by root without manifest", &page(root, 1_760_000_000), None),
                entry("page by device with manifest", &by_device, Some(&manifest)),
                entry("page by device without manifest", &by_device, None),
                entry("page by device before device created", &page(device, 1_755_000_000), Some(&manifest)),
                entry("page by device after device expiry", &page(device, 1_788_000_000), Some(&manifest)),
                entry("page by revoked key", &page(stranger, 1_760_000_000), Some(&manifest)),
                entry("page by unknown key", &page(&keys[3], 1_760_000_000), Some(&manifest)),
                entry("blob reference by root", &blob, None),
                entry("pointer home by device", &home_record, Some(&manifest)),
                entry("pointer home seq 2 by root", &second, None),
                entry("pointer manifest by root", &mpointer_root, None),
                entry("pointer manifest by device", &mpointer_device, Some(&manifest)),
                entry("tampered signature", &tampered, Some(&manifest)),
            ]
        }),
    );
}
