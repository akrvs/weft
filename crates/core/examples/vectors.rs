#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use serde_json::{Value, json};
use weft_core::cbor::Value as Cbor;
use weft_core::{
    Access, Address, Body, Device, Draft, Grant, Manifest, Pointer, Receipt, Record, Revoke,
    SecretKey, Voucher, verify,
};

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
    let seeds: Vec<[u8; 32]> = (1u8..=7).map(|n| [n; 32]).collect();
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

    let app = &keys[3];
    let grant = |kinds: &[&str], access: Access, expires: Option<u64>| Grant {
        app: app.public(),
        kinds: kinds.iter().map(|k| (*k).to_owned()).collect(),
        access,
        expires,
    };
    let at = 1_760_000_010;
    let good = grant(&["note", "page"], Access::ReadWrite, Some(1_770_000_000));
    let good_record = good.draft(&root.public(), &device.public(), at).sign(device).unwrap();
    let raw_grant = |body: Cbor, signer: &SecretKey| {
        Draft {
            author: root.public(),
            signer: signer.public(),
            kind: "grant".into(),
            created: at,
            refs: vec![],
            body: Body::Inline(body.encode()),
        }
        .sign(signer)
        .unwrap()
    };
    let bad_access = raw_grant(
        Cbor::Map(vec![
            ("access".into(), Cbor::Uint(4)),
            ("app".into(), Cbor::Bytes(app.public().bytes().to_vec())),
            ("kinds".into(), Cbor::Array(vec![Cbor::Text("note".into())])),
        ]),
        root,
    );
    let unknown_field = raw_grant(
        Cbor::Map(vec![
            ("access".into(), Cbor::Uint(1)),
            ("app".into(), Cbor::Bytes(app.public().bytes().to_vec())),
            ("kinds".into(), Cbor::Array(vec![Cbor::Text("note".into())])),
            ("scope".into(), Cbor::Text("all".into())),
        ]),
        root,
    );
    let too_many: Vec<String> = (0..17).map(|i| format!("k{i:02}")).collect();
    let too_many =
        Grant { app: app.public(), kinds: too_many, access: Access::Read, expires: None };
    let signed = |g: &Grant, signer: &SecretKey| {
        g.draft(&root.public(), &signer.public(), at).sign(signer).unwrap()
    };
    let revoke = Revoke { grant: good_record.address() };
    let revoke_record =
        revoke.draft(&root.public(), &device.public(), at + 1).sign(device).unwrap();
    let revoke_no_ref = Draft {
        author: root.public(),
        signer: root.public(),
        kind: "revoke".into(),
        created: at + 1,
        refs: vec![],
        body: Body::Inline(revoke.encode()),
    }
    .sign(root)
    .unwrap();
    write(
        "grants",
        &json!({
            "records": [
                entry("grant read write by device", &good_record, Some(&manifest)),
                entry("grant read by root", &signed(&grant(&["note"], Access::Read, None), root), None),
                entry("grant by device without manifest", &good_record, None),
                entry("grant by revoked key", &signed(&good, stranger), Some(&manifest)),
                entry("grant expires before created", &signed(&grant(&["note"], Access::Read, Some(at)), root), None),
                entry("grant reserved kind", &signed(&grant(&["pointer"], Access::Read, None), root), None),
                entry("grant invalid kind", &signed(&grant(&["Note"], Access::Read, None), root), None),
                entry("grant unsorted kinds", &signed(&grant(&["page", "note"], Access::Read, None), root), None),
                entry("grant duplicate kinds", &signed(&grant(&["note", "note"], Access::Read, None), root), None),
                entry("grant no kinds", &signed(&grant(&[], Access::Read, None), root), None),
                entry("grant too many kinds", &signed(&too_many, root), None),
                entry("grant bad access", &bad_access, None),
                entry("grant unknown field", &unknown_field, None),
                entry("revoke by device", &revoke_record, Some(&manifest)),
                entry("revoke by revoked key", &revoke.draft(&root.public(), &stranger.public(), at + 1).sign(stranger).unwrap(), Some(&manifest)),
                entry("revoke without ref", &revoke_no_ref, None),
            ]
        }),
    );

    let bank = &keys[4];
    let relay = &keys[5];
    let voucher = Voucher::mint(bank, relay.public(), 5, [7; 32]).unwrap();
    let mut records = vec![by_device.address(), blob.address()];
    records.sort();
    let receipt =
        Receipt { relay: relay.public(), records, until: at + 86_400, voucher: voucher.clone() };
    let receipt_record = receipt.draft(&root.public(), &device.public(), at).sign(device).unwrap();
    let wrong_relay = Receipt { relay: keys[6].public(), ..receipt.clone() };
    let raw_receipt = |body: Cbor, refs: Vec<Address>| {
        Draft {
            author: root.public(),
            signer: root.public(),
            kind: "receipt".into(),
            created: at,
            refs,
            body: Body::Inline(body.encode()),
        }
        .sign(root)
        .unwrap()
    };
    let forged = Voucher { cents: 500, ..voucher.clone() };
    let mut tampered_voucher = voucher.encode();
    let last = tampered_voucher.len() - 1;
    tampered_voucher[last] ^= 0x01;
    write(
        "receipts",
        &json!({
            "bank_seed": hex(&seeds[4]),
            "relay_seed": hex(&seeds[5]),
            "vouchers": [
                { "name": "five cents", "hex": hex(&voucher.encode()), "id": voucher.id().to_string(), "cents": 5 },
                { "name": "forged cents", "hex": hex(&forged.encode()), "error": "signature invalid" },
                { "name": "tampered signature", "hex": hex(&tampered_voucher), "error": "signature invalid" },
            ],
            "records": [
                entry("receipt by device", &receipt_record, Some(&manifest)),
                entry("receipt by root", &receipt.draft(&root.public(), &root.public(), at).sign(root).unwrap(), None),
                entry("receipt by device without manifest", &receipt_record, None),
                entry("receipt wrong relay", &wrong_relay.draft(&root.public(), &root.public(), at).sign(root).unwrap(), None),
                entry("receipt until not after created", &Receipt { until: at, ..receipt.clone() }.draft(&root.public(), &root.public(), at).sign(root).unwrap(), None),
                entry("receipt without refs", &raw_receipt(weft_core::cbor::decode(&receipt.encode()).unwrap(), vec![]), None),
                entry("receipt no records", &raw_receipt(Cbor::Map(vec![
                    ("records".into(), Cbor::Array(vec![])),
                    ("relay".into(), Cbor::Bytes(relay.public().bytes().to_vec())),
                    ("until".into(), Cbor::Uint(at + 1)),
                    ("voucher".into(), Cbor::Bytes(voucher.encode())),
                ]), vec![]), None),
                entry("receipt forged voucher", &Receipt { voucher: forged, ..receipt.clone() }.draft(&root.public(), &root.public(), at).sign(root).unwrap(), None),
                entry("receipt unknown field", &raw_receipt(Cbor::Map(vec![
                    ("records".into(), Cbor::Array(vec![Cbor::Bytes(by_device.address().bytes().to_vec())])),
                    ("relay".into(), Cbor::Bytes(relay.public().bytes().to_vec())),
                    ("tip".into(), Cbor::Uint(1)),
                    ("until".into(), Cbor::Uint(at + 1)),
                    ("voucher".into(), Cbor::Bytes(voucher.encode())),
                ]), vec![by_device.address()]), None),
            ]
        }),
    );
}
