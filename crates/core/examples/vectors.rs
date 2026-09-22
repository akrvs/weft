#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::missing_panics_doc)]

use serde_json::{Value, json};
use weft_core::cbor::Value as Cbor;
use weft_core::recovery::{self, Signature};
use weft_core::{
    Access, Address, Body, Challenge, Device, Draft, Grant, Guardians, Manifest, Payment, Pointer,
    Proof, Receipt, Record, Recovery, Revoke, SecretKey, Voucher, verify,
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
        guardians: None,
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
    let receipt = Receipt {
        relay: relay.public(),
        records,
        until: at + 86_400,
        payment: Payment::Voucher(Box::new(voucher.clone())),
    };
    let preimage = [9u8; 32];
    let by_preimage = Receipt { payment: Payment::Preimage(preimage), ..receipt.clone() };
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
            "preimage": { "hex": hex(&preimage), "hash": hex(&weft_core::receipt::payment_hash(&preimage)), "id": by_preimage.payment.id().to_string() },
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
                entry("receipt forged voucher", &Receipt { payment: Payment::Voucher(Box::new(forged)), ..receipt.clone() }.draft(&root.public(), &root.public(), at).sign(root).unwrap(), None),
                entry("receipt by preimage", &by_preimage.draft(&root.public(), &device.public(), at).sign(device).unwrap(), Some(&manifest)),
                entry("receipt both payments", &raw_receipt(Cbor::Map(vec![
                    ("preimage".into(), Cbor::Bytes(preimage.to_vec())),
                    ("records".into(), Cbor::Array(vec![Cbor::Bytes(by_device.address().bytes().to_vec())])),
                    ("relay".into(), Cbor::Bytes(relay.public().bytes().to_vec())),
                    ("until".into(), Cbor::Uint(at + 1)),
                    ("voucher".into(), Cbor::Bytes(voucher.encode())),
                ]), vec![by_device.address()]), None),
                entry("receipt no payment", &raw_receipt(Cbor::Map(vec![
                    ("records".into(), Cbor::Array(vec![Cbor::Bytes(by_device.address().bytes().to_vec())])),
                    ("relay".into(), Cbor::Bytes(relay.public().bytes().to_vec())),
                    ("until".into(), Cbor::Uint(at + 1)),
                ]), vec![by_device.address()]), None),
                entry("receipt short preimage", &raw_receipt(Cbor::Map(vec![
                    ("preimage".into(), Cbor::Bytes(vec![9; 31])),
                    ("records".into(), Cbor::Array(vec![Cbor::Bytes(by_device.address().bytes().to_vec())])),
                    ("relay".into(), Cbor::Bytes(relay.public().bytes().to_vec())),
                    ("until".into(), Cbor::Uint(at + 1)),
                ]), vec![by_device.address()]), None),
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

    let service = "http://127.0.0.1:8080";
    let challenge = Challenge { service: service.into(), nonce: [7u8; 32], expires: at + 300 };
    let login = |c: &Challenge, signer: &SecretKey, created: u64| {
        c.draft(&root.public(), &signer.public(), created).sign(signer).unwrap()
    };
    let raw_login = |body: Cbor, refs: Vec<Address>| {
        Draft {
            author: root.public(),
            signer: root.public(),
            kind: "login".into(),
            created: at,
            refs,
            body: Body::Inline(body.encode()),
        }
        .sign(root)
        .unwrap()
    };
    let login_map = |service: &str, nonce: &[u8], extra: Option<(&str, Cbor)>| {
        let mut m = vec![
            ("expires".to_owned(), Cbor::Uint(at + 300)),
            ("nonce".to_owned(), Cbor::Bytes(nonce.to_vec())),
            ("service".to_owned(), Cbor::Text(service.into())),
        ];
        if let Some((k, v)) = extra {
            m.push((k.to_owned(), v));
        }
        Cbor::Map(m)
    };
    let by_device = login(&challenge, device, at);
    let by_root = login(&challenge, root, at);
    let proof = |login: &Record, manifest: Option<&Record>| Proof {
        login: login.clone(),
        manifest: manifest.cloned(),
    };
    let other_manifest =
        Manifest { seq: 1, prev: None, devices: vec![], revoked: vec![], guardians: None }
            .draft(&keys[3].public(), at)
            .sign(&keys[3])
            .unwrap();
    let proof_entry = |name: &str, p: &Proof, service: &str, now: u64| {
        let result = p.verify(service, now, None);
        json!({
            "name": name,
            "text": p.to_text(),
            "service": service,
            "now": now,
            "author": result.as_ref().ok().map(|l| l.author.address().to_string()),
            "error": result.err().map(|e| e.to_string()),
        })
    };
    write(
        "login",
        &json!({
            "challenge": {
                "text": challenge.to_text(),
                "service": service,
                "nonce": hex(&challenge.nonce),
                "expires": challenge.expires,
            },
            "bad_challenges": [
                { "text": "", "why": "empty" },
                { "text": "!!!!", "why": "not base64url" },
                { "text": weft_core::login::to_text(&login_map("HTTP://x", &[7u8; 32], None).encode()), "why": "uppercase service" },
                { "text": weft_core::login::to_text(&login_map("", &[7u8; 32], None).encode()), "why": "empty service" },
                { "text": weft_core::login::to_text(&login_map("http://x", &[7u8; 31], None).encode()), "why": "short nonce" },
                { "text": weft_core::login::to_text(&login_map("http://x", &[7u8; 32], Some(("return", Cbor::Text("/".into())))).encode()), "why": "unknown field" },
            ],
            "records": [
                entry("login by device with manifest", &by_device, Some(&manifest)),
                entry("login by root without manifest", &by_root, None),
                entry("login by device without manifest", &by_device, None),
                entry("login by revoked key", &login(&challenge, stranger, at), Some(&manifest)),
                entry("login expires before created", &login(&challenge, root, at + 300), None),
                entry("login with refs", &raw_login(login_map(service, &[7u8; 32], None), vec![manifest_record.address()]), None),
                entry("login uppercase service", &raw_login(login_map("HTTP://x", &[7u8; 32], None), vec![]), None),
                entry("login service with space", &raw_login(login_map("http://x y", &[7u8; 32], None), vec![]), None),
                entry("login service too long", &raw_login(login_map(&"a".repeat(254), &[7u8; 32], None), vec![]), None),
                entry("login short nonce", &raw_login(login_map(service, &[7u8; 31], None), vec![]), None),
                entry("login unknown field", &raw_login(login_map(service, &[7u8; 32], Some(("return", Cbor::Text("/".into())))), vec![]), None),
            ],
            "proofs": [
                proof_entry("device proof with manifest", &proof(&by_device, Some(&manifest_record)), service, at + 1),
                proof_entry("root proof without manifest", &proof(&by_root, None), service, at + 1),
                proof_entry("root proof with manifest", &proof(&by_root, Some(&manifest_record)), service, at + 1),
                proof_entry("device proof without manifest", &proof(&by_device, None), service, at + 1),
                proof_entry("device proof with another author's manifest", &proof(&by_device, Some(&other_manifest)), service, at + 1),
                proof_entry("device proof with a page as manifest", &proof(&by_device, Some(&page(root, at))), service, at + 1),
                proof_entry("wrong service", &proof(&by_device, Some(&manifest_record)), "http://127.0.0.1:8081", at + 1),
                proof_entry("expired", &proof(&by_device, Some(&manifest_record)), service, at + 300),
                proof_entry("not a login record", &proof(&page(root, at), None), service, at + 1),
            ]
        }),
    );

    let guardians: Vec<&SecretKey> = {
        let mut g = vec![&keys[4], &keys[5], &keys[6]];
        g.sort_by_key(|k| k.public());
        g
    };
    let new_root = &keys[3];
    let guarded = Manifest {
        seq: 2,
        prev: Some(manifest_record.address()),
        guardians: Some(Guardians {
            keys: guardians.iter().map(|k| k.public()).collect(),
            threshold: 2,
        }),
        ..manifest.clone()
    };
    let guarded_record = guarded.draft(&root.public(), at).sign(root).unwrap();
    let recover = |to: &SecretKey, seq: u64, signers: &[&SecretKey], signer: &SecretKey| {
        let msg = recovery::message(&root.public(), &to.public(), seq, &[]);
        let mut sigs: Vec<Signature> = signers
            .iter()
            .map(|k| Signature { key: k.public(), sig: k.sign_in(recovery::DOMAIN, &msg) })
            .collect();
        sigs.sort_by_key(|s| s.key);
        let r = Recovery { to: to.public(), seq, prev: vec![], sigs };
        let mut d = r.draft(&root.public(), at + 10);
        d.signer = signer.public();
        d.sign(signer).unwrap()
    };
    let raw_recovery = |body: Cbor, signer: &SecretKey| {
        Draft {
            author: root.public(),
            signer: signer.public(),
            kind: "recovery".into(),
            created: at + 10,
            refs: vec![],
            body: Body::Inline(body.encode()),
        }
        .sign(signer)
        .unwrap()
    };
    let sig_map = |k: &SecretKey, msg: &[u8]| {
        Cbor::Map(vec![
            ("key".into(), Cbor::Bytes(k.public().bytes().to_vec())),
            ("sig".into(), Cbor::Bytes(k.sign_in(recovery::DOMAIN, msg).to_vec())),
        ])
    };
    let body_with = |to: &SecretKey, sigs: Vec<Cbor>| {
        Cbor::Map(vec![
            ("prev".into(), Cbor::Array(vec![])),
            ("seq".into(), Cbor::Uint(1)),
            ("sigs".into(), Cbor::Array(sigs)),
            ("to".into(), Cbor::Bytes(to.public().bytes().to_vec())),
        ])
    };
    let msg = recovery::message(&root.public(), &new_root.public(), 1, &[]);
    let valid = recover(new_root, 1, &guardians[..2], new_root);
    let mut tampered_body = Recovery::from_record(&valid).unwrap();
    tampered_body.sigs[0].sig[0] ^= 1;
    let tampered =
        raw_recovery(weft_core::cbor::decode(&tampered_body.encode()).unwrap(), new_root);
    let many: Vec<SecretKey> = (100u8..117).map(|n| SecretKey::from_seed([n; 32])).collect();
    let mut many_sigs: Vec<Cbor> = many.iter().map(|k| sig_map(k, &msg)).collect();
    many_sigs.sort_by_key(Cbor::encode);
    let entry_with = |name: &str, record: &Record, manifest: Option<&Manifest>| {
        let mut e = entry(name, record, manifest);
        e["manifest"] =
            json!(manifest.map(|m| if m.guardians.is_some() { "guarded" } else { "plain" }));
        e
    };
    write(
        "recovery",
        &json!({
            "root_seed": hex(&seeds[0]),
            "new_root_seed": hex(&seeds[3]),
            "guardian_seeds": [hex(&seeds[4]), hex(&seeds[5]), hex(&seeds[6])],
            "threshold": 2,
            "message": hex(&msg),
            "manifest": { "hex": hex(&guarded_record.to_bytes()), "address": guarded_record.address().to_string() },
            "records": [
                entry_with("guarded manifest self-signed", &guarded_record, None),
                entry_with("recovery at threshold", &valid, Some(&guarded)),
                entry_with("recovery by every guardian", &recover(new_root, 1, &guardians, new_root), Some(&guarded)),
                entry_with("recovery below threshold", &recover(new_root, 1, &guardians[..1], new_root), Some(&guarded)),
                entry_with("recovery without manifest", &valid, None),
                entry_with("recovery against a manifest without guardians", &valid, Some(&manifest)),
                entry_with("recovery with a stranger", &recover(new_root, 1, &[guardians[0], stranger], new_root), Some(&guarded)),
                entry_with("recovery signed by the old root", &recover(new_root, 1, &guardians[..2], root), Some(&guarded)),
                entry_with("recovery to the old root", &recover(root, 1, &guardians[..2], root), Some(&guarded)),
                entry_with("recovery to another key", &raw_recovery(body_with(device, vec![sig_map(guardians[0], &msg), sig_map(guardians[1], &msg)]), new_root), Some(&guarded)),
                entry_with("recovery with a tampered guardian signature", &tampered, Some(&guarded)),
                entry_with("recovery with a duplicate guardian", &raw_recovery(body_with(new_root, vec![sig_map(guardians[0], &msg), sig_map(guardians[0], &msg)]), new_root), Some(&guarded)),
                entry_with("recovery with unsorted guardians", &raw_recovery(body_with(new_root, vec![sig_map(guardians[1], &msg), sig_map(guardians[0], &msg)]), new_root), Some(&guarded)),
                entry_with("recovery with no signatures", &raw_recovery(body_with(new_root, vec![]), new_root), Some(&guarded)),
                entry_with("recovery with seventeen signatures", &raw_recovery(body_with(new_root, many_sigs), new_root), Some(&guarded)),
                entry_with("recovery with an unknown field", &raw_recovery(Cbor::Map(vec![("note".into(), Cbor::Text("x".into()))]), new_root), Some(&guarded)),
            ],
            "bad_manifests": [
                { "hex": hex(&Manifest { guardians: Some(Guardians { keys: vec![keys[6].public(), keys[4].public()], threshold: 1 }), ..guarded.clone() }.encode()), "why": "unsorted guardians" },
                { "hex": hex(&Manifest { guardians: Some(Guardians { keys: vec![root.public()], threshold: 1 }), ..guarded.clone() }.encode()), "why": "root as guardian" },
                { "hex": hex(&Manifest { guardians: Some(Guardians { keys: vec![keys[4].public()], threshold: 0 }), ..guarded.clone() }.encode()), "why": "zero threshold" },
                { "hex": hex(&Manifest { guardians: Some(Guardians { keys: vec![keys[4].public()], threshold: 2 }), ..guarded.clone() }.encode()), "why": "threshold above count" },
                { "hex": hex(&Manifest { guardians: Some(Guardians { keys: vec![], threshold: 1 }), ..guarded.clone() }.encode()), "why": "no guardians with a threshold" },
                { "hex": hex(&Manifest { guardians: Some(Guardians { keys: many.iter().map(SecretKey::public).collect::<std::collections::BTreeSet<_>>().into_iter().collect(), threshold: 1 }), ..guarded.clone() }.encode()), "why": "seventeen guardians" },
            ]
        }),
    );
    lists(&keys, &manifest);
    follows(&keys, &manifest);
}

#[allow(clippy::too_many_lines)]
fn lists(keys: &[SecretKey], manifest: &Manifest) {
    use weft_core::{Label, Labels, Petname, Petnames};
    let (root, device) = (&keys[0], &keys[1]);
    let at = 1_760_000_020;
    let raw = |kind: &str, body: Cbor| {
        Draft {
            author: root.public(),
            signer: device.public(),
            kind: kind.into(),
            created: at,
            refs: vec![],
            body: Body::Inline(body.encode()),
        }
        .sign(device)
        .unwrap()
    };
    let pet = |name: &str, k: &SecretKey| {
        Cbor::Map(vec![
            ("key".into(), Cbor::Bytes(k.public().bytes().to_vec())),
            ("name".into(), Cbor::Text(name.into())),
        ])
    };
    let names = |entries: Vec<Cbor>| Cbor::Map(vec![("names".into(), Cbor::Array(entries))]);
    let tag = |side: &str, bytes: &[u8], value: &str| {
        Cbor::Map(vec![
            (side.into(), Cbor::Bytes(bytes.to_vec())),
            ("value".into(), Cbor::Text(value.into())),
        ])
    };
    let labels = |entries: Vec<Cbor>| Cbor::Map(vec![("labels".into(), Cbor::Array(entries))]);
    let petnames = Petnames {
        names: vec![
            Petname { name: "alice".into(), key: keys[3].public() },
            Petname { name: "bob-2".into(), key: keys[4].public() },
        ],
    };
    let spam = Address::of(b"spam");
    let tags = Labels {
        labels: vec![
            Label { subject: keys[3].public().address(), value: "trusted".into() },
            Label { subject: spam, value: "nsfw".into() },
            Label { subject: spam, value: "spam".into() },
        ],
    };
    let k3 = keys[3].public();
    let k3 = k3.bytes();
    let many_names: Vec<Cbor> = (0..513).map(|i| pet(&format!("n{i:04}"), &keys[3])).collect();
    let mut many_labels: Vec<Cbor> =
        (0..513u32).map(|i| tag("record", Address::of(&i.to_le_bytes()).bytes(), "x")).collect();
    many_labels.sort_by_key(Cbor::encode);
    let signed = |d: Draft| d.sign(device).unwrap();
    let (r, d) = (root.public(), device.public());
    let m = Some(manifest);
    let sk = |k: &[u8], name: &str, extra: Option<(&str, &str)>| {
        let mut v =
            vec![("key".into(), Cbor::Bytes(k.to_vec())), ("name".into(), Cbor::Text(name.into()))];
        v.extend(extra.map(|(a, b)| (a.into(), Cbor::Text(b.into()))));
        Cbor::Map(v)
    };
    write(
        "lists",
        &json!({
            "records": [
                entry("petnames", &signed(petnames.draft(&r, &d, at)), m),
                entry("empty petnames", &signed(Petnames::default().draft(&r, &d, at)), m),
                entry("labels", &signed(tags.draft(&r, &d, at)), m),
                entry("empty labels", &signed(Labels::default().draft(&r, &d, at)), m),
                entry("petnames without manifest", &signed(petnames.draft(&r, &d, at)), None),
                entry("petnames unsorted", &raw("petname", names(vec![pet("bob", &keys[4]), pet("alice", &keys[3])])), m),
                entry("petnames duplicate name", &raw("petname", names(vec![pet("alice", &keys[3]), pet("alice", &keys[4])])), m),
                entry("petname uppercase", &raw("petname", names(vec![pet("Alice", &keys[3])])), m),
                entry("petname with a dot", &raw("petname", names(vec![pet("a.b", &keys[3])])), m),
                entry("petname starting with a digit", &raw("petname", names(vec![pet("1a", &keys[3])])), m),
                entry("petname of 33 bytes", &raw("petname", names(vec![pet(&"a".repeat(33), &keys[3])])), m),
                entry("petname empty", &raw("petname", names(vec![pet("", &keys[3])])), m),
                entry("petnames over 512", &raw("petname", names(many_names)), m),
                entry("petname with a short key", &raw("petname", names(vec![sk(&[1; 31], "a", None)])), m),
                entry("petname with an unknown field", &raw("petname", names(vec![sk(k3, "a", Some(("note", "x")))])), m),
                entry("petnames with an unknown field", &raw("petname", Cbor::Map(vec![("names".into(), Cbor::Array(vec![])), ("owner".into(), Cbor::Text("x".into()))])), m),
                entry("labels unsorted", &raw("label", labels(vec![tag("record", spam.bytes(), "spam"), tag("record", spam.bytes(), "nsfw")])), m),
                entry("labels record before key", &raw("label", labels(vec![tag("record", spam.bytes(), "spam"), tag("key", k3, "trusted")])), m),
                entry("labels duplicate", &raw("label", labels(vec![tag("record", spam.bytes(), "spam"), tag("record", spam.bytes(), "spam")])), m),
                entry("label with key and record", &raw("label", labels(vec![Cbor::Map(vec![("key".into(), Cbor::Bytes(k3.to_vec())), ("record".into(), Cbor::Bytes(spam.bytes().to_vec())), ("value".into(), Cbor::Text("spam".into()))])])), m),
                entry("label without subject", &raw("label", labels(vec![Cbor::Map(vec![("value".into(), Cbor::Text("spam".into()))])])), m),
                entry("label value with a dash", &raw("label", labels(vec![tag("record", spam.bytes(), "no-go")])), m),
                entry("label value empty", &raw("label", labels(vec![tag("record", spam.bytes(), "")])), m),
                entry("label value of 33 bytes", &raw("label", labels(vec![tag("record", spam.bytes(), &"a".repeat(33))])), m),
                entry("labels over 512", &raw("label", labels(many_labels)), m),
                entry("label with an unknown field", &raw("label", labels(vec![Cbor::Map(vec![("record".into(), Cbor::Bytes(spam.bytes().to_vec())), ("value".into(), Cbor::Text("spam".into())), ("why".into(), Cbor::Text("x".into()))])])), m),
            ]
        }),
    );
}

fn follows(keys: &[SecretKey], manifest: &Manifest) {
    use weft_core::Follows;
    let (root, device) = (&keys[0], &keys[1]);
    let at = 1_760_000_030;
    let raw = |body: Cbor| {
        Draft {
            author: root.public(),
            signer: device.public(),
            kind: "follow".into(),
            created: at,
            refs: vec![],
            body: Body::Inline(body.encode()),
        }
        .sign(device)
        .unwrap()
    };
    let list = |entries: Vec<Cbor>| Cbor::Map(vec![("follows".into(), Cbor::Array(entries))]);
    let mut sorted = vec![keys[3].public(), keys[4].public(), keys[2].public()];
    sorted.sort_by(|a, b| a.bytes().cmp(b.bytes()));
    let follows = Follows { keys: sorted.clone() };
    let low = Cbor::Bytes(sorted[0].bytes().to_vec());
    let high = Cbor::Bytes(sorted[1].bytes().to_vec());
    let mut many: Vec<Vec<u8>> = (0..513u32)
        .map(|i| {
            let mut seed = [7u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            SecretKey::from_seed(seed).public().bytes().to_vec()
        })
        .collect();
    many.sort();
    let mut weak = [0u8; 32];
    weak[0] = 1;
    let signed = |d: Draft| d.sign(device).unwrap();
    let (r, d) = (root.public(), device.public());
    let m = Some(manifest);
    write(
        "follows",
        &json!({
            "records": [
                entry("follows", &signed(follows.draft(&r, &d, at)), m),
                entry("empty follows", &signed(Follows::default().draft(&r, &d, at)), m),
                entry("follows without manifest", &signed(follows.draft(&r, &d, at)), None),
                entry("follows unsorted", &raw(list(vec![high, low.clone()])), m),
                entry("follows duplicate", &raw(list(vec![low.clone(), low.clone()])), m),
                entry("follows over 512", &raw(list(many.into_iter().map(Cbor::Bytes).collect())), m),
                entry("follow with a short key", &raw(list(vec![Cbor::Bytes(vec![1; 31])])), m),
                entry("follow with a weak key", &raw(list(vec![Cbor::Bytes(weak.to_vec())])), m),
                entry("follow as text", &raw(list(vec![Cbor::Text("alice".into())])), m),
                entry("follow as a map", &raw(list(vec![Cbor::Map(vec![("key".into(), low)])])), m),
                entry("follows missing", &raw(Cbor::Map(vec![])), m),
                entry("follows with an unknown field", &raw(Cbor::Map(vec![("follows".into(), Cbor::Array(vec![])), ("note".into(), Cbor::Text("x".into()))])), m),
            ]
        }),
    );
}
