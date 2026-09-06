# Weft protocol, version 1

Normative. Defines the byte formats and rules a conforming implementation
must follow. `vectors/` holds fixtures every implementation must reproduce.

## 1. Primitives

| Primitive | Choice |
|---|---|
| Signature | Ed25519, RFC 8032, strict verification, weak public keys rejected |
| Hash | blake3, 32 byte output |
| Encoding | CBOR, RFC 8949, core deterministic encoding, restricted subset |
| Text | UTF-8 |
| Time | Unsigned integer seconds since the Unix epoch, author asserted |

## 2. Canonical CBOR

Only these major types are allowed: unsigned integer (0), byte string (2),
text string (3), array (4), map (5). Anything else, including negative
integers, floats, booleans, null, tags, and indefinite lengths, is rejected.

- Integers and lengths use the shortest form that fits.
- Map keys are text strings, unique, sorted by the bytewise order of their
  encoded form. Shorter keys therefore sort before longer ones.
- Nesting depth is at most 8. Arrays and maps hold at most 4096 items.
- Decoders reject any input that does not re-encode to identical bytes.
- Unknown map keys are rejected in every structure defined here.

## 3. Addresses

An address names a public key or a record. Its binary form is 37 bytes:

```
version(1) || payload(32) || checksum(4)
```

| Version | Payload |
|---|---|
| `0x01` | Ed25519 public key |
| `0x02` | blake3 hash |

`checksum` is the first 4 bytes of `blake3(version || payload)`. The text
form is RFC 4648 base32 of the 37 bytes, lowercase, no padding, exactly 60
characters. Decoders reject uppercase, wrong length, unknown versions, and
checksum mismatches.

## 4. Records

A record is a CBOR map with these keys and no others:

| Key | Type | Rule |
|---|---|---|
| `author` | bytes(32) | root public key of the identity |
| `signer` | bytes(32) | public key that produced `sig`; equals `author` or a device key |
| `kind` | text | 1 to 32 bytes of `a-z`, `0-9`, `_` |
| `created` | uint | author asserted creation time |
| `refs` | array of bytes(32) | record hashes this record cites; at most 1024 |
| `body` | bytes | inline payload, at most 65536 bytes |
| `blob` | bytes(32) | blake3 hash of an external payload |
| `sig` | bytes(64) | Ed25519 signature |

Exactly one of `body` and `blob` is present.

The signature covers the canonical encoding of the map without `sig`,
framed with a domain string:

```
message = "weft/record/1" || 0x00 || canonical(record without sig)
sig     = Ed25519.sign(signer, message)
```

The record address is `blake3(canonical(record))` over the full map
including `sig`, with version `0x02`.

Records are immutable. Mutation is expressed with pointers.

## 5. Manifests

`kind = "manifest"`. Lists the device keys allowed to sign for an identity.
`signer` must equal `author`. `body` is a canonical map:

| Key | Type | Rule |
|---|---|---|
| `seq` | uint | strictly increasing per identity |
| `prev` | bytes(32), optional | address of the previous manifest record |
| `devices` | array of device maps | sorted by key bytes, unique, at most 256 |
| `revoked` | array of bytes(32) | sorted, unique, at most 256 |

A device map holds `key` bytes(32), `label` text of 1 to 64 bytes,
`created` uint, and optionally `expires` uint greater than `created`.

The root key must not appear in `devices` or `revoked`. A key must not
appear in both lists. When a record cites `prev`, it also lists it in `refs`.

The newest manifest for an identity is the valid one with the highest
`seq`, ties broken by the highest `created`.

## 6. Pointers

`kind = "pointer"`. Names the current version of something mutable.
`body` is a canonical map:

| Key | Type | Rule |
|---|---|---|
| `name` | text | 1 to 64 bytes |
| `target` | bytes(32) | address of the current record |
| `seq` | uint | Lamport sequence for this author and name |
| `prev` | array of bytes(32) | addresses of the heads the writer saw; at most 16 |

A writer sets `seq` to one more than the highest `seq` it has seen for the
same author and name, and lists the heads it saw in `prev` and in `refs`.

The head among valid pointers with the same author and name is the one with
the highest `seq`, then the highest `created`, then the lowest address.
Forks are visible: two heads with equal `seq` are both retained until a
later pointer cites both.

The name `manifest` is reserved. A pointer named `manifest` must have
`signer` equal to `author`, and its target is the newest manifest record.

## 7. Verification

Every implementation verifies through one procedure. Given a record and,
optionally, the newest manifest for its author:

1. Decode the bytes. Reject non-canonical input and unknown fields.
2. Check field constraints from sections 4 to 6.
3. Verify `sig` under `signer` with strict Ed25519 verification.
4. If `kind` is `manifest`, or `kind` is `pointer` with name `manifest`,
   require `signer == author`.
5. If `signer != author`: a manifest is required. Reject if `signer` is in
   `revoked`. Reject if `signer` is not in `devices`. Reject if `created`
   is before the device's `created` or not before its `expires`.
6. The record address is the blake3 hash of the input bytes.

Revocation applies to everything the revoked key signed. A relying party
holding a newer manifest must re-verify what it holds.

## 8. Limits

| Limit | Value |
|---|---|
| Inline body | 65536 bytes |
| Refs per record | 1024 |
| Kind length | 32 bytes |
| Devices, revoked keys | 256 each |
| Pointer prev | 16 |
| Name, label | 64 bytes |
| Kinds per grant | 16 |
| CBOR depth | 8 |
| CBOR items per container | 4096 |

## 9. Reserved kinds

`manifest`, `pointer`, `grant`, and `revoke` are defined here. `page` and
`file` are conventional for M1 and carry no extra rules. Later versions
define `receipt`, `label`, and `petname`.

## 10. Grants

`kind = "grant"`. Lets an application key read or write kinds in the
author's store. `body` is a canonical map:

| Key | Type | Rule |
|---|---|---|
| `app` | bytes(32) | application public key |
| `kinds` | array of text | 1 to 16 kind names, sorted, unique, none reserved |
| `access` | uint | 1 read, 2 write, 3 both |
| `expires` | uint, optional | greater than the record's `created` |

`kind = "revoke"`. Ends a grant. `body` is a canonical map with one key,
`grant` bytes(32), the address of the grant record, which is also listed
in `refs`.

A grant is active at time `t` when its record verifies, `expires` is
absent or greater than `t`, and no verifying revoke by the same author
cites it. A store enforces grants at the moment of each request. Records
of a reserved kind are never readable or writable through a grant.
