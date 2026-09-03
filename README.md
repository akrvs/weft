```
██╗    ██╗███████╗███████╗████████╗
██║    ██║██╔════╝██╔════╝╚══██╔══╝
██║ █╗ ██║█████╗  █████╗     ██║   
██║███╗██║██╔══╝  ██╔══╝     ██║   
╚███╔███╔╝███████╗██║        ██║   
 ╚══╝╚══╝ ╚══════╝╚═╝        ╚═╝   
                        a k r v s
```

> Sign. Address. Verify. Repeat. A web where the reader holds the keys and
> the content outlives the host. Every record is signed and named by its
> hash, identity is a keypair you own, and nothing in the protocol has a
> slot for watching you. This repo is the thread the rest gets woven onto.

![status](https://img.shields.io/badge/status-M2-yellow)
![category](https://img.shields.io/badge/category-Protocol%20%2F%20Identity-9cf)
![difficulty](https://img.shields.io/badge/difficulty-Insane-critical)
![rust](https://img.shields.io/badge/rust-1.85%2B-orange)
![tests](https://img.shields.io/badge/tests-19%20passing-brightgreen)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-brightgreen)

```
┌─[ TARGET ]──────────────────────────────────────────────────────┐
│ codename   : weft                                               │
│ category   : Application layer for a new internet               │
│ stack      : Rust · Ed25519 · blake3 · canonical CBOR · iroh    │
│ interfaces : weft-core · weft-net · weft CLI · weft-relay       │
│ flags      : user [sign here, fetch there, no shared server]    │
│              root [revoke a device, watch its records die]      │
│ status     : M2 — spec frozen · 4 crates · relay over QUIC      │
└─────────────────────────────────────────────────────────────────┘
```

## [ Briefing ]

A URL names a place. Someone has to run the place, so they need revenue, so
they sell attention, so they track the reader, so they issue accounts, so
the reader's data is locked to the host. Weft breaks the first link: a
record is named by what it is, signed by who made it, and served by anyone.

| | The web | Weft |
|---|---|---|
| Address | Location | blake3 hash of the signed bytes |
| Identity | Account issued by the host | Ed25519 root key, device subkeys |
| Provenance | Trust the domain | Verify the signature, every time |
| Mutation | Overwrite in place | Immutable records, Lamport pointers |
| Revocation | Ask the host | Root signs a manifest, readers enforce it |

Two milestones in: the record format, the identity model, one verification
choke point, and a relay that moves records and blobs between machines over
iroh QUIC. The relay is a cache with a contract. It stores what allowlisted
authors push and serves it to anyone. It signs nothing and readers trust
nothing they have not verified themselves.

## [ Recon ] — the machine

```
  root key ──signs──▶ manifest { devices, revoked, seq, prev }
      │                   ▲
      │ authorizes        │ pointer "manifest" (root signed only)
      ▼                   │
  device key ──signs──▶ record { author, signer, kind, created, refs, body | blob, sig }
                          │
                          └──▶ address = blake3(canonical bytes)  ──▶ pointer { name, target, seq, prev }
```

Three rules keep it honest:

1. **Canonical or nothing.** Records are a restricted deterministic CBOR
   subset. A decoder rejects anything that would not re-encode to the same
   bytes, so one record has exactly one address.
2. **Root signs the manifest, devices sign the content.** A stolen laptop
   can publish pages until you revoke it. It can never rewrite who is
   allowed to publish.
3. **One verifier.** Signature, authorization window, and revocation are
   checked in a single function. There is no second path.

The normative spec is [`docs/protocol.md`](docs/protocol.md), the wire
protocol is [`docs/relay.md`](docs/relay.md), and the vision they serve is
[`docs/design.md`](docs/design.md).

## [ Foothold ]

```bash
cargo build --release
export WEFT_PASSPHRASE='correct horse'      # or omit and get prompted
target/release/weft init                    # prints your root address
```

Keys live under `$XDG_DATA_HOME/weft`, root and device seeds encrypted with
Argon2id and XChaCha20-Poly1305, files at mode 0600.

## [ User Flag ] — sign here, fetch there

```bash
weft device add laptop
weft manifest                               # root signs; emits manifest + pointer
weft sign page.html --as laptop             # prints records/<address>.weft
weft sign video.mp4 --kind file --as laptop # over 64 KiB becomes a blob record
weft point home <address> --as laptop       # mutable name over an immutable record
```

Run a relay anywhere with a public route, even behind NAT:

```bash
weft-relay init                             # prints the relay endpoint id
weft-relay allow <root address>             # only listed authors may push
weft-relay serve
```

Push from the laptop, resolve and fetch from the desktop. The only thing
they share is the relay endpoint id.

```bash
weft relay add <endpoint id>
weft push                                   # records first, blobs pulled by the relay
weft resolve <root> home --relay            # head pointer, verified against the newest manifest
weft fetch <address> --out page.html        # record verified, blob hash checked by iroh-blobs
```

Offline, with a copied `records/` directory, the same commands work
without `--relay`.

## [ Root Flag ] — revoke a device, watch its records die

```bash
weft device revoke laptop
weft manifest                               # seq 2, revoked list grows
```

Push the two new records. Every reader that asks the relay now gets the
newer manifest, `verify` on the page answers `signer revoked`, and the
relay itself refuses anything else that key signs. Revocation is
retroactive in version 1 and enforced by the reader, not the host.

## [ Persistence ] — posture

- `#![forbid(unsafe_code)]` in both crates, clippy pedantic, `unwrap`
  and `panic` denied in library code.
- Strict Ed25519 verification, weak public keys rejected, domain separated
  signatures.
- Addresses carry a version byte and a blake3 checksum. Typos fail closed.
- The core crate does no I/O and takes no randomness. The CLI owns both.
- Wire frames are capped at 1 MiB, batches at 64 records, and every
  message is canonical CBOR with unknown fields rejected.
- The relay verifies before it stores, pulls blobs only for records it
  has already accepted, and never signs.
- `cargo-deny` gates advisories, licenses, and sources in CI.

## [ Loadout ]

```
crates/core/         weft-core: address · cbor · identity · record · manifest · pointer · verify
crates/net/          weft-net: wire · client · relay handler · redb index
crates/relay/        weft-relay: init · allow · serve
crates/cli/          weft: keystore · store · home · net · commands
docs/protocol.md     normative record spec
docs/relay.md        wire protocol
docs/design.md       the why
vectors/             fixtures every implementation must reproduce
progress/            milestone plans and logs
```

Regenerate vectors after a deliberate format change, never by accident:

```bash
cargo run -p weft-core --example vectors && git diff vectors
```

## [ Ops ]

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo deny check
```

## [ Next Ops ]

M3: the browser. Tauri shell, tiered address bar, native record renderer,
provenance panel, embedded web view for HTTPS with the unsigned label. See
[`progress/`](progress/).
