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

![status](https://img.shields.io/badge/status-M1-yellow)
![category](https://img.shields.io/badge/category-Protocol%20%2F%20Identity-9cf)
![difficulty](https://img.shields.io/badge/difficulty-Insane-critical)
![rust](https://img.shields.io/badge/rust-1.85%2B-orange)
![tests](https://img.shields.io/badge/tests-17%20passing-brightgreen)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-brightgreen)

```
┌─[ TARGET ]──────────────────────────────────────────────────────┐
│ codename   : weft                                               │
│ category   : Application layer for a new internet               │
│ stack      : Rust · Ed25519 · blake3 · canonical CBOR           │
│ interfaces : weft-core crate · weft CLI                         │
│ flags      : user [sign here, verify there]                     │
│              root [revoke a device, watch its records die]      │
│ status     : M1 — spec frozen · 2 crates · 4 vector files       │
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

This milestone is the bottom of the stack: the record format, the identity
model, and one verification choke point. No network yet. That is M2.

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

The normative spec is [`docs/protocol.md`](docs/protocol.md). The vision it
serves is [`docs/design.md`](docs/design.md).

## [ Foothold ]

```bash
cargo build --release
export WEFT_PASSPHRASE='correct horse'      # or omit and get prompted
target/release/weft init                    # prints your root address
```

Keys live under `$XDG_DATA_HOME/weft`, root and device seeds encrypted with
Argon2id and XChaCha20-Poly1305, files at mode 0600.

## [ User Flag ] — sign here, verify there

```bash
weft device add laptop
weft manifest                               # root signs; emits manifest + pointer
weft sign page.html --as laptop             # prints records/<address>.weft
weft point home <address> --as laptop       # mutable name over an immutable record
```

Copy `records/` to another machine. Nothing else travels.

```bash
weft --dir records verify <address>.weft    # finds the manifest, checks the window
weft --dir records resolve <root> home      # walks pointers, prints the head
weft inspect <address>.weft
```

## [ Root Flag ] — revoke a device, watch its records die

```bash
weft device revoke laptop
weft manifest                               # seq 2, revoked list grows
```

Copy the two new records over. `verify` on the page now answers
`signer revoked`, and `resolve` finds no valid head. Revocation is
retroactive in version 1 and enforced by the reader, not the host.

## [ Persistence ] — posture

- `#![forbid(unsafe_code)]` in both crates, clippy pedantic, `unwrap`
  and `panic` denied in library code.
- Strict Ed25519 verification, weak public keys rejected, domain separated
  signatures.
- Addresses carry a version byte and a blake3 checksum. Typos fail closed.
- The core crate does no I/O and takes no randomness. The CLI owns both.
- `cargo-deny` gates advisories, licenses, and sources in CI.

## [ Loadout ]

```
crates/core/         weft-core: address · cbor · identity · record · manifest · pointer · verify
crates/cli/          weft: keystore · store · home · commands
docs/protocol.md     normative spec
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

M2: iroh transport, pointers over the network, a minimal relay. See
[`progress/`](progress/).
