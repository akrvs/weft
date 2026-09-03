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

![status](https://img.shields.io/badge/status-M3-yellow)
![category](https://img.shields.io/badge/category-Protocol%20%2F%20Identity-9cf)
![difficulty](https://img.shields.io/badge/difficulty-Insane-critical)
![rust](https://img.shields.io/badge/rust-1.85%2B-orange)
![tests](https://img.shields.io/badge/tests-27%20passing-brightgreen)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-brightgreen)

```
┌─[ TARGET ]──────────────────────────────────────────────────────┐
│ codename   : weft                                               │
│ category   : Application layer for a new internet               │
│ stack      : Rust · Ed25519 · blake3 · CBOR · iroh · Tauri 2    │
│ interfaces : core · home · net · CLI · relay · browser          │
│ flags      : user [sign here, fetch there, no shared server]    │
│              root [one address bar for both webs]               │
│ status     : M3 — spec frozen · 6 crates · browser first cut    │
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

Three milestones in: the record format, the identity model, one
verification choke point, a relay that moves records and blobs between
machines over iroh QUIC, and a browser that opens signed records and the
old web in the same window. The relay is a cache with a contract. The
browser trusts nothing it has not verified itself and says so on every
page.

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

## [ Root Flag ] — one address bar for both webs

```bash
cd crates/browser/ui && npm ci && npm run build && cd -
cargo run -p weft-browser -- <root>/home     # or an address, or https://…
```

The address bar takes a raw address, `author/name`, or an HTTPS URL and
says which one it resolved. Signed pages are Markdown rendered natively:
no scripts, no remote loads, images only by blob address. The provenance
panel shows address, kind, author, signer, time, and who served it. An
HTTPS page opens in a second web view under a banner that reads unsigned,
and nothing below that line is trusted. Compose signs a page with a
device key and pushes it to your relays.

Revocation still wins everywhere:

```bash
weft device revoke laptop
weft manifest                               # seq 2, revoked list grows
weft push
```

Every reader that asks the relay gets the newer manifest, the browser and
`verify` answer `signer revoked`, and the relay refuses anything else that
key signs.

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
- The browser chrome runs under a CSP with no inline script, no remote
  origins, and images only from the local blob scheme. Raw HTML in a page
  is dropped, links are limited to `weft:` and `https:`, and the HTTPS
  web view is incognito and cannot navigate off `https:`.
- `cargo-deny` gates advisories, licenses, and sources in CI.

## [ Loadout ]

```
crates/core/         weft-core: address · cbor · identity · record · manifest · pointer · verify
crates/home/         weft-home: encrypted keystore · record store · relay list
crates/net/          weft-net: wire · client · relay handler · redb index
crates/relay/        weft-relay: init · allow · serve
crates/cli/          weft: commands over home and net
crates/browser/      weft-browser: Tauri 2 app · Markdown renderer · TypeScript chrome
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

M4: DNS bridge and HTTPS gateway. A TXT record binds a domain to a key,
verified over DNS over HTTPS, and a gateway serves records to browsers that
do not speak Weft. See [`progress/`](progress/).
