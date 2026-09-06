# Handoff

The one file a new session reads first. Rewritten at the close of every
milestone, never appended. Keep it under 120 lines.

## Where we are

| | |
|---|---|
| Done | M0 spec and vectors, M1 core and CLI, M2 relay over iroh, M3 browser, M4 DNS bridge and gateway |
| Next | M5 personal store and grants |
| After | M6 challenge response login, M7 payments |
| Repo | private, github.com/akrvs/weft, CI on push to main, license deferred |

Roadmap detail is the table in `docs/design.md`. Each milestone gets its
own `progress/M#.md`, written before code, updated with the work.

## Crates

| Crate | Path | One line |
|---|---|---|
| weft-core | crates/core | Address, canonical CBOR, identity, record, manifest, pointer, one `verify` |
| weft-home | crates/home | Encrypted keystore, record store, relay list, home directory layout |
| weft-net | crates/net | Relay wire protocol, client, relay handler, redb index |
| weft-resolve | crates/resolve | Target grammar, DNS registry over DoH, record and head resolution, Markdown renderer |
| weft-relay | crates/relay | Relay binary: init, allow, deny, serve |
| weft-gateway | crates/gateway | HTTP gateway binary over hyper: any target the address bar takes, provenance headers |
| weft | crates/cli | Commands over home, net, and resolve |
| weft-browser | crates/browser | Tauri 2 app over weft-resolve, TypeScript chrome |

Fixtures in `vectors/` are regenerated only on a deliberate format change
with `cargo run -p weft-core --example vectors`. CI fails on drift.

## Frozen decisions

- Ed25519 strict, blake3, RFC 8949 core deterministic CBOR subset, no
  unknown fields anywhere.
- Addresses: version byte, 32 byte payload, 4 byte blake3 checksum,
  lowercase base32, 60 characters.
- Manifests and the pointer named `manifest` are root signed only. Device
  keys sign everything else. Revocation is retroactive in version 1.
- Pointers carry a Lamport `seq` per author and name and cite prior heads.
  Head order: highest `seq`, then `created`, then lowest address.
- Relay is a cache with a contract: allowlisted authors push, anyone
  reads, the relay never signs. Blobs are pulled from the pusher after the
  record is accepted.
- Pages are CommonMark without raw HTML, rendered in Rust to a fixed
  element set. Links `weft:` or `https:` only, images `weft:` only.
- Tauri 2 with vanilla TypeScript, no framework, no bundler, strict CSP.
- Address bar grammar lives in `Target`: raw address, `author/name`,
  `domain`, `domain/name`. A bare domain opens `home`. Domains are
  lowercase ASCII labels with at least one dot.
- DNS registry: `_weft.<domain>` TXT `weft=<key address>`, exactly one.
  Looked up over DNS over HTTPS to Cloudflare unless `WEFT_DOH=ip,name`.
  DNSSEC is reported from the resolver's AD bit, never required.
- Gateway speaks plain HTTP on an explicit bind, default loopback. TLS is
  a reverse proxy's job. GET and HEAD only, no script, no remote origin.
- Dependencies default features off, exact minor pins, cargo-deny gates.

## Gotchas that cost time

- Tauri ignores child web view positions on Linux and packs children in a
  GtkBox. The browser fixes layout through the `gtk` crate: chrome wrapped
  in a ScrolledWindow with External policy, packing toggled on open and
  close. See `frame` and `pack` in `crates/browser/src/main.rs`.
- iroh `presets::N0` needs internet. Tests use `presets::Minimal` with
  `RelayMode::Disabled` over loopback. CLI network commands need a real
  relay.
- hickory's `Resolver` never asks for the AD bit. `weft-resolve::Dns`
  builds the query message itself and sends it through `NameServerPool`.
  `Record::data` is a field in hickory-proto 0.26, not a method.
- The relay reads its allowlist only at start.
- Argon2id at 64 MiB makes the CLI end to end test take about ten seconds
  in debug builds. That is expected.
- `deny.toml` ignores unmaintained advisories from iroh transitives, GTK3
  bindings, and Tauri codegen, each with a reason. Add to the list only
  with a reason.
- Screenshots on this Wayland desktop: a tab in the running Firefox plus
  `grim`. Headless Firefox fails.

## Run it

```bash
cargo build --release
export WEFT_PASSPHRASE='...'
weft init && weft device add laptop && weft manifest
weft-relay init && weft-relay allow <root> && weft-relay serve
weft relay add <relay id> && weft sign page.md --as laptop && weft push
weft-gateway --bind 127.0.0.1:8080 && weft dns example.com
weft-browser <root>/home
```

Browser UI: `cd crates/browser/ui && npm ci && npm run build` first.

## Verify before commit

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets
cargo test --workspace && cargo deny check
npm run --prefix crates/browser/ui check
grep -rnP '[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}]' README.md docs progress crates --exclude-dir=node_modules
grep -rn '//' crates --include='*.rs' --include='*.ts' --exclude-dir=node_modules | grep -v '://'
```

## Parallel

Independent pairs may run at the same time in separate worktrees:

| Milestone | Depends on | Touches |
|---|---|---|
| M5 personal store and grants | nothing in flight | new crate, home, browser store view |
| M6 challenge response login | M5 landed | new crate, browser identity |
| M7 payments | M5 landed | net, relay, new kinds |

Shared files edited only at close: HANDOFF, BACKLOG, README, Cargo.toml,
Cargo.lock, deny.toml, ci.yml. Conflict rules live in the `milestone` skill.

## Open questions

In `progress/BACKLOG.md`. The biggest is revocation with an effective time.
