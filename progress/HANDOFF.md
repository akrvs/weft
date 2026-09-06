# Handoff

## Where we are

| | |
|---|---|
| Done | M0 spec and vectors, M1 core and CLI, M2 relay over iroh, M3 browser, M4 DNS bridge and gateway, M5 personal store and grants, M7 payments experiment |
| Next | M6 challenge response login |
| After | roadmap ends at M7; M8 is open, see `BACKLOG.md` |
| Repo | private, github.com/akrvs/weft, CI on push to main, license deferred |

Roadmap in `docs/design.md`. Each milestone owns `progress/M#.md`. Loose
ends live in `progress/BACKLOG.md`.

## Crates

| Crate | Path | One line |
|---|---|---|
| weft-core | crates/core | Address, canonical CBOR, identity, record, manifest, pointer, grant, revoke, receipt, voucher, one `verify` |
| weft-home | crates/home | Encrypted keystore, record store, active grants, relay list, home directory layout |
| weft-net | crates/net | Relay wire protocol, client, relay handler with pricing, pins, sweep, redb index |
| weft-resolve | crates/resolve | Target grammar, DNS registry over DoH, record and head resolution, Markdown renderer |
| weft-store | crates/store | Store gate over a Unix socket: wire, `Gate`, server, client, `weft-store` and `weft-app` binaries |
| weft-relay | crates/relay | Relay binary: init, allow, deny, rate, bank, price, serve |
| weft-bank | crates/bank | Faucet binary: init, whoami, mint vouchers |
| weft-gateway | crates/gateway | HTTP gateway binary over hyper: any target the address bar takes, provenance headers |
| weft | crates/cli | Commands over home, net, and resolve, including grants, price, paid push, receipts |
| weft-browser | crates/browser | Tauri 2 app over weft-resolve, TypeScript chrome, store view |

`vectors/` regenerate only on a deliberate format change with
`cargo run -p weft-core --example vectors`. CI fails on drift.

## Frozen decisions

- Ed25519 strict, blake3, RFC 8949 deterministic CBOR subset, no unknown
  fields. Addresses: version byte, 32 byte payload, 4 byte checksum, base32.
- Manifests and the pointer named `manifest` are root signed only. Device
  keys sign everything else. Revocation is retroactive in version 1.
- Pointers carry a Lamport `seq` per author and name and cite prior heads.
  Head order: highest `seq`, then `created`, then lowest address.
- Relay is a cache with a contract: allowlisted authors push, payers pin,
  anyone reads, the relay never signs. Blobs are pulled after acceptance.
- Pages are CommonMark without raw HTML, rendered in Rust to a fixed
  element set. Links `weft:` or `https:` only, images `weft:` only.
- Tauri 2 with vanilla TypeScript, no framework, no bundler, strict CSP.
- Address bar grammar lives in `Target`: raw address, `author/name`,
  `domain`, `domain/name`. A bare domain opens `home`.
- DNS registry: `_weft.<domain>` TXT `weft=<key address>`, exactly one.
  Looked up over DNS over HTTPS to Cloudflare unless `WEFT_DOH=ip,name`.
  DNSSEC is reported from the resolver's AD bit, never required.
- Gateway: plain HTTP on an explicit bind, default loopback, GET and HEAD
  only, no script, no remote origin. TLS is a reverse proxy's job.
- Grants: `grant` body `app`, sorted `kinds` of 1 to 16, `access` 1 read
  2 write 3 both, optional `expires`; `revoke` cites the grant in body and
  `refs`. Device signed allowed. Reserved kinds never grantable. Active
  means valid, unexpired, not revoked, checked at every request.
- The store is a daemon on `<home>/store.sock` mode 0600, relay framing,
  nonce handshake under `weft/store/1`. Writes are signed by the daemon's
  device key and verified against the manifest. Reads cover the root only.
- Payments: voucher `bank`, `to`, `cents`, `nonce`, `sig` under
  `weft/voucher/1`, 256 bytes max, spent once. `receipt` reserved: `relay`,
  sorted `records` 1 to 64 also in `refs`, `until`, `voucher`. Pays only
  for its author. `ceil(bytes/1024) * days * rate`, 366 days max.
  Allowlisted authors are free and never swept. The relay never signs.
- Dependencies default features off, exact minor pins, cargo-deny gates.

## Gotchas that cost time

- Tauri packs child web views in a GtkBox on Linux and ignores positions.
  The browser wraps the chrome in a ScrolledWindow and toggles packing on
  open and close: `frame` and `pack` in `crates/browser/src/main.rs`.
- iroh `presets::N0` needs internet. Tests use `presets::Minimal` with
  `RelayMode::Disabled` over loopback. CLI network commands need a relay.
- hickory's `Resolver` never asks for the AD bit. `weft-resolve::Dns`
  builds the query itself. `Record::data` is a field in hickory-proto 0.26.
- The relay reads `allow`, `banks`, and `rate` only at start. Argon2id at
  64 MiB makes the CLI end to end test take ten seconds in debug.
- `deny.toml` ignores unmaintained advisories from iroh transitives, GTK3
  bindings, and Tauri codegen, each with a reason. Add only with a reason.
- Screenshots on this Wayland desktop: `grim -g "x,y wxh"` on the rectangle
  from `hyprctl clients -j`. Keys reach the app through `hyprctl dispatch
  sendshortcut ", Tab, class:weft-browser"`; drive dialogs by Tab and Return.
- Store tests bind real sockets under `temp_dir()`, one directory per test.
- Relay `put` order: manifests, records, receipts. Non allowlisted records
  wait in memory for a receipt in the same batch. `iroh-blobs` 0.103 has
  no public blob delete; `sweep` returns orphaned hashes, nothing collects.

## Run it

```bash
npm ci --prefix crates/browser/ui && npm run --prefix crates/browser/ui build
cargo build --release && export WEFT_PASSPHRASE='...'
weft init && weft device add laptop && weft manifest
weft-relay init && weft-relay allow <root> && weft-relay serve
weft relay add <relay id> && weft sign page.md --as laptop && weft push
weft-gateway --bind 127.0.0.1:8080 && weft dns example.com
weft-store serve --device laptop && WEFT_APP_PASSPHRASE='...' weft-app key
weft grant add <app> --kind note --read --write --as laptop && weft-app write note n.md
weft-app read note && weft grant revoke <grant> --as laptop && weft-browser <root>/home
weft-relay rate 1 && weft-relay bank add <bank> && weft-bank init && weft-bank mint --to <relay id> --cents 4 --out v.bin && weft push <page> --pay v.bin --days 1
```

## Verify before commit

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets
cargo test --workspace && cargo deny check
npm run --prefix crates/browser/ui check
grep -rnP '[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}]' README.md docs progress crates --exclude-dir=node_modules
grep -rn '//' crates --include='*.rs' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist | grep -v '://'
```

## Parallel

| Milestone | Depends on | Touches |
|---|---|---|
| M6 challenge response login | nothing in flight | new crate, browser identity, store handshake reuse |

Shared files edited only at close; conflict rules are in the `milestone` skill.
