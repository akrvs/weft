# Handoff

Read first, rewritten at every close, never appended, under 120 lines.

## Where we are

| | |
|---|---|
| Done | M0 spec and vectors, M1 core and CLI, M2 relay over iroh, M3 browser, M4 DNS bridge and gateway, M5 personal store and grants, M6 challenge response login, M7 payments experiment |
| Next | roadmap complete; M8 is open, pull it from `BACKLOG.md` |
| Repo | private, github.com/akrvs/weft, CI on push to main, license deferred |

Roadmap `docs/design.md`, plans `progress/M#.md`, loose ends `progress/BACKLOG.md`.

## Crates

| Crate | Path | One line |
|---|---|---|
| weft-core | crates/core | Address, canonical CBOR, identity, record, manifest, pointer, grant, revoke, receipt, voucher, login challenge and proof, one `verify` |
| weft-home | crates/home | Encrypted keystore, record store, active grants, relay list, home directory layout |
| weft-net | crates/net | Relay wire protocol, client, relay handler with pricing, pins, sweep, redb index |
| weft-resolve | crates/resolve | Target grammar, DNS registry over DoH, record and head resolution, Markdown renderer |
| weft-store | crates/store | Store gate over a Unix socket: wire, `Gate`, server, client, login request, `weft-store` and `weft-app` binaries |
| weft-relay | crates/relay | Relay binary: init, allow, deny, rate, bank, price, serve |
| weft-bank | crates/bank | Faucet binary: init, whoami, mint vouchers |
| weft-gateway | crates/gateway | HTTP gateway binary over hyper: any target the address bar takes, provenance headers, `/login` sessions |
| weft | crates/cli | Commands over home, net, and resolve: grants, price, paid push, receipts, login |
| weft-browser | crates/browser | Tauri 2 app over weft-resolve, TypeScript chrome, store view, login consent dialog |

`vectors/` regenerate only on a format change: `cargo run -p weft-core --example vectors`.

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
  `domain`, `domain/name`. A bare domain opens `home`. Domains are
  lowercase ASCII labels with at least one dot.
- DNS registry: `_weft.<domain>` TXT `weft=<key address>`, exactly one, over
  DoH to Cloudflare unless `WEFT_DOH=ip,name`. DNSSEC reported, never required.
- Gateway: plain HTTP on an explicit bind, default loopback, GET and HEAD
  only except POST `/login` and `/logout`, no script, no remote origin. TLS
  is a reverse proxy's job.
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
- Login: record of kind `login`, body the challenge (`service` origin text,
  `nonce` bytes(32), `expires` after `created`), `refs` empty, never stored
  or relayed, grantable. Proof is `login` plus optional `manifest` record,
  at most 64 KiB, base64url in `weft:login?c=`. Highest `seq` manifest wins.
- Dependencies default features off, exact minor pins, cargo-deny gates.

## Gotchas that cost time

- Tauri ignores child web view positions on Linux; see `frame` and `pack`.
- iroh `presets::N0` needs internet. Tests use `presets::Minimal` with
  `RelayMode::Disabled` over loopback. CLI network commands need a relay.
- hickory's `Resolver` never asks for the AD bit; `weft-resolve::Dns` builds it.
- The relay reads `allow`, `banks`, and `rate` only at start. Argon2id makes
  the CLI end to end tests take about fifteen seconds in debug. Expected.
- `deny.toml` ignores unmaintained advisories from iroh, GTK3, Tauri codegen.
- Screenshots: `grim -g "x,y wxh"` from `hyprctl clients -j`, visible
  workspace only, so `hyprctl dispatch focuswindow class:weft-browser` first.
  Keys: `hyprctl dispatch sendshortcut ", Tab, class:weft-browser"`; no modifiers.
- Relay `put` order: manifests, records, receipts; unpaid records wait for a
  receipt in the same batch. `iroh-blobs` 0.103 has no blob delete; `sweep`
  only reports orphans.
- reqwest with `rustls-no-provider` panics at `Client::build` unless a
  provider is installed; the browser installs `rustls::crypto::ring` in
  `main`. Only the smoke test covers it.

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
curl -sL 127.0.0.1:8080/login | grep -o 'weft:login?c=[^"]*' && weft login sign <c> --as laptop
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

Nothing in flight. Shared files are edited only at close; conflict rules
are in the `milestone` skill.
