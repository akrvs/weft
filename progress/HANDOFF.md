# Handoff

Read first, rewritten at every close, never appended, under 120 lines.

## Where we are

| | |
|---|---|
| Done | M0 spec and vectors, M1 core and CLI, M2 relay over iroh, M3 browser, M4 DNS bridge and gateway, M5 personal store and grants, M6 challenge response login, M7 payments experiment, M8 store as the single gate, M9 reads behind the gate, M10 store hardening, M11 gateway behind the gate, M12 reads that fetch, M13 fetch hardening |
| Next | roadmap complete; M14 is open, pull it from `BACKLOG.md` |
| Repo | private, github.com/akrvs/weft, CI on push to main, license deferred |

## Crates

| Crate | Path | One line |
|---|---|---|
| weft-core | crates/core | Address, canonical CBOR, identity, record, manifest, pointer, grant, revoke, receipt, voucher, login challenge and proof, one `verify` |
| weft-home | crates/home | Encrypted keystore, record store with a shared cache that mirrors the directory, the one blob writer, part sweep, `Snapshot`, `Reads` trait, relay list, home directory layout |
| weft-net | crates/net | Relay wire protocol, client, relay handler with pricing, pins, sweep, redb index, `EndpointId` re-export |
| weft-resolve | crates/resolve | Target grammar, DNS registry over DoH with a positive and negative TTL cache, `Resolver<R: Reads>` for records, heads, blobs, pulling from relays on a miss unless `offline`, Markdown renderer |
| weft-store | crates/store | Store gate over a Unix socket: wire, `Gate`, server, client, pooled `Local` reads, browser key per run, `weft-store` and `weft-app` binaries |
| weft-relay | crates/relay | Relay binary: init, allow, deny, rate, bank, price, serve |
| weft-bank | crates/bank | Faucet binary: init, whoami, mint vouchers |
| weft-gateway | crates/gateway | HTTP gateway binary over hyper and `Resolver<Local>`: any target the address bar takes, provenance headers, `/login` sessions on disk, allow list, pulls for sessions only |
| weft | crates/cli | Commands over home, net, and resolve: grants, price, paid push, receipts, login |
| weft-browser | crates/browser | Tauri 2 app over `Resolver<Local>`: every record and blob over the socket, store view with daemon log, start form from a failed navigation, login consent |

## Frozen decisions

- Ed25519 strict, blake3, RFC 8949 deterministic CBOR subset, no unknown fields. Addresses:
  version byte, 32 byte payload, 4 byte checksum, base32. Manifests and the pointer named
  `manifest` are root signed only, device keys sign the rest, revocation is retroactive in version
  1. Pointers carry a Lamport `seq` per author and name and cite prior heads; head order is
  highest `seq`, then `created`, then lowest address.
- Relay is a cache with a contract: allowlisted authors push, payers pin, anyone reads, the relay
  never signs. Blobs are pulled after acceptance. Pages are CommonMark without raw HTML, rendered
  in Rust to a fixed element set. Links `weft:` or `https:` only, images `weft:` only, rendered by
  the browser as `weft://blob/<address>`. Tauri 2, vanilla TypeScript, strict CSP.
- Address bar grammar lives in `Target`: raw address, `author/name`, `domain`, `domain/name`; a
  bare domain opens `home`; domains are lowercase ASCII labels with a dot. DNS registry:
  `_weft.<domain>` TXT `weft=<key address>`, exactly one, over DoH to Cloudflare unless
  `WEFT_DOH=ip,name`. DNSSEC reported only. Cache per process, 1024 hosts, TTL clamped 60 s to
  3600 s: a binding for the lowest TXT TTL, a miss for the SOA negative TTL. NXDomain, an empty
  answer, two records, and a malformed value are misses; other codes and transport failures are
  errors, never cached.
- Gateway: plain HTTP on an explicit bind, default loopback, GET and HEAD only except POST
  `/login` and `/logout`, no script, no remote origin, TLS is a reverse proxy's job. Reads go over
  the store socket through `Local`; a stopped daemon answers 503, never the directory. Anonymous
  requests use `Resolver::offline` and answer 404 `...; log in to fetch from relays`; a live
  session pulls under a gateway wide `Semaphore` of 4, past it 429. Sessions: `<home>/gateway/sessions`,
  canonical CBOR, mode 0600, rewritten on every login and logout, at most 1024. `--allow <path>`:
  one root address per line, read at start, checked before the nonce is consumed.
- Grants: `grant` body `app`, sorted `kinds` of 1 to 16, `access` 1 read 2 write 3 both, optional
  `expires`; `revoke` cites the grant in body and `refs`. Device signed allowed. Reserved kinds
  never grantable. Active means valid, unexpired, not revoked, checked at every request.
- The store is a daemon on `<home>/store.sock` mode 0600, relay framing, nonce handshake under
  `weft/store/1`, idle connections closed at 60 s. Writes are signed by the daemon's device key
  and verified against the manifest. Grant reads cover the root only. The browser and the gateway
  are its privileged clients through `<home>/browser.key`, 32 seed bytes mode 0600, written fresh
  by every `serve` once it holds the socket; `Local` reads it at connect and pools 4 idle
  connections. That key skips grants and alone may use the requests `docs/store.md` marks browser
  only. Neither client signs or opens `records/` or `blobs/`; the browser pushes to relays itself.
  `serve --attach` reads the passphrase from stdin and exits on its EOF; the browser holds the
  pipe and shows a 16 KiB stderr ring.
- Blobs cross the socket by `offset` in chunks of at most 512 KiB, total at most 1 GiB, hashed
  whole by the resolver, which reads only through `weft_home::Reads` and verifies every candidate.
  `Store`'s cache is memory only and pruned to the directory on every snapshot. `Resolver::relays`
  is the one place the relay list is read and the client bound; `offline()` turns it off. Reads
  pull on a miss: records and heads from each relay in turn under 5 s, blobs under `PART_TTL`
  120 s, then `keep` or `keep-blob` to the daemon, which never talks to a relay. `keep-blob`
  appends to `<home>/blobs/<address>.part`: offset 0 starts over, any other offset must equal the
  part length, at `total` the daemon hashes and adopts or removes it. `serve` removes every part
  before it binds, every snapshot removes parts idle past `PART_TTL`, and `Store::keep_blob` is
  the only writer of `blobs/`.
- Payments: voucher `bank`, `to`, `cents`, `nonce`, `sig` under `weft/voucher/1`, 256 bytes max,
  spent once. `receipt` reserved: `relay`, sorted `records` 1 to 64 also in `refs`, `until`,
  `voucher`. Pays only for its author. `ceil(bytes/1024) * days * rate`, 366 days max. Allowlisted
  authors are free and never swept. The relay never signs.
- Login: record of kind `login`, body the challenge (`service` origin, `nonce` bytes(32), `expires`
  after `created`), `refs` empty, never stored or relayed, grantable. Proof is `login` plus an
  optional `manifest`, at most 64 KiB, base64url in `weft:login?c=`. Highest `seq` manifest wins.

## Gotchas that cost time

- Tauri ignores child web view positions on Linux; see `frame` and `pack`. WebKit routes only
  `weft://blob/<address>` to the scheme handler. Screenshots: `grim -g "x,y wxh"` from `hyprctl
  clients -j` after focusing `class:weft-browser`; `ydotool` coordinates are doubled at 2560 wide.
- iroh `presets::N0` needs internet. Tests use `presets::Minimal` with `RelayMode::Disabled` over
  loopback; relays are bare ids, so a loopback test seeds the client endpoint with
  `iroh::address_lookup::MemoryLookup`. CLI network commands need a relay. A socket path over 107
  bytes fails with `SUN_LEN`; a home under a deep scratch directory hits it, use `/tmp/w<n>`.
- hickory's `Resolver` never asks for the AD bit; `weft-resolve::Dns` builds it, and `Record::ttl`
  is a field. hickory 0.26 reports NXDomain and an empty answer as a `NoRecordsFound` error
  carrying `negative_ttl`, not as a response. Relay reads `allow`, `banks`, `rate` only at start:
  run `allow` before `serve`. Argon2id: debug CLI tests take 15 s. `deny.toml` ignores
  unmaintained advisories. reqwest `rustls-no-provider` panics without a provider; the browser
  installs `ring` in `main`.
- Idle connections close after 60 s; `Local` retries once, a bare `Client` does not. `Local`
  reports a missing daemon only as text, `weft_store::Error::Down`; the browser and the gateway
  compare against it. `echo pass | weft-store serve --attach &` dies at once on EOF. `weft login
  sign` takes the `c=` value alone.
- Relay `put` order: manifests, records, receipts; unpaid records wait for a receipt in the batch.
  `iroh-blobs` 0.103 has no delete; `sweep` reports orphans. A fresh worktree has no
  `node_modules`: `npm ci --prefix crates/browser/ui` before the UI check.

## Verify before commit

Every flag section of `README.md` is a runnable transcript. `vectors/` regenerate only on a format change: `cargo run -p weft-core --example vectors`.

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets
cargo test --workspace && cargo deny check && npm run --prefix crates/browser/ui check
grep -rnP '[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}]' README.md docs progress crates --exclude-dir=node_modules
grep -rn '//' crates --include='*.rs' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist | grep -v '://'
```

## Parallel

Nothing in flight. Shared files are edited only at close; conflict rules are in the `milestone` skill.
