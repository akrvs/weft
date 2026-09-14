# Handoff

Read first, rewritten at every close, never appended, under 120 lines.

## Where we are

| | |
|---|---|
| Done | M0 spec and vectors, M1 core and CLI, M2 relay over iroh, M3 browser, M4 DNS bridge and gateway, M5 personal store and grants, M6 challenge response login, M7 payments experiment, M8 store as the single gate, M9 reads behind the gate, M10 store hardening, M11 gateway behind the gate, M12 reads that fetch, M13 fetch hardening, M14 gateway and relay operations, M15 relay hygiene, M16 loose ends, M17 operational loose ends, M18 every loose end but the browser |
| Next | M19 browser polish: the whole of `BACKLOG.md`, nothing else is open |
| Repo | private, github.com/akrvs/weft, CI on push to main, license deferred |

## Crates

| Crate | Path | One line |
|---|---|---|
| weft-core | crates/core | Address, canonical CBOR, identity, record, manifest, pointer, grant, revoke, receipt, voucher, login challenge and proof, one `verify` |
| weft-home | crates/home | Encrypted keystore with `retire`, record store with an in memory index guarded by the directory mtime and a shared LRU cache under a byte cap, the one blob writer, part sweep, `Snapshot` returning `Arc<Record>`, `Reads` trait, `Relay` list entries with addresses |
| weft-net | crates/net | `Net` from `WEFT_NET`, relay wire protocol, client that primes direct addresses before a blob download, relay handler with `Config` behind a lock, `reload`, pricing, pins for any author, one rule sweep, blob GC, redb index |
| weft-resolve | crates/resolve | Target grammar, DNS registry over DoH with a positive and negative TTL cache, `Resolver<R: Reads>` for records, heads, blobs, pulling from relays on a miss unless `offline`, `metered`, `title` of an author's home page, Markdown renderer |
| weft-store | crates/store | Store gate over a Unix socket: wire, `Gate` over every held record, `stop` that ends `serve`, `Log` file, server, client, pooled `Local` reads, browser key per run, `weft-store serve` and `stop`, `weft-app` |
| weft-relay | crates/relay | Relay binary: init, allow, deny, rate, bank, price, serve through `Net` printing its list entry; SIGHUP rereads allow, banks, rate and sweeps |
| weft-bank | crates/bank | Faucet binary: init, whoami, mint vouchers |
| weft-gateway | crates/gateway | HTTP gateway binary over hyper and `Resolver<Local>`: any target the address bar takes, `Host` based routing for publisher domains, provenance headers, `/login` sessions and budget windows in `State` (redb), allow list, pulls for sessions only under `Limits`; SIGHUP rereads the allow list and sweeps sessions |
| weft | crates/cli | Commands over home, net, and resolve: device retire, grants listed with app titles, price, paid push that keeps the receipt only after accept, receipts, login; prints through `say!`, quiet on a closed pipe |
| weft-browser | crates/browser | Tauri 2 app over `Resolver<Local>`: every record and blob over the socket, store view with the log tail, a stop button, and app titles, start form from a failed navigation with an attached or detached daemon, login consent |

## Frozen decisions

- Ed25519 strict, blake3, RFC 8949 deterministic CBOR subset, no unknown fields. Manifests and the
  pointer named `manifest` are root signed only, device keys sign the rest, revocation retroactive; a
  lost key is retired instead, `weft device retire` sets its `expires` and earlier records stand.
  Pointers carry a Lamport `seq` per author and name and cite prior heads; head order is highest
  `seq`, then `created`, then lowest address.
- Endpoints bind through one `Net`: `WEFT_NET` unset is `presets::N0`, `local` is `presets::Minimal`,
  no iroh relay, mDNS lookup as `weft`; anything else is an error. A relay list entry is `<id>` or
  `<id>@<host:port>[,...]`, at most 8 addresses, dialed directly, one entry per id; serve prints its own.
- Relay is a cache with a contract: allowlisted authors push, payers pin any records present, anyone
  reads, the relay never signs. Blobs are pulled after acceptance. `allow`, `banks`, `rate` are one
  `Config` read at start and on SIGHUP; a bad file keeps the old one. The sweep, every 60 s and
  after a reload, keeps a record only if its author is allowlisted, it holds a live pin, or it is the
  manifest of an author one of whose records does; stale heads and manifest entries go too, and the
  `iroh-blobs` GC collects unnamed blobs on the same interval. `authors` and `blobs` derive from
  `records`. Pages are CommonMark without raw HTML rendered in Rust to a fixed element set; links
  `weft:` or `https:`, images `weft:` only as `weft://blob/<address>`. Tauri 2, strict CSP.
- Address bar grammar lives in `Target`: raw address, `author/name`, `domain`, `domain/name`; a bare
  domain opens `home`; domains are lowercase ASCII labels with a dot. DNS: `_weft.<domain>` TXT
  `weft=<key address>`, exactly one, over DoH to Cloudflare unless `WEFT_DOH=ip,name`, DNSSEC
  reported only. Cache per process, 1024 hosts, TTL clamped 60 s to 3600 s. NXDomain, an empty
  answer, two records, and a malformed value are misses; other codes and transport failures are
  errors, never cached. No public domain carries a record yet; the positive path is tested on the fake.
- Gateway: plain HTTP on an explicit bind, default loopback, GET and HEAD plus POST `/login` and
  `/logout`, no script, TLS is a reverse proxy's job. A `Host` that is a domain other than the
  origin's is a publisher host: `/` is its `home`, a path that is no target is its name, a full
  target keeps its meaning; login challenges name `<origin scheme>://<host>`, a bad host is 400.
  Reads go over the store socket through `Local`; a stopped daemon answers 503. Anonymous requests
  read `offline`, a miss is 404 `...; log in to fetch from relays`. A session pulls under `--pulls`
  (4), past it 429, a `--budget` MiB (64, 0 unlimited) per root per fixed hour; over it reads go
  offline and a miss says `; pull budget spent, resets at <time>`. Sessions and budget windows are
  rows in `<home>/gateway/state.redb` mode 0600, written row by row, at most `--sessions` (soonest
  expiry evicted) and `--identities` (oldest window evicted), 4096 by default, no ceiling; a bad
  file refuses to start. Pending challenges cap at 1024. `--allow`: one root address per line,
  reread on SIGHUP with a session sweep.
- Grants: body `app`, sorted `kinds` 1 to 16, `access` 1 read 2 write 3 both, optional `expires`;
  `revoke` cites the grant in body and `refs`. Device signed allowed; reserved kinds never grantable.
  Active means valid, unexpired, not revoked, checked at every request. Reads cover every held record
  of the kind verified against its author's manifest; writes stay the root's. An app is shown by the
  first heading of its `home` page, read locally.
- The store is a daemon on `<home>/store.sock` mode 0600 speaking `docs/store.md`, idle connections
  closed at 60 s. Writes are signed by the daemon's device key and verified against the manifest.
  The browser and the gateway are its privileged clients through `<home>/browser.key`, 32 seed bytes
  mode 0600, written fresh by every `serve`, pooled 4 deep by `Local`; that key alone may use the
  browser only requests, `stop` among them.
  `serve` reads the passphrase from a non terminal stdin, `--attach` also exits on EOF, and after
  binding logs to `<home>/store.log` mode 0600, rotated at 1 MiB, never to stderr. `--cache <MiB>`
  (256, 0 unlimited) bounds the cache; the index is reused while the record directory's mtime holds.
- Blobs cross the socket by `offset` in chunks of at most 512 KiB, total at most 1 GiB, hashed whole
  by the resolver, which reads only through `weft_home::Reads` and verifies every candidate; it
  alone binds the client, `offline()` turns pulls off. Reads pull on a miss, each relay in turn under
  5 s, blobs under `PART_TTL` 120 s, then `keep` to the daemon, which alone writes `blobs/`.
- Payments: voucher `bank`, `to`, `cents`, `nonce`, `sig` under `weft/voucher/1`, 256 bytes, spent
  once. `receipt`: `relay`, sorted `records` 1 to 64 also in `refs`, `until`, `voucher`; pays for any
  author's records present; `ceil(bytes/1024) * days * rate`, 366 days max. The voucher is version
  1's rail; a real one replaces it behind `Relay::settle`.
- Login: kind `login`, body the challenge (`service`, `nonce` bytes(32), `expires` after `created`),
  `refs` empty, never stored or relayed, grantable. Proof is `login` plus an optional `manifest`, at
  most 64 KiB, base64url in `weft:login?c=`; highest `seq` manifest wins.

## Gotchas that cost time

- Tauri ignores child web view positions on Linux; see `frame` and `pack`. WebKit routes only
  `weft://blob/<address>` to the scheme handler. reqwest `rustls-no-provider` needs `ring` installed.
- iroh `presets::N0` needs internet; `Endpoint::online` never returns with relays disabled. Tests
  use `presets::Minimal`, `RelayMode::Disabled`, and `MemoryLookup` over loopback. The iroh-blobs
  downloader dials by id alone; `Client::download` connects with the entry's addresses first. A
  socket path over 107 bytes fails with `SUN_LEN`. rpassword reads `/dev/tty`, never a pipe. redb
  holds one process lock per file: the store index stays in memory because the CLI writes beside the
  daemon, and a test that restarts the gateway drops the old one first.
- hickory's `Resolver` never asks for the AD bit; `weft-resolve::Dns` builds it, and `Dns::udp` under
  `cfg(test)` uses a loopback UDP fake that must echo the query. hickory 0.26 reports NXDomain and an
  empty answer as `NoRecordsFound` carrying `negative_ttl`.
- `Local` retries an idle close once, a bare `Client` does not. `println!` panics on EPIPE under
  `panic = "abort"`; the CLI prints through `say!`. `weft login sign` takes the `c=` value alone;
  post a bare proof as `text/plain`. The keystore's `expires` sits under the AEAD tag, so `retire`
  needs the passphrase. Relay `put` order: manifests, records, receipts. `iroh-blobs` 0.103 drops
  blobs only through `Options.gc` on `FsStore::load_with_opts`, after one whole interval.

## Verify before commit

Every flag section of `README.md` is a runnable transcript; `npm ci --prefix crates/browser/ui` first in a fresh worktree. `vectors/` regenerate only on a format change: `cargo run -p weft-core --example vectors`.
```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets
cargo test --workspace && cargo deny check && npm run --prefix crates/browser/ui check
grep -rnP '[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}]' README.md docs progress crates --exclude-dir=node_modules
grep -rn '//' crates --include='*.rs' --include='*.ts' --exclude-dir=node_modules --exclude-dir=dist | grep -v '://'
```

## Parallel
Nothing in flight. Shared files are edited only at close; conflict rules are in the `milestone` skill.
