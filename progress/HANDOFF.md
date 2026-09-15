# Handoff

Read first, rewritten at every close, never appended, under 120 lines.

## Where we are

| | |
|---|---|
| Done | M0 spec and vectors, M1 core and CLI, M2 relay over iroh, M3 browser, M4 DNS bridge and gateway, M5 personal store and grants, M6 challenge response login, M7 payments experiment, M8 store as the single gate, M9 reads behind the gate, M10 store hardening, M11 gateway behind the gate, M12 reads that fetch, M13 fetch hardening, M14 gateway and relay operations, M15 relay hygiene, M16 loose ends, M17 operational loose ends, M18 every loose end but the browser, M19 the browser |
| Next | Nothing scheduled. `BACKLOG.md` holds what is left; the roadmap in `design.md` is complete |
| Repo | private, github.com/akrvs/weft, CI on push to main, license deferred |

## Crates

| Crate | Path | One line |
|---|---|---|
| weft-core | crates/core | Address, canonical CBOR, identity, record, manifest, pointer, grant, revoke, receipt, voucher with a base64url text form, login challenge and proof, one `verify` |
| weft-home | crates/home | Encrypted keystore with `retire`, record store with an in memory index guarded by the directory mtime and a shared LRU cache under a byte cap, the one blob writer, part sweep, `Snapshot` returning `Arc<Record>`, `Reads` trait, `Relay` list entries with addresses and `from_key` |
| weft-net | crates/net | `Net` from `WEFT_NET`, relay wire protocol, client that primes direct addresses before a blob download and reports pulled bytes, relay handler with `Config` behind a lock, `reload`, pricing, pins for any author, one rule sweep, blob GC, redb index |
| weft-resolve | crates/resolve | Target grammar, DNS registry over DoH with a positive and negative TTL cache, `Resolver<R: Reads>` for records, heads, blobs, pulling from relays on a miss unless `offline`, `metered`, `watched` for pull progress, `title` of an author's home page, Markdown renderer |
| weft-store | crates/store | Store gate over a Unix socket: wire, `Gate` over every held record, `names`, `point`, `receipt`, `stop` that ends `serve`, `Log` file, server, client, pooled `Local` reads, browser key per run, `weft-store serve` and `stop`, `weft-app` |
| weft-relay | crates/relay | Relay binary: init, allow, deny, rate, bank, price, serve through `Net` printing its list entry; SIGHUP rereads allow, banks, rate and sweeps |
| weft-bank | crates/bank | Faucet binary: init, whoami, mint vouchers to a file and as text |
| weft-gateway | crates/gateway | HTTP gateway binary over hyper and `Resolver<Local>`: any target the address bar takes, `Host` based routing for publisher domains, provenance headers, `/login` sessions and budget windows in `State` (redb), allow list, pulls for sessions only under `Limits`; SIGHUP rereads the allow list and sweeps sessions |
| weft | crates/cli | Commands over home, net, and resolve: device retire, grants listed with app titles, price, paid push that keeps the receipt only after accept, receipts, login; prints through `say!`, quiet on a closed pipe |
| weft-browser | crates/browser | Tauri 2 app over `Resolver<Local>`: light and dark tokens, one line provenance panel, back and forward, history and bookmarks in `<home>/browser/`, compose with live preview, price table and voucher pay, store view with names and repoint, blob view with sniff and save, pull bar from `pull` events, start form, login consent, `register` for `weft:` links on Linux |

## Frozen decisions

- Ed25519 strict, blake3, RFC 8949 deterministic CBOR subset, no unknown fields. Manifests and the
  `manifest` pointer are root signed only, device keys sign the rest, revocation retroactive; a lost
  key is retired, `weft device retire` sets its `expires` and earlier records stand. Pointers carry a
  Lamport `seq` per author and name and cite prior heads; head order is `seq`, `created`, address.
- Endpoints bind through one `Net`: `WEFT_NET` unset is `presets::N0`, `local` is `presets::Minimal`,
  no iroh relay, mDNS lookup as `weft`; anything else is an error. A relay list entry is `<id>` or
  `<id>@<host:port>[,...]`, at most 8 addresses, dialed directly, one entry per id; serve prints its own.
- Relay is a cache with a contract: allowlisted authors push, payers pin any records present, anyone
  reads, the relay never signs. Blobs are pulled after acceptance. `allow`, `banks`, `rate` are one
  `Config` read at start and on SIGHUP; a bad file keeps the old one. The sweep, every 60 s and after
  a reload, keeps a record only if its author is allowlisted, it holds a live pin, or it is the
  manifest of a pinned author; stale heads go too, and the `iroh-blobs` GC runs on the same interval.
  Pages are CommonMark, no raw HTML, a fixed element set; links `weft:<address>` or `https:` only.
- Address bar grammar lives in `Target`: raw address, `author/name`, `domain`, `domain/name`; a bare
  domain opens `home`; domains are lowercase ASCII labels with a dot. DNS: `_weft.<domain>` TXT
  `weft=<key address>`, exactly one, over DoH to Cloudflare unless `WEFT_DOH=ip,name`, DNSSEC
  reported only. Cache per process, 1024 hosts, TTL clamped 60 s to 3600 s. NXDomain, an empty
  answer, two records, and a malformed value are misses; other failures are errors, never cached.
  No public domain carries a record yet; the positive path is tested on the fake.
- Gateway: plain HTTP on an explicit bind, default loopback, GET and HEAD plus POST `/login` and
  `/logout`, no script, TLS is a reverse proxy's job. A `Host` other than the origin's is a publisher
  host: `/` is its `home`, a bare path its name; login challenges name `<origin scheme>://<host>`, a
  bad host is 400. Reads go over the store socket through `Local`, a stopped daemon answers 503.
  Anonymous requests read `offline`, a miss is 404. A session pulls under `--pulls` (4), past it 429,
  within `--budget` MiB (64, 0 unlimited) per root per fixed hour, then offline with the reset time in
  the 404. Sessions and budget windows are rows in `<home>/gateway/state.redb` mode 0600, at most
  `--sessions` and `--identities` (4096, no ceiling); a bad file refuses to start. Pending challenges
  cap at 1024. `--allow`: one root address per line, reread on SIGHUP with a session sweep.
- Grants: body `app`, sorted `kinds` 1 to 16, `access` 1 read 2 write 3 both, optional `expires`;
  `revoke` cites the grant in body and `refs`. Device signed allowed; reserved kinds never grantable.
  Active means valid, unexpired, not revoked, checked at every request. Reads cover every held record
  of the kind verified against its author's manifest; writes stay the root's. Apps show their `home` title.
- The store is a daemon on `<home>/store.sock` mode 0600 speaking `docs/store.md`, idle connections
  closed at 60 s. Writes are signed by the daemon's device key and verified against the manifest.
  The browser and the gateway are its privileged clients through `<home>/browser.key`, 32 seed bytes
  mode 0600, fresh at every `serve`, pooled 4 deep by `Local`; that key alone may use the browser
  only requests: `names` lists head pointers, `point` signs and stores the next pointer at a held
  verified record, `receipt` signs a checked receipt body without storing it, `stop` ends serve.
  `serve` reads the passphrase from a non terminal stdin, `--attach` also exits on EOF, then logs to
  `<home>/store.log` mode 0600, rotated at 1 MiB. `--cache <MiB>` (256, 0 unlimited) bounds the cache.
- Blobs cross the socket by `offset` in chunks of at most 512 KiB, total at most 1 GiB, hashed whole
  by the resolver, which reads only through `weft_home::Reads`, verifies every candidate, alone binds
  the client; `offline()` turns pulls off, `watched()` reports pulled bytes. Reads pull on a miss, each
  relay in turn under 5 s, blobs under `PART_TTL` 120 s, then `keep` to the daemon, the one blob writer.
- Payments: voucher `bank`, `to`, `cents`, `nonce`, `sig` under `weft/voucher/1`, 256 bytes, spent
  once, text form base64url without padding. `receipt`: `relay`, sorted `records` 1 to 64 also in
  `refs`, `until`, `voucher`; pays for any author's records present; `ceil(bytes/1024) * days *
  rate`, 366 days max; the voucher is version 1's rail. Login: kind `login`, body the challenge
  (`service`, `nonce` bytes(32), `expires` after `created`), `refs` empty, never stored or relayed,
  grantable; proof is `login` plus an optional `manifest`, 64 KiB, base64url in `weft:login?c=`.
- Browser state: `<home>/browser/history` (`<unix>\t<target>`, 1024 lines, adjacent repeats dropped)
  and `bookmarks` (`<target>\t<title>`, one per target), directory 0700, files 0600, rewritten whole.
  Blobs sniffed by magic: PNG, JPEG, GIF, WebP render; UTF-8 under 64 KiB without NUL renders as
  text; the rest shows size and a save button writing `<downloads>/<address>` with `create_new`,
  downloads from `$XDG_DOWNLOAD_DIR`, `user-dirs.dirs`, then `~/Downloads`. `weft-browser register`
  is Linux only and explicit: `weft.desktop` and an icon under `$XDG_DATA_HOME`, then `xdg-mime
  default`. A second launch is a second process. Theme follows the system, no toggle.

## Gotchas that cost time

- Tauri ignores child web view positions on Linux; see `frame` and `pack`. WebKit routes only
  `weft://blob/<address>` to the scheme handler. reqwest `rustls-no-provider` needs `ring` installed.
  Tauri embeds `crates/browser/ui` at compile time: `npm run build` before `cargo build`. WebKitGTK's
  `prefers-color-scheme` follows the desktop portal on Hyprland, not `GTK_THEME` or gsettings.
- iroh `presets::N0` needs internet; `Endpoint::online` never returns with relays disabled. Tests
  use `presets::Minimal`, `RelayMode::Disabled`, and `MemoryLookup` over loopback. The iroh-blobs
  downloader dials by id alone and reports offsets, never a total; `Client::download` connects with
  the entry's addresses first. A socket path over 107 bytes fails with `SUN_LEN`, so smoke homes
  live under `$XDG_RUNTIME_DIR`. rpassword reads `/dev/tty`, never a pipe. redb holds one process
  lock per file: the store index stays in memory, a gateway test restart drops the old one first.
- hickory's `Resolver` never asks for the AD bit; `weft-resolve::Dns` builds it, and `Dns::udp` under
  `cfg(test)` uses a loopback UDP fake that must echo the query. hickory 0.26 reports NXDomain and an
  empty answer as `NoRecordsFound` carrying `negative_ttl`. `Local` retries an idle close once, a
  bare `Client` does not. `println!` panics on EPIPE under `panic = "abort"`; the CLI uses `say!`.
  `weft login sign` takes the `c=` value alone; post a bare proof as `text/plain`. `retire` needs the
  passphrase. Relay `put` order: manifests, records, receipts. `iroh-blobs` 0.103 drops blobs only
  through `Options.gc` on `FsStore::load_with_opts`. The renderer drops a `weft:author/name` link.

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
