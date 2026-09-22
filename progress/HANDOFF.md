# Handoff

Read first, rewritten at every close, never appended, under 120 lines.

## Where we are

| | |
|---|---|
| Done | M0 spec and vectors, M1 core and CLI, M2 relay over iroh, M3 browser, M4 DNS bridge and gateway, M5 personal store and grants, M6 challenge response login, M7 payments experiment, M8 store as the single gate, M9 reads behind the gate, M10 store hardening, M11 gateway behind the gate, M12 reads that fetch, M13 fetch hardening, M14 gateway and relay operations, M15 relay hygiene, M16 loose ends, M17 operational loose ends, M18 every loose end but the browser, M19 the browser, M20 named links, blob totals, a driven smoke test, M21 a Lightning rail, the portal theme, login in the smoke, M22 social recovery, an open kind namespace, LND live, theme fallbacks, M23 Apache-2.0, the design status table, `v0.1.0` with a filmed demo |
| Next | Nothing scheduled. `BACKLOG.md` holds what is left, now including every design promise the code never grew; petnames and label lists are the first pair worth a milestone, both already reserved kinds |
| Repo | public, github.com/akrvs/weft, Apache-2.0, CI on every push, `v0.1.0` tagged with a release carrying `weft-0.1.mp4` and `.gif` from `crates/browser/demo.sh` |

## Crates

| Crate | Path | One line |
|---|---|---|
| weft-core | crates/core | Address, canonical CBOR, identity, record, manifest with `Guardians`, pointer, grant, revoke, receipt with a `Payment` of voucher or preimage, voucher with a base64url text form, login challenge and proof, `Recovery` with guardian `Signature`s and a `Message`, one `verify` |
| weft-home | crates/home | Encrypted keystore with `retire`, record store with an in memory index guarded by the directory mtime and a shared LRU cache under a byte cap, the one blob writer, part sweep, `Snapshot` returning `Arc<Record>` with `manifest_record` and `recovery_record` heads, `Reads` trait, `Relay` list entries with addresses and `from_key` |
| weft-net | crates/net | `Net` from `WEFT_NET`, relay wire protocol with `size`, `invoice`, and `recovery`, client with `Quote` and `Offer` that primes direct addresses before a blob download and reports pulled bytes with the total, relay handler with `Config` behind a lock, `reload`, pricing in cents with `sats` per cent, `Node` trait with `Fake`, open invoices, pins for any author, one rule sweep, blob GC, redb index with a recovery head per author |
| weft-resolve | crates/resolve | Target grammar with `Display`, DNS registry over DoH with a positive and negative TTL cache, `Resolver<R: Reads>` for records, heads, blobs, pulling from relays on a miss unless `offline`, `redirect` through recovery heads under `MAX_HOPS`, `metered`, `watched` for pull progress with totals, `title` of an author's home page, Markdown renderer with named links |
| weft-store | crates/store | Store gate over a Unix socket: wire, `Gate` over every held record, `names`, `point`, `receipt`, `recovery`, `stop` that ends `serve`, `Log` file, server, client, pooled `Local` reads, browser key per run, `weft-store serve` and `stop`, `weft-app` |
| weft-relay | crates/relay | Relay binary over a small lib: init, allow, deny, rate, sats, bank, `node fake` or `node lnd <url>`, price, serve through `Net` printing its list entry; SIGHUP rereads allow, banks, rate, sats and sweeps; `lnd.rs` is the LND REST adapter with a pinned certificate, `lnd.sh` a regtest network in containers, `tests/lnd.rs` the ignored live test |
| weft-bank | crates/bank | Faucet binary: init, whoami, mint vouchers to a file and as text |
| weft-gateway | crates/gateway | HTTP gateway binary over hyper and `Resolver<Local>`: any target the address bar takes, `Host` based routing for publisher domains, provenance headers, `/login` sessions and budget windows in `State` (redb), allow list, pulls for sessions only under `Limits`; SIGHUP rereads the allow list and sweeps sessions |
| weft | crates/cli | Commands over home, net, and resolve: device retire, `manifest --guardian --threshold`, `recover draft`, `sign`, `finish`, grants listed with app titles, price, `invoice`, push paid by voucher or `--preimage --relay` keeping the receipt only after accept, receipts, login, `resolve` following recoveries; prints through `say!`, quiet on a closed pipe |
| weft-browser | crates/browser | Tauri 2 app over `Resolver<Local>`: `light-dark()` tokens stamped from the portal, GSettings, or GTK, one line provenance panel, back and forward, history and bookmarks in `<home>/browser/`, compose with live preview, price table, invoice button and a pay field for voucher or preimage, store view with names and repoint, blob view with sniff and save, pull bar with a total, start form, login consent, `register` for `weft:` links on Linux, `drive` feature with a JavaScript socket, `drive.sh` helpers, `smoke.sh`, `demo.sh` filming the loop into `target/demo/`, `tests/drift.rs` |

## Frozen decisions

- Ed25519 strict, blake3, RFC 8949 deterministic CBOR subset with no booleans, no unknown fields. Manifests and the
  `manifest` pointer are root signed only, device keys sign the rest, revocation retroactive; a lost key is retired:
  `weft device retire` sets `expires`, earlier records stand. Pointers carry a Lamport `seq` per author and name and
  cite prior heads; head order is `seq`, `created`, address. Kinds are an open namespace, 1 to 32 bytes of `a-z0-9_`;
  only the kinds `protocol.md` section 9 names carry rules, and the reserved ones are never grantable.
- Recovery (`protocol.md` 13): guardians are other identities' root keys named in the manifest with a threshold; a
  `recovery` record is authored by the lost root and signed by the new one, and `verify` alone checks the guardian
  signatures, skipping device authorization for this kind only. Head is the pointer rule. Resolvers `redirect` at most
  4 hops, a fifth or a cycle is `Error::Hops`, raw addresses never redirect. Relay and store answer `recovery { author }`
  with the head. Recovery replaces a lost root, never a compromised one; guardians sign with their root through the CLI.
- Endpoints bind through one `Net`: `WEFT_NET` unset is `presets::N0`, `local` is `presets::Minimal` with mDNS as
  `weft`, else an error. Relay entries are `<id>` or `<id>@<host:port>[,...]`, at most 8 addresses dialed directly.
- Relay is a cache with a contract: allowlisted authors push, payers pin any records present, anyone reads, the relay
  never signs. Blobs are pulled after acceptance. `allow`, `banks`, `rate`, `sats` are one `Config` read at start and
  on SIGHUP, a bad file keeps the old one; `node` is read at start only. The sweep, every 60 s and after a reload,
  keeps a record only if its author is allowlisted, it holds a live pin, or it is the manifest of a pinned author;
  stale heads and expired invoices go too, and the `iroh-blobs` GC runs on the same interval. Pages are CommonMark, no
  raw HTML, links `https:` or `weft:` plus any `Target`, images blob addresses only. `size` answers `bytes` for a
  complete blob, else absent; the client asks once before a download.
- Address bar grammar lives in `Target`: raw address, `author/name`, `domain`, `domain/name`; a bare domain opens
  `home`. DNS: `_weft.<domain>` TXT `weft=<key address>`, exactly one, over DoH to Cloudflare unless `WEFT_DOH=ip,name`,
  DNSSEC reported only, cached per process for 1024 hosts with the TTL clamped to 60 s to 3600 s. NXDomain, an empty
  answer, two records, and a malformed value are misses; other failures are errors.
- Gateway: plain HTTP on an explicit bind, GET and HEAD plus POST `/login` and `/logout`, no script, TLS is a reverse
  proxy's job. A foreign `Host` is a publisher host whose `/` is its `home`; challenges name `<scheme>://<host>`. Reads
  go over the store socket through `Local`: stopped daemon 503, anonymous reads `offline`, miss or too many hops 404.
  Only a session pulls, under `--pulls` (4, then 429) and `--budget` MiB (64) per root per fixed hour, then offline with
  the reset time in the 404. Sessions and windows are rows in `<home>/gateway/state.redb` 0600 under `--sessions` and
  `--identities` (4096); a bad file refuses to start; challenges cap at 1024; `--allow` lists one root per line.
- Grants (`protocol.md` 10): device signed allowed, reserved kinds never grantable, active means valid, unexpired, not
  revoked, checked at every request; reads cover every held verified record of the kind, writes stay the root's.
- The store is a daemon on `<home>/store.sock` 0600, idle connections closed at 60 s. The browser key is
  `<home>/browser.key`, 32 random bytes 0600, fresh at every `serve`, pooled 4 deep by `Local`; that key alone may use
  `names`, `point`, `receipt` (signs a checked body, stores nothing), `recovery`, `stop`. `serve` reads the passphrase
  from a non terminal stdin, `--attach` exits on EOF, logs to `<home>/store.log` rotated at 1 MiB, `--cache <MiB>` (256).
- Blobs cross the socket by `offset` in 512 KiB chunks, at most 1 GiB, hashed whole by the resolver, which reads only
  through `weft_home::Reads`, verifies every candidate, alone binds the client, and pulls each relay under 5 s, blobs
  under `PART_TTL` 120 s, then `keep`s; `offline()` turns pulls off, `watched()` reports bytes and the total.
- Payments (`protocol.md` 11, `relay.md`): two rails, a bank voucher or the preimage of an invoice the relay issued; the
  payment id spends once and pays for any author's records present, `ceil(bytes/1024) * days * rate`, 366 days max.
  Open invoices live `INVOICE_TTL` 3600 s, at most 4096; a preimage settles against that table alone and the node is
  asked only to issue `cents * sats * 1000` msat; `price` carries `sats`, 0 when no node. `Fake` writes preimages to
  `data/preimages/<hex hash>` 0600. LND: `lnd.macaroon` (invoice macaroon) and `lnd.pem` in the relay dir, the
  certificate pinned byte for byte, https only; run against LND 0.19.2 in regtest through `lnd.sh`, never in CI.
- Login (`protocol.md` 12): never stored or relayed, grantable; the proof carries the record and an optional manifest.
- Browser state: `<home>/browser/history` (`<unix>\t<target>`, 1024 lines, adjacent repeats dropped) and `bookmarks`
  (`<target>\t<title>`, one per target), directory 0700, files 0600, rewritten whole. Blobs sniffed by magic: PNG, JPEG,
  GIF, WebP render; UTF-8 under 64 KiB without NUL renders as text; the rest shows size and a save button writing
  `<downloads>/<address>` with `create_new` under `$XDG_DOWNLOAD_DIR`, `user-dirs.dirs`, then `~/Downloads`.
  `weft-browser register` is Linux only and explicit: `weft.desktop` and an icon, then `xdg-mime default`. Theme follows
  the system, no toggle: `light-dark()` tokens under `color-scheme: light dark`; on Linux `theme.rs` picks one `Source`
  at start, the portal's `color-scheme` when it answers, else GSettings `org.gnome.desktop.interface color-scheme` when
  the schema has the key (`default` defers to GTK), else GTK `gtk-application-prefer-dark-theme`; it stamps `data-theme`
  and follows that source's signal. No source, no stamp.

## Gotchas that cost time

- Tauri ignores child web view positions on Linux; see `frame` and `pack`. WebKit routes only `weft://blob/<address>`
  to the scheme handler. reqwest `rustls-no-provider` needs `ring` installed. LND's self signed certificate is
  `CA:TRUE`, which webpki refuses as a leaf (`CaUsedAsEndEntity`), hence the pinned `ServerCertVerifier` through
  `use_preconfigured_tls`. `gio::Settings` and `gtk::Settings` are not `Send`, so `theme.rs` keeps its `Source` in a
  `thread_local`. Tauri embeds `crates/browser/ui` at compile time: `npm ci`, `npm run build`, then `cargo build`; a
  missing `tsc` fails `npm run check` without the word error. WebKitGTK 2.52 here renders `prefers-color-scheme: dark`
  whatever the portal says, hence the portal read in Rust; `gio` lacks `v2_72`, so `connect_g_signal` takes no detail.
- iroh `presets::N0` needs internet; `Endpoint::online` never returns with relays disabled. Tests use
  `presets::Minimal`, `RelayMode::Disabled`, and `MemoryLookup` over loopback. The iroh-blobs downloader dials by id
  alone and reports offsets, never a total, hence `size`; `Client::download` connects with the entry's addresses
  first. A socket path over 107 bytes fails with `SUN_LEN`, so smoke homes live under `$XDG_RUNTIME_DIR`. rpassword
  reads `/dev/tty`, never a pipe. redb locks per file and a read fails on a table never created, so `Index::open`
  opens every table once. The CBOR subset has no boolean: flags on the wire are `uint`. `docker` here is podman's
  emulation; `lnd.sh` takes `WEFT_OCI` for either. hickory's `Resolver` never asks for the AD bit; `weft-resolve::Dns`
  builds it, and `Dns::udp` under `cfg(test)` uses a loopback UDP fake that must echo the query. hickory 0.26 reports
  NXDomain and an empty answer as `NoRecordsFound` with `negative_ttl`. `Local` retries an idle close once, a bare
  `Client` does not. `println!` panics on EPIPE under `panic = "abort"`; the CLI uses `say!`. `iroh-blobs` 0.103 drops
  blobs only through `Options.gc` on `FsStore::load_with_opts`. No WebKitWebDriver on Arch, `/dev/uinput` root only:
  `cargo build -p weft-browser --features drive`, then `WEFT_DRIVE=<socket>` evaluates one JavaScript expression per
  connection, `{"ok":..}` or `{"err":..}` back; `drive` polls a `window.__drive<n>` slot, `eval_with_callback` returns early.
  `smoke.sh` is the transcript and refreshes the screenshots; Hyprland tiles new windows, so `demo.sh` floats one via `hyprctl`.

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
