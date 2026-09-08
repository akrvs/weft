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

![status](https://img.shields.io/badge/status-M11-yellow)
![category](https://img.shields.io/badge/category-Protocol%20%2F%20Identity-9cf)
![difficulty](https://img.shields.io/badge/difficulty-Insane-critical)
![rust](https://img.shields.io/badge/rust-1.85%2B-orange)
![tests](https://img.shields.io/badge/tests-81%20passing-brightgreen)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-brightgreen)

```
┌─[ TARGET ]──────────────────────────────────────────────────────┐
│ codename   : weft                                               │
│ category   : Application layer for a new internet               │
│ stack      : Rust · Ed25519 · blake3 · CBOR · iroh · Tauri 2    │
│ interfaces : core · home · net · resolve · store · CLI · relay  │
│              gateway · browser · bank                           │
│ flags      : user [sign here, fetch there, no shared server]    │
│              root [one address bar for both webs]               │
│              bridge [same page in Firefox and in Weft]          │
│              store [revoke a grant and watch access end]        │
│              pay [a few cents to host a stranger's page]        │
│              login [no account, no password, one signature]     │
│              gate [the browser signs nothing, the daemon does]  │
│              reads [the browser opens no record or blob file]   │
│ status     : M9 — spec frozen · 10 crates · one gate · one door │
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

Eight milestones in: the record format, the identity model, one
verification choke point, a relay that moves records and blobs between
machines over iroh QUIC, a browser that opens signed records and the old
web in the same window, a DNS registry that binds a domain to a key, a
gateway that serves signed records to any browser, a store daemon that
lets applications in only through revocable grants, a login that is a
signature over a challenge instead of an account, and a relay that pins a
stranger's page for a few cents and sweeps it when the pin runs out. The
relay is a cache with a contract. The browser trusts nothing it has not
verified itself and
says so on every page.

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

## [ Bridge Flag ] — same page in Firefox and in Weft

A publisher adopts Weft with one TXT record:

```
_weft.example.com.  TXT  "weft=<root address>"
```

```bash
weft dns example.com                         # bound key, dnssec verified or unverified
weft-browser example.com/blog                # domain tier in the address bar
weft-store serve --device laptop             # the gateway reads through the daemon
weft-gateway --bind 127.0.0.1:8080           # then open http://127.0.0.1:8080/example.com/blog
```

The lookup goes over DNS over HTTPS to Cloudflare, or to `WEFT_DOH=ip,name`,
and the resolver's DNSSEC verdict rides along as provenance. The gateway
serves every form the address bar takes, `/<address>`, `/<author>/<name>`,
`/<domain>/<name>`, with the signature check in a header bar and in
`x-weft-*` response headers. Every record and blob comes over the store
socket; with the daemon stopped every page is a 503. Plain HTTP on
loopback by default; TLS is the reverse proxy's job.

## [ Store Flag ] — revoke a grant and watch access end

Applications do not get a database of users. They get a key and a grant.

```bash
weft-store serve --device laptop              # the store daemon, socket at $WEFT_HOME/store.sock
WEFT_APP_PASSPHRASE='...' weft-app key        # an application key, prints its address
weft grant add <app> --kind note --read --write --as laptop
weft-app write note today.md                  # the daemon signs it as you, with the laptop key
weft-app read note                            # every note you hold, verified
weft grant revoke <grant> --as laptop         # or the revoke button in the browser's store view
weft-app read note                            # refused: no active grant
weft-browser                                  # compose, revoke, log in: no passphrase, the daemon signs
```

A grant is a signed record naming an application key, the kinds it may
read or write, and an optional expiry. A revoke is a signed record citing
it. The daemon checks the grants active at the moment of every request, so
revoking one ends access on the next request of an open connection. Writes
go through the daemon's device key and the local manifest, reads cover
only your own verified records, and `manifest`, `pointer`, `grant`, and
`revoke` can never be granted. The browser's store view lists your kinds
and your active grants with a revoke form.

The browser and the gateway are the daemon's privileged clients.
`weft-store serve` writes a fresh `browser.key` next to the socket on
every start; the browser presents it and asks the daemon to sign pages,
pointers, revokes, and logins, the gateway presents it to read. Neither
opens the keystore or the record directory. Applications asking for the
same requests are refused with `browser only`.

Since M9 the browser never opens the record or blob directory either.
Every record, manifest, pointer, and blob it renders comes over the
socket, blobs in 512 KiB chunks hashed whole on arrival, and every record
it fetches from a relay goes back to the daemon, which verifies before it
keeps. The daemon itself parses each record file once and remembers each
verification per manifest, while still listing the directory on every
request so the command line's writes are seen, and drops what the
listing no longer shows. With no daemon running the browser says so and
opens the start form; the navigation that failed runs again once the
daemon is up, and the daemon's log is one click away in the store dialog:

```bash
weft-browser                                  # cold, no daemon
# <root>/home                                 # weft-store is not running, the start form opens
# laptop > passphrase > start store           # spawns weft-store serve --device laptop --attach, page renders
# store                                       # kinds, grants, daemon log
# close the browser                           # the daemon exits with it and removes its socket
```

## [ Pay Flag ] — a few cents to host a stranger's page

A relay stores what its allowlist pushes for free. Everyone else pays.

```bash
weft-relay rate 1 && weft-relay bank add <bank>   # cents per KiB per day, and who mints them
weft-bank init && weft-bank mint --to <relay id> --cents 4 --out v.bin
weft price                                        # every relay's rate and banks
weft push <page> <pointer>                        # rejected: payment required
weft push <page> <pointer> --pay v.bin --days 30  # a receipt rides in the batch, both records pin
weft receipts                                     # what you paid, to whom, until when
```

A voucher is a bank signed note naming the relay it can be redeemed at, a
few cents, and a nonce. A receipt is a record you sign naming the relay,
the records you want kept, a date, and the voucher. The relay checks the
bank, the spend, the date, and the price, then stores and pins. Every
minute it sweeps pins that have passed, along with heads and manifests
nothing holds up any more. Allowlisted authors are never swept, a voucher
spends once, and the relay still never signs. The rail is a faucet, on
purpose: the seam for real money is one function.
## [ Login Flag ] — no account, no password, one signature

```bash
weft-gateway --bind 127.0.0.1:8080          # GET /login issues a challenge and waits
weft-gateway --allow allow.txt              # one root address per line; unlisted identities get 403
weft login sign <challenge> --as laptop     # a proof: the signed challenge plus your manifest
weft-browser 'weft:login?c=<challenge>'     # or the consent dialog signs and posts it for you
weft grant add <app> --kind login --write --as laptop
weft-app login <challenge>                  # an application logs you in through the daemon
```

A challenge names the service origin, a fresh nonce, and an expiry. The
response is a record of kind `login` whose body is the challenge verbatim,
signed by a device the manifest authorizes, carried with that manifest so
any verifier can check it offline. The gateway matches the origin, the
nonce, and the clock, prefers the newest manifest it can find, opens a
session for the root address, and shows it. Sessions live in
`$WEFT_HOME/gateway/sessions`, mode 0600, so a gateway restart keeps
everyone logged in and logout still revokes. The `login` record itself is
stored nowhere; every store and every relay refuses it.

## [ Persistence ] — posture

- `#![forbid(unsafe_code)]` in every crate, clippy pedantic, `unwrap`
  and `panic` denied in library code.
- Strict Ed25519 verification, weak public keys rejected, domain separated
  signatures.
- Addresses carry a version byte and a blake3 checksum. Typos fail closed.
- The core crate does no I/O and takes no randomness. The CLI owns both.
- Wire frames are capped at 1 MiB, batches at 64 records, and every
  message is canonical CBOR with unknown fields rejected.
- The relay verifies before it stores, pulls blobs only for records it
  has already accepted, and never signs. Payment is settled in one
  function: relay key, trusted bank, unspent voucher, date window, price.
- The browser chrome runs under a CSP with no inline script, no remote
  origins, and images only from the local blob scheme. Raw HTML in a page
  is dropped, links are limited to `weft:` and `https:`, and the HTTPS
  web view is incognito and cannot navigate off `https:`.
- One grammar for names. A domain binds through exactly one `_weft` TXT
  record holding a key address; two records, a hash address, or a
  malformed value fail closed.
- The gateway answers GET and HEAD only, plus POST on `/login` and
  `/logout`, caps paths at 1 KiB, headers at 16 KiB, and login bodies at
  88 KiB, sends a CSP with no script and no remote origin, types blobs by
  magic bytes and serves everything else as an attachment.
- Logins bind the service origin and a single use nonce with a five minute
  life, session cookies are `HttpOnly` and `SameSite=Strict`, and the
  tables behind them are capped and swept. The session file is canonical
  CBOR with no unknown fields; a malformed file or allow list refuses to
  start.
- The gateway holds no record or blob path. Every read goes over the
  store socket under the browser key, so the daemon is the one process
  that opens signed state.
- The store daemon listens on a 0600 Unix socket, authenticates every
  connection with a fresh nonce signed under its own domain string,
  authorizes every request through one function against the grants active
  at that instant, and never hands out a record it has not verified. The
  browser's privilege is one key comparison in that same function.
- The browser holds no record or blob file. Every read for rendering
  crosses the socket and is verified again by the resolver, blobs are
  bounded per chunk and in total and hashed whole, and a record kept on
  the browser's behalf is verified by the daemon first. The daemon the
  browser starts takes its passphrase on a pipe, never on a command line,
  and cannot outlive the browser.
- `cargo-deny` gates advisories, licenses, and sources in CI.

## [ Loadout ]

```
crates/core/         weft-core: address · cbor · identity · record · manifest · pointer · grant · receipt · login · verify
crates/home/         weft-home: encrypted keystore · record store · snapshot cache that mirrors the directory · Reads trait · relay list
crates/net/          weft-net: wire · client · relay handler · pricing · pins · sweep · redb index
crates/resolve/      weft-resolve: target grammar · DNS over HTTPS · head resolution over any Reads · Markdown renderer
crates/store/        weft-store: store wire · gate · browser key per run · daemon with --attach · client · pooled Local reads · weft-app sample
crates/relay/        weft-relay: init · allow · rate · bank · price · serve
crates/bank/         weft-bank: init · whoami · mint
crates/gateway/      weft-gateway: hyper server over the store socket · provenance bar · x-weft headers · sessions on disk · allow list
crates/cli/          weft: commands over home, net, and resolve · grants · price · paid push · receipts · login
crates/browser/      weft-browser: Tauri 2 app over the store socket · start dialog · store view with daemon log · login dialog
docs/protocol.md     normative record spec
docs/relay.md        relay wire protocol
docs/store.md        store wire protocol
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

The roadmap is complete, the store daemon is hardened, and every reader
is behind it. What follows is open: blob pull on miss, a real payment
rail behind the voucher seam, blob collection on sweep, `weft:` as a
registered URL handler so a site's login link opens the browser, gateway
host based routing and TLS, browser visual design. See
[`progress/`](progress/).
