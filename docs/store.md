# Weft store protocol, version 1

The personal store is a daemon. Applications never touch the record
directory; they hold a key, present it over a local socket, and get
exactly what an active grant by the store's owner allows at that moment.
The browser and the gateway are the daemon's privileged clients: they
hold the key at `<home>/browser.key` and sign nothing themselves.

## Browser key

`weft-store serve` writes a fresh `<home>/browser.key` on every start,
after it holds the socket: 32 seed bytes, mode 0600, written to a
temporary file and renamed into place. The key lives exactly as long as
one daemon run. The key means a process on this host with access to the
home directory; the browser and the gateway both read it when they
connect, so they follow a restart on their next request. The daemon
treats exactly that public key as privileged. Every other key is an
application under grants. Nothing but the daemon opens `records/` or
`blobs/`; with the daemon stopped the gateway answers 503.

## Transport

A Unix domain socket at `<home>/store.sock`, mode 0600. One connection
carries one authenticated application and any number of requests in
sequence. A connection idle for 60 seconds is closed.

## Framing

```
length(4, big endian) || canonical CBOR
```

A frame is at most 1 MiB. Every message is a map with a text field `t`
naming its type and no unknown fields. Canonical CBOR follows
`protocol.md` section 2.

## Handshake

The store speaks first.

| Direction | `t` | Fields |
|---|---|---|
| store to app | `hello` | `nonce`: bytes(32), fresh per connection |
| app to store | `auth` | `app`: bytes(32) public key; `sig`: bytes(64) |
| store to app | `ok` | |

```
sig = Ed25519.sign(app, "weft/store/1" || 0x00 || nonce)
```

Any other first request, or a signature that does not verify, is
answered with `error` and the connection is closed.

## Requests

| `t` | Fields | Limits |
|---|---|---|
| `list` | `kind`: text | a valid kind name |
| `get` | `address`: bytes(32) | |
| `put` | `kind`: text; `body`: bytes; `refs`: array of bytes(32) | body at most 65536 bytes, at most 1024 refs |
| `login` | `challenge`: bytes | a canonical challenge from `protocol.md` section 12, at most 1024 bytes |
| `kinds` | | browser only |
| `grants` | | browser only |
| `revoke` | `grant`: bytes(32) | browser only |
| `publish` | `body`: bytes; `name`: text, optional | browser only, body at most 65536 bytes, name 1 to 64 bytes |
| `record` | `address`: bytes(32) | browser only |
| `manifest` | `author`: bytes(32) | browser only |
| `pointers` | `author`: bytes(32); `name`: text | browser only, name 1 to 64 bytes |
| `blob` | `address`: bytes(32); `offset`: uint | browser only, offset at most 1 GiB |
| `keep` | `record`: bytes | browser only, at most 131072 bytes |
| `keep-blob` | `address`: bytes(32); `total`: uint; `offset`: uint; `chunk`: bytes | browser only, total and offset at most 1 GiB, chunk at most 524288 bytes |

## Responses

| `t` | Fields |
|---|---|
| `list` | `addresses`: array of bytes(32), sorted |
| `get` | `record`: bytes |
| `put` | `address`: bytes(32) |
| `login` | `proof`: bytes |
| `kinds` | `kinds`: array of [`kind`: text, `count`: uint], sorted by kind |
| `grants` | `records`: array of bytes, the active grant records |
| `publish` | `records`: array of bytes, the page then the pointer |
| `records` | `records`: array of bytes |
| `blob` | `total`: uint, the blob length; `chunk`: bytes, at most 524288 |
| `missing` | |
| `error` | `why`: text |

Arrays in a response hold at most 4096 entries.

## Rules

- Before every request the store reads its records and computes the
  grants active now for the authenticated key: valid, unexpired, and not
  cited by a valid revoke. Revoking a grant ends access on the next
  request of an open connection.
- `list` and `get` cover only records whose author is the store's root
  and which verify against the newest local manifest. `get` refuses a
  record whose kind the key may not read, and answers the same way for a
  record that does not exist.
- `put` signs a record as the store's root with the store's device key,
  verifies it against the local manifest, and stores it. A device the
  manifest does not authorize cannot write.
- Reserved kinds `manifest`, `pointer`, `grant`, and `revoke` are never
  readable or writable through a grant.
- `login` needs a grant covering kind `login` with write access. The store
  signs the challenge as its root with its device key, verifies the record
  against the local manifest, and returns a proof holding the record and
  the manifest record. Nothing is stored; a `put` of kind `login` is
  refused.
- The browser key skips the grant lookup on `list`, `get`, `put`, and
  `login`. Reserved kinds stay refused on `list` and `put` for every key.
- `kinds`, `grants`, `revoke`, and `publish` answer `refused: browser only`
  for any other key. `kinds` counts the root's verified records per kind.
  `grants` returns the grant records active now. `revoke` refuses a grant
  that is not active, otherwise signs and stores a `revoke` citing it and
  answers `put`. `publish` signs a `page` record and, when `name` is
  given, a pointer for it with the next `seq` and the current head as
  `prev`, stores both, and returns them. The store never pushes to a
  relay; the browser does.
- `record`, `manifest`, `pointers`, `blob`, `keep`, and `keep-blob` are
  the browser's reads for rendering and answer `refused: browser only` for any other
  key. They cover every author the store holds, not only the root.
  `record` answers `get` with the record at that address or `missing`.
  `manifest` answers `get` with the newest valid manifest record by that
  author or `missing`. `pointers` answers `records` with the pointer
  records of that author and name that verify against the author's
  newest local manifest. The browser verifies again what it renders.
- `blob` answers `blob` with the total length and the bytes from `offset`
  up to 524288 of them, or `missing`. An offset past the end is refused.
  The client asks again from the end of the last chunk until it holds
  `total` bytes, refuses a `total` above 1 GiB or one that changes, and
  the reader checks the blake3 hash of the whole against the address.
- `keep` stores a record the browser fetched from a relay. The store
  verifies it first: a manifest against nothing, anything else against
  the newest local manifest for its author. What does not verify is
  refused, and a `login` record is refused as always.
- `keep-blob` stores a blob the browser pulled from a relay, one chunk
  per request, each answered `ok`. `offset` 0 starts
  `<home>/blobs/<address>.part` afresh; any other offset must equal the
  part's length, and `offset + len(chunk)` may not pass `total`. An empty
  chunk is refused unless it completes the blob. When the part reaches
  `total` the store hashes it: a match moves it to `<home>/blobs/<address>`,
  anything else is refused and the part removed. A blob already present
  answers `ok` without writing. The hash check is the one door into the
  blob directory; the command line's own writes go through it too. Parts
  do not outlive their pull: `serve` removes every `.part` before it binds
  the socket, and every listing removes parts untouched for 120 s, the
  blob pull timeout.

## Index

The store lists its record directory on every request and parses only
files it has not seen, keyed by the address in the file name. A file
whose content does not hash to its name is ignored. Verification
outcomes are remembered per record and manifest, so a record is checked
once per manifest. Each listing drops cached records whose file is gone
and outcomes for manifests no longer on disk, so the cache never
outgrows the directory. Other writers to the same directory, such as the
command line, are seen on the next request.

## Attach

`weft-store serve --device <label> --attach` reads the passphrase as the
first line of standard input and exits when standard input closes. The
browser starts the daemon this way with a pipe it holds until it exits,
so the daemon lives exactly as long as the browser. Without `--attach`
the daemon prompts on the terminal and runs until it is stopped. The
browser drains the daemon's standard error into a ring of the last 16 KiB
and shows it in the store dialog; a failed start reports that text. The
browser's `Local` reads keep up to four idle connections to the daemon
and open more as requests overlap.
