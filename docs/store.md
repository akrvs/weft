# Weft store protocol, version 1

The personal store is a daemon. Applications never touch the record
directory; they hold a key, present it over a local socket, and get
exactly what an active grant by the store's owner allows at that moment.
The browser is the daemon's one privileged client: it holds the key at
`<home>/browser.key` and signs nothing itself.

## Browser key

`weft-store serve` writes `<home>/browser.key` on its first start: 32
seed bytes, mode 0600, created with `create_new` so a second daemon never
overwrites it. The daemon treats exactly that public key as privileged.
Every other key is an application under grants.

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
