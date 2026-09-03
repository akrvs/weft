# Weft relay protocol, version 1

A relay stores records and blobs for allowlisted authors and serves them
to anyone. It never signs anything and clients re-verify everything they
receive.

## Transport

iroh QUIC connections. ALPN `weft/relay/1` for records, the iroh-blobs
ALPN for blob transfer on the same endpoint. One request and one response
per bidirectional stream. A connection may carry many streams in sequence.

## Framing

```
length(4, big endian) || canonical CBOR
```

A frame is at most 1 MiB. Canonical CBOR follows `protocol.md` section 2.
Every message is a map with a text field `t` naming its type and no
unknown fields.

## Requests

| `t` | Fields | Limits |
|---|---|---|
| `put` | `records`: array of record bytes | at most 64 records |
| `get` | `address`: bytes(32) | |
| `head` | `author`: bytes(32), `name`: text | name 1 to 64 bytes |

## Responses

| `t` | Fields |
|---|---|
| `put` | `stored`: array of bytes(32); `rejected`: array of `[index, reason]` |
| `get` | `record`: bytes, absent when unknown |
| `head` | `pointer`: bytes, absent when unknown; `manifest`: bytes, absent when unknown |
| `error` | `why`: text |

`head` always returns the newest manifest the relay holds for the author,
whatever the name. Asking for the reserved name `manifest` is the way to
fetch only the manifest.

## Rules on put

1. Records that do not parse are rejected by index.
2. Manifests in a batch are processed first so the records that follow
   verify against them.
3. The author must be on the relay's allowlist.
4. Each record passes the verification procedure in `protocol.md`
   section 7 against the newest manifest the relay holds.
5. A record whose body is a blob is stored only after the relay has
   downloaded the blob from the pushing endpoint over iroh-blobs and the
   hash has verified.
6. A manifest replaces the author's newest manifest only when its `seq`
   is higher. A pointer replaces the head for its author and name only
   when it wins the ordering in `protocol.md` section 6.

## Storage

Records and indexes live in a redb database with three tables: records by
address, heads by author and name, newest manifest by author. Blobs live
in an iroh-blobs file store beside it.
