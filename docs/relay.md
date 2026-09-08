# Weft relay protocol, version 1

A relay stores records and blobs for allowlisted authors, and for anyone
who pays, and serves them to everyone. It never signs anything and clients
re-verify everything they receive.

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
| `price` | | |

## Responses

| `t` | Fields |
|---|---|
| `put` | `stored`: array of bytes(32); `rejected`: array of `[index, reason]` |
| `get` | `record`: bytes, absent when unknown |
| `head` | `pointer`: bytes, absent when unknown; `manifest`: bytes, absent when unknown |
| `price` | `rate`: uint cents per KiB per day; `banks`: array of bytes(32), sorted |
| `error` | `why`: text |

`head` always returns the newest manifest the relay holds for the author,
whatever the name. Asking for the reserved name `manifest` is the way to
fetch only the manifest.

## Rules on put

1. Records that do not parse are rejected by index.
2. Manifests in a batch are processed first so the records that follow
   verify against them, and receipts last so the records they pay for
   are already known.
3. Each record passes the verification procedure in `protocol.md`
   section 7 against the newest manifest the relay holds, or the one in
   the batch.
4. A record whose body is a blob is stored only after the relay has
   downloaded the blob from the pushing endpoint over iroh-blobs and the
   hash has verified.
5. Records by an allowlisted author are stored at once. Records and
   manifests by anyone else wait for a receipt in the same batch. Those
   no receipt covers are rejected with `payment required`.
6. A receipt is honoured when its `relay` is this relay, its voucher's
   bank is one the relay trusts, the voucher id is not yet spent, `until`
   is after now and at most 366 days ahead, every record it names is by
   the receipt's author and is in the batch or already stored, and
   `cents` is at least the cost. The cost is the sum over the named
   records of `ceil(bytes / 1024) * days * rate`, bytes being the record
   plus its blob, `days = ceil((until - now) / 86400)`. No change is
   given. The voucher is then spent, the records, the author's manifest,
   and the receipt are stored, and each named record and the receipt is
   pinned until `until`, or later if already pinned later.
7. A receipt by an allowlisted author is stored and nothing is charged.
8. A manifest replaces the author's newest manifest only when its `seq`
   is higher. A pointer replaces the head for its author and name only
   when it wins the ordering in `protocol.md` section 6.

## Storage

Records and indexes live in a redb database with five tables: records by
address, heads by author and name, newest manifest by author, pins by
address holding `until` and the paying author, spent voucher ids. Blobs
live in an iroh-blobs file store beside it.

## Sweep

At start and every 60 seconds the relay drops records whose pin has
passed, heads that point at a dropped record, and manifests of authors
who are not allowlisted and have no pin left. Allowlisted authors are
never swept. Spent voucher ids are kept forever. Blobs of swept records
stay in the blob store until a later milestone collects them.

## Reload

`allow`, `banks`, and `rate` are read at start and again on SIGHUP. A
reload replaces all three at once, then sweeps. A batch in flight keeps
the rules it started with; the next batch sees the new ones. A file that
fails to parse is reported on stderr and the running config stays. A
delisted author is refused on the next push; records the relay already
holds for that author stay until a pin they never had would have passed,
which is never.
