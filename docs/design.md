# Weft design, version 0.1

Context for the protocol in `protocol.md`. Written 2026-09-02, revised
2026-09-03 with the review findings listed at the end, and brought level
with the code on 2026-09-22 for the 0.1 release. The prose is the vision.
The status table under the layers says what the code does today.

## Summary

Weft is a new application layer for the internet. It keeps IP, QUIC, and
TLS, and replaces the parts of the web that cause the damage: location
based URLs, account based identity, and advertising as the default business
model. In their place: signed, content addressed records; identity as a
keypair the user owns; names that resolve through pluggable registries;
hosting that is paid for openly rather than funded by watching the reader.

The first artifact is a browser that opens Weft content and ordinary HTTPS
pages side by side, shows who signed what, and carries one identity and one
personal data store across everything the user does. The old web stays
reachable, and old browsers reach Weft content through gateways.

Built by one person as a side project, with the intent to make it sellable
later. Reuse working components, ship a thin end to end slice early, defer
anything that needs a network effect to exist.

Weft is a protocol suite, a reference browser, and a small set of
libraries. It is not a new network stack, an anonymity network, a
blockchain, or a token.

## The problem

Four failures with one root. Surveillance: reading is tracked because
tracking pays for pages. Centralization and fragility: a handful of hosts
and identity providers sit under everything, and a third of decade old
links are dead. Trust: nothing tells the reader who wrote something or
whether it was altered. Economics: attention is the only thing the web can
bill for.

A URL names a place, not a thing. Someone must run the place and pay for
it, so they need revenue, so they sell attention, so they must identify the
reader, so they issue accounts, which lock the reader's data to the host.
Break the first link and the chain loosens. Content named by what it is can
be served by anyone and proven by its author. A reader who brings their own
identity needs no account. Hosting with a visible price needs no ads.

Content addressing, self held identity, and open payment for hosting are
three legs of one stool. Projects that fixed one leg stayed niche. Weft
ships all three in a single client.

## Principles

1. The user holds the keys.
2. Content is addressed by what it is.
3. Every byte is signed. An unsigned record is not a Weft record.
4. Names sit above content, never below.
5. Pay or host, never watch. The protocol has no slot for tracking.
6. Local first. Remote services accelerate and back up.
7. Bridge, do not break.
8. Crypto where it earns its place. No ledger without a proven need, no token.
9. One person can build the first version.

## Layers

| Layer | Name | At 0.1 |
|---|---|---|
| L7 | Applications: the browser, later feeds and publishing tools | browser shipped |
| L6 | Payments: signed receipts, settlement through any rail | shipped, two rails, relays only |
| L5 | Personal store: the user's log plus scoped, revocable grants | shipped |
| L4 | Naming: petnames, DNS bridged names, pluggable registries | raw and DNS shipped, petnames deferred |
| L3 | Delivery: DHT discovery, relays, direct peers | relays shipped, DHT and gossip deferred |
| L2 | Content: signed, content addressed records and pointers | shipped |
| L1 | Identity: keypairs, device subkeys, rotation, claims | keys, devices, recovery shipped; rotation and claims deferred |
| L0 | Transport: IP, QUIC, TLS 1.3 | reused |

### Status at 0.1

Every promise this document makes, against the code at `v0.1.0`. Shipped
means the rule is in `protocol.md` or `relay.md` and a test exercises it.
Partial means part of the promise. Deferred means no code and a row in
`progress/BACKLOG.md`.

| Promise | Status | Where |
|---|---|---|
| Signed, content addressed records; pointers with a Lamport sequence | shipped | `protocol.md` 4, 6; `weft-core` |
| Root key, device keys, manifest, revocation, retire | shipped | `protocol.md` 5, 7 |
| Social recovery through guardians | shipped | `protocol.md` 13 |
| Root rotation by a successor manifest signed by both roots | deferred | recovery replaces a lost root only |
| Root in a hardware token or enclave | deferred | passphrase encrypted file, `weft-home` |
| Selective disclosure claims | deferred | login proves the key alone, `protocol.md` 12 |
| Raw addresses with a version byte and checksum | shipped | `protocol.md` 3 |
| DNS bridged names over DNSSEC or DoH | shipped | `_weft` TXT over DoH, `weft-resolve` |
| Petnames | deferred | kind reserved, `protocol.md` 9 |
| Relays as caches with a contract | shipped | `relay.md`, `weft-net`, `weft-relay` |
| Direct peers | partial | relays dialed by address, mDNS on a LAN; readers never dial each other |
| DHT discovery of hashes and keys | deferred | iroh discovery finds a relay by id; no Kademlia mapping |
| Gossip between relays | deferred | |
| Personal store as a log, grants that sever on revoke | shipped | `protocol.md` 10, `store.md`, `weft-store` |
| Receipts, an author pays a relay to host | shipped | `protocol.md` 11, vouchers and Lightning preimages |
| A reader pays an author, or a relay for priority | deferred | |
| Web of trust from follows and endorsements | deferred | |
| Label lists in the labeler model | deferred | kind reserved, `protocol.md` 9 |
| No delete, revocation records clients honor | shipped, changed | revocation is retroactive; retire keeps a key's earlier records, `protocol.md` 7 |
| HTTPS gateway with provenance in a header bar | shipped | `weft-gateway` |
| Challenge response login with no account | shipped | `protocol.md` 12, gateway `/login` |
| Browser opens HTTPS pages with the unsigned label | shipped | `weft-browser` |
| Signed snapshot of an HTTPS page | deferred | |
| Native renderer for signed records | shipped | CommonMark, no raw HTML |
| One address bar for every tier | shipped | `Target` in `weft-resolve` |
| Provenance panel | shipped | `weft-browser` |
| Identity switcher with throwaways | deferred | one identity per home |
| Personal store as a first class view | shipped | names, grants, repoint |
| Publish from anywhere | partial | compose with preview, `weft sign`; no drag and drop |

### Identity

An identity is an Ed25519 root key. The root signs a manifest listing the
device keys allowed to act for it and the keys it has revoked. Losing a
device means revoking one entry, not losing the identity. The root lives in
the most protected place available and is used only to sign manifests.

Login is a challenge signed by a device key, checked against the manifest.
A service that needs only a fact receives a selective disclosure proof
instead. Identity is a bare public key, not a DID and not a domain.
Readable names are layer 4's job.

A root can name guardians, other identities' root keys, and a threshold in
its manifest. When the root is lost, that many guardians sign a recovery
record handing the identity to a new root, and every resolver follows it.
A root that is merely compromised is not recovered this way: it can still
rewrite the guardian list, so recovery trusts the newest manifest as the
rest of the protocol does.

### Content

The unit is the record: a signed envelope around a body. Large bodies are
referenced by hash and fetched in chunks from many sources. Records are
immutable. Mutable things are reached through pointers. Provenance is a
lookup, not an investigation. Format details are in `protocol.md`.

### Naming

Three optional tiers, each resolving to a key or hash, each falling back to
the one below. Raw addresses always work. Petnames are the user's own and
cannot be spoofed or taken. Registered names come from pluggable
registries, and the first registry is DNS: a TXT record binds a domain to a
key, verified over DNSSEC or DNS over HTTPS. No global ledger for names in
version 1.

### Delivery

Given a hash or a key, where are the bytes. Direct peers when reachable,
relays that store and serve for a fee, and a Kademlia DHT mapping hashes
and keys to whoever serves them. A relay is a cache with a contract, not an
authority. The reference implementation builds on iroh for QUIC with hole
punching, blake3 verified blob transfer, and discovery.

Open: relay economics before payments exist.

### Personal store

An append only log of the user's own records, replicated across devices
and optionally to a relay. Applications do not have databases of users;
they have grants. A grant is a signed, revocable record permitting an
application key to read or write certain kinds in the store. Revoking one
severs access. Views such as folders are derived, not stored.

### Payments

Deliberately last. The protocol reserves the receipt: a signed record
acknowledging that a specific service is owed a specific amount, settled
out of band through any rail. Authors pay relays to host, readers pay
authors per article or month, readers pay relays for priority. None
requires the reader to be identified beyond a possibly throwaway key.
Version 1 settles through two rails behind `Relay::settle`: the voucher in
`protocol.md`, a bearer token a bank the relay trusts has signed, and a
Lightning preimage, where the relay issues an invoice over its wire and
the receipt carries the preimage any wallet hands back on payment. A relay
verifies a preimage against the invoices it issued, offline, with one
hash; its node is asked only to issue. Nothing else in the protocol names
the rail.

### Trust and moderation

Signatures say who. Two user controlled mechanisms say whether to believe
or see. A web of trust computed from signed follows and endorsements, and
subscribable label lists in the ATProto labeler model. The protocol has no
delete; authors publish revocations that clients honor, and relays drop
what they will not host.

### Bridges

An HTTPS gateway serves any Weft address to an old browser with provenance
in a header bar. The Weft browser opens any HTTPS page, labels it as
unsigned, and offers to save a signed snapshot. A publisher adopts Weft by
adding a TXT record and pinning to a relay. A reader adopts it by
installing one browser.

## The browser

Desktop, Rust core, Tauri shell, system web view for the old web, native
renderer for records. One address bar that accepts any tier of name and
says which one resolved. A provenance panel on every page. An identity
switcher with throwaways. The personal store as a first class view.
Publish from anywhere.

The minimum end to end slice: generate an identity on machine A, publish a
signed page, resolve and render it on machine B through the DHT with the
signature verified, then open an HTTPS page in the same window with the
unsigned label.

## Prior art

| Project | Weft takes |
|---|---|
| IPFS | content addressing, the Merkle blob model |
| iroh | the transport and blob layer |
| Nostr | signed events, relays as caches, DNS name binding |
| ATProto | repository as log, labelers for moderation |
| Solid | the grant model for application access |
| Urbit | the ambition, not the stack |
| Web with passkeys | the passkey experience for keys, DNS as the first registry |

Each solved one leg. Weft's bet is that the client is the product and each
layer is borrowed rather than rebuilt.

## Threats and non goals

Key loss is mitigated by device subkeys; root loss without backup is fatal
by design. Sybil and spam meet trust distance, label lists, and pinning
fees. Illegal content is the relay's legal decision. Relay capture cannot
forge or alter content. DNS failure modes are inherited by the DNS tier
only. DHT lookups leak interest; Weft is not an anonymity network. Records
carry author asserted times.

Non goals: replacing IP, QUIC, or TLS; anonymity against a global passive
adversary; a token or sale; mobile before desktop; live streaming.

## Roadmap

| Milestone | Deliverable | Demo |
|---|---|---|
| M0 | Protocol spec and test vectors | walk the layer stack |
| M1 | Core crate and CLI | sign on one machine, verify on another from copied files |
| M2 | iroh integration, pointers over the network, minimal relay | publish on the laptop, fetch by hash on the desktop |
| M3 | Browser first cut | the minimum end to end slice |
| M4 | DNS bridge and HTTPS gateway | same page in Firefox via gateway and in Weft via domain |
| M5 | Personal store and grants | revoke a grant and watch access end |
| M6 | Challenge response login | log in with no account and no password |
| M7 | Payments experiment | pay a relay a few cents to host a page |

Shipped after the roadmap, each closing what the one before left open.

| Milestone | Deliverable |
|---|---|
| M8 | The store daemon is the one process that signs |
| M9 | Every read the browser renders crosses the store socket |
| M10 | Store hardening: capped cache, pooled reads, fresh browser key |
| M11 | The gateway reads through the store socket, sessions survive restarts |
| M12 | Reads that fetch: a blob the store lacks is pulled from a relay |
| M13 | Fetch hardening: anonymous readers never make a gateway pull |
| M14 | Byte budgets per identity, SIGHUP reloads on relay and gateway |
| M15 | Relay hygiene: sweep by pins, blob GC, no dead receipts |
| M16 | Sweep and protect set as table lookups, budgets survive restarts |
| M17 | `WEFT_NET=local`, cache cap, detached daemon, capped sessions |
| M18 | Retire instead of revoke, pins for any author, `Host` routing |
| M19 | The browser: themes, compose, history, bookmarks, blobs, handler |
| M20 | Named links, blob totals, a driven smoke test with screenshots |
| M21 | Lightning preimages as the second rail, the portal theme |
| M22 | Guardians and recovery, an open kind namespace, LND in regtest |
| M23 | Apache-2.0, this status table, the `v0.1.0` release, a recorded demo |

## Review findings, 2026-09-03

- A device signed pointer could point readers at a stale manifest that
  still authorizes a stolen device. Manifests and the `manifest` pointer
  are root signed only.
- A single per identity counter forks silently across offline devices.
  Pointers carry a Lamport sequence and cite the heads they saw.
- Bare base32 keys had no algorithm agility or typo detection. Addresses
  carry a version byte and a checksum.
- Deterministic CBOR was underspecified. The subset and rules are frozen
  in `protocol.md` with vectors.
- Grants only bite if the store is a gate. The store will be a daemon
  reached over IPC with the browser as its only privileged client.
- Build pointers and records on iroh-blobs and iroh-gossip, not iroh-docs.
- Render a restricted native subset for signed records before any
  sandboxed HTML.
- Revocation is retroactive in version 1: everything a revoked key signed
  stops verifying. A lost key is retired through the device's `expires`
  instead, which keeps its earlier records; `protocol.md` section 7.

## Open questions

- Relay incentives before payments.
- Streaming payments versus aggregated receipts.
- When a consensus backed name registry is justified.
- The project's real name.

Each waits for readers and authors who are not the author of this
document. The 0.1 release exists to find them.

Settled: social recovery through guardians named in the manifest,
`protocol.md` section 13; record kinds are an open namespace with a
reserved core, section 9.
