# Weft design, draft 0.1

Context for the protocol in `protocol.md`. Written 2026-09-02, revised
2026-09-03 with the review findings listed at the end.

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

| Layer | Name | Status |
|---|---|---|
| L7 | Applications: the browser, later feeds and publishing tools | new |
| L6 | Payments: signed receipts, settlement through any rail | later |
| L5 | Personal store: the user's log plus scoped, revocable grants | new |
| L4 | Naming: petnames, DNS bridged names, pluggable registries | new |
| L3 | Delivery: DHT discovery, relays, direct peers | new |
| L2 | Content: signed, content addressed records and pointers | new |
| L1 | Identity: keypairs, device subkeys, rotation, claims | new |
| L0 | Transport: IP, QUIC, TLS 1.3 | reused |

### Identity

An identity is an Ed25519 root key. The root signs a manifest listing the
device keys allowed to act for it and the keys it has revoked. Losing a
device means revoking one entry, not losing the identity. The root lives in
the most protected place available and is used only to sign manifests.

Login is a challenge signed by a device key, checked against the manifest.
A service that needs only a fact receives a selective disclosure proof
instead. Identity is a bare public key, not a DID and not a domain.
Readable names are layer 4's job.

Open: social recovery for the root key.

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
  stops verifying. Distinguishing a lost key from a compromised one, with
  an effective time, is open for M2.

## Open questions

- Social recovery for root keys.
- Relay incentives before payments.
- Streaming payments versus aggregated receipts.
- When a consensus backed name registry is justified.
- Record kinds: fixed set or open namespace with a small core.
- Revocation with an effective time.
- The project's real name.
