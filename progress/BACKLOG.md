# Backlog

Items with no milestone yet. Pull one into a `progress/M*.md` when it is
scheduled.

| Item | Origin | Notes |
|---|---|---|
| Browser visual design | M3 review | First cut is functional and plain. Needs typography, spacing, a proper provenance panel, light and dark themes, and a real icon |
| Compose preview and pointer management | M3 | Preview the rendered page before signing; list and repoint names |
| History and bookmarks in the browser | M3 | Back is an in-memory trail |
| Non-image blob view | M3 | Download affordance for blobs that are not images |
| Revocation with an effective time | M1 | Distinguish a lost key from a compromised one |
| Live `_weft` record | M4 | No domain carries one yet; the positive DoH path and the AD bit on a real answer are unverified |
| Gateway host based routing and TLS | M4 | A publisher CNAME to the gateway, TLS in process |
| Grants over fetched records | M5 | Only the root's own records are visible through a grant |
| Application display names | M5 | The store knows an app only by its key address |
| Real payment rail | M7 | Lightning preimage or ecash token behind the voucher seam in `Relay::settle` |
| Sponsorship | M7 | A receipt pays only for its author's records |
| Browser price and pay | M7 | Publishing from the browser cannot pay a relay |
| `weft:` URL handler registration | M6 | A challenge page in Firefox cannot launch weft-browser; the link is pasted by hand |
| Passphrase field after a failed start | M10 | The start form keeps the typed passphrase after the daemon refuses it |
| Blob download progress | M12 | The browser shows nothing while a large blob pulls |
| Store index | M17 | Every snapshot walks the record directory; a store larger than `--cache` re-reads evicted records on each request |
| Detached daemon log | M17 | A daemon started detached from the browser logs nowhere once the browser closes; stopping it needs a terminal |
| Local mode across subnets | M17 | `WEFT_NET=local` finds relays by mDNS on one link only; no addressed relay entries |
| Gateway table format | M17 | `--sessions` and `--identities` are bounded at 4096 by the CBOR array limit; a larger public gateway needs a paged file |
