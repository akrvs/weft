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
| Offline preset for CLI network commands | M2 | Loopback path exists only in the library tests |
| CLI exits with a panic on a closed stdout pipe | M3 | `weft whoami \| head -1` |
| Blob pull on miss | M4 | Browser and gateway serve blobs from the local store only |
| DNS cache and TTL | M4 | One DoH lookup per navigation, TTL discarded |
| Live `_weft` record | M4 | No domain carries one yet; the positive DoH path and the AD bit on a real answer are unverified |
| Gateway host based routing and TLS | M4 | A publisher CNAME to the gateway, TLS in process |
| Home directory creation outside `init` | M4 | `store` and `keep_blob` expect their directories to exist |
| Store cache eviction | M9 | The record cache and the verification memo in `weft_home::Store` never evict |
| Grants over fetched records | M5 | Only the root's own records are visible through a grant |
| Application display names | M5 | The store knows an app only by its key address |
| Blob garbage collection on sweep | M7 | `sweep` reports orphaned blob hashes; iroh-blobs 0.103 keeps `delete` crate private |
| Dead receipts after a refused paid push | M7 | The CLI stores the receipt before the relay answers |
| Real payment rail | M7 | Lightning preimage or ecash token behind the voucher seam in `Relay::settle` |
| Sponsorship | M7 | A receipt pays only for its author's records |
| Browser price and pay | M7 | Publishing from the browser cannot pay a relay |
| Relay reloads config | M2, M7 | `allow`, `banks`, and `rate` are read only at start |
| Gateway session persistence | M6 | Sessions and pending challenges live in memory; a restart logs everyone out |
| `weft:` URL handler registration | M6 | A challenge page in Firefox cannot launch weft-browser; the link is pasted by hand |
| Start the store from a failed navigation | M9 | A navigation with the daemon down reports it; only the store dialog offers the start form |
| Daemon stderr after start | M9 | The browser reads the child's stderr only when the start fails; the pipe stays open and unread afterwards |
| Detached daemon from the browser | M9 | The browser only starts an attached daemon that dies with it |
| One connection in `Local` | M9 | Browser requests to the daemon are serialized on one socket connection |
| Browser key rotation | M8 | `browser.key` is written once; replacing it means deleting the file and restarting the daemon |
| Login policy at the gateway | M6 | Any valid identity logs in; there is no allowlist or first seen record |
