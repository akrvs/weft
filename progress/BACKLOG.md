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
| Live `_weft` record | M4 | No domain carries one yet; the positive DoH path and the AD bit on a real answer are unverified |
| Gateway host based routing and TLS | M4 | A publisher CNAME to the gateway, TLS in process |
| Grants over fetched records | M5 | Only the root's own records are visible through a grant |
| Application display names | M5 | The store knows an app only by its key address |
| Blob garbage collection on sweep | M7 | `sweep` reports orphaned blob hashes; iroh-blobs 0.103 keeps `delete` crate private |
| Dead receipts after a refused paid push | M7 | The CLI stores the receipt before the relay answers |
| Real payment rail | M7 | Lightning preimage or ecash token behind the voucher seam in `Relay::settle` |
| Sponsorship | M7 | A receipt pays only for its author's records |
| Browser price and pay | M7 | Publishing from the browser cannot pay a relay |
| Relay reloads config | M2, M7 | `allow`, `banks`, and `rate` are read only at start |
| `weft:` URL handler registration | M6 | A challenge page in Firefox cannot launch weft-browser; the link is pasted by hand |
| Detached daemon from the browser | M9 | The browser only starts an attached daemon that dies with it |
| Gateway allow list reload | M11 | `--allow` is read once at start, like the relay's `allow` |
| Gateway sessions cap on disk | M11 | The file holds at most 1024 sessions; a full table refuses new logins until a sweep |
| Store cache cap | M10 | The cache mirrors the directory; a store larger than memory has no hard cap |
| Passphrase field after a failed start | M10 | The start form keeps the typed passphrase after the daemon refuses it |
| Blob download progress | M12 | The browser shows nothing while a large blob pulls |
| Per session pull budget | M13 | A logged in reader may pull without limit beyond the gateway wide in-flight cap of 4; no bytes per session accounting |
| Gateway pull cap flag | M13 | `Gateway::pull_cap` exists for tests; the binary has no `--pulls` flag |
