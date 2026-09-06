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
| Relay quotas and receipts | design | Bootstrap allowlist becomes paid pinning |
| Offline preset for CLI network commands | M2 | Loopback path exists only in the library tests |
| CLI exits with a panic on a closed stdout pipe | M3 | `weft whoami \| head -1` |
| Blob pull on miss | M4 | Browser and gateway serve blobs from the local store only |
| DNS cache and TTL | M4 | One DoH lookup per navigation, TTL discarded |
| Live `_weft` record | M4 | No domain carries one yet; the positive DoH path and the AD bit on a real answer are unverified |
| Gateway host based routing and TLS | M4 | A publisher CNAME to the gateway, TLS in process |
| Home directory creation outside `init` | M4 | `store` and `keep_blob` expect their directories to exist |
| Browser behind the store daemon | M5 | The browser still reads the home directory; the design wants it as the daemon's one privileged client |
| Store index | M5 | The gate re-reads and re-verifies every record per request |
| Grants over fetched records | M5 | Only the root's own records are visible through a grant |
| Application display names | M5 | The store knows an app only by its key address |
