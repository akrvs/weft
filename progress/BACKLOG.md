# Backlog

Items with no milestone yet. Pull one into a `progress/M*.md` when it is
scheduled.

| Item | Origin | Notes |
|---|---|---|
| `weft:` handler on macOS and Windows | M19 | `weft-browser register` writes a desktop entry and runs `xdg-mime`; the other platforms need `CFBundleURLTypes` and a registry key, both behind a bundle |
| Recovery in the browser | M22 | `weft recover sign` and `finish` are CLI only; a guardian dialog would show the old and new root and sign with the root key through the daemon, which today never opens the root |
| Theme fallback on a live desktop without a portal | M22 | `theme.rs` picks GSettings then GTK when the portal answers nothing; the mapping is unit tested and the code compiled, but this box has a portal, so neither fallback has stamped a running window |
| TLS in the gateway process | M4 | A reverse proxy's job by decision |
| Label authoring in the browser | M24 | Labelers publish with `weft label`; the browser only follows and acts |
| Labels refreshed on a timer | M24 | Page hits read the local store; labeler heads are pulled on follow and on the refresh button only |
| Pointers for granted apps | M24 | An app granted `petname` or `label` can `put` a list but not `point` it; `point` stays browser only |
| Relay rate limits by trust distance | design.md 4.7 | Follows and the walk shipped in M25; relays still gate by allowlist and pins alone |
| Pull on `weft follow add` | M25 | The CLI writes the list only; `weft trust --refresh` pulls |
| Redirects past the last read | M25 | A key first seen at distance 3 is not followed through recovery, since its list is never read |
| Selective disclosure claims | design.md 4.1 | Login proves the key alone; a claim format and an issuer are both missing |
| Root rotation | design.md 4.1 | A successor manifest signed by both roots. Recovery covers a lost root only |
| Hardware backed root | design.md 4.1 | The root is a passphrase encrypted file; a token or enclave path needs a signing trait in `weft-home` |
| Signed snapshot of an HTTPS page | design.md 4.8 | The browser labels the page unsigned and cannot save it |
| Identity switcher | design.md 5 | One identity per home; throwaways need several keystores or several roots in one |
| Reader pays author | design.md 4.6 | Receipts pay a relay for pinning only; the author side and priority delivery have no receipt shape |
| DHT discovery and relay gossip | design.md 4.4 | Relays are dialed from explicit entries; iroh discovery finds a relay by id, nothing maps a hash to who serves it |
| Publish by drag and drop | design.md 5 | Compose takes typed Markdown; a dropped file should become a blob record and a link |
