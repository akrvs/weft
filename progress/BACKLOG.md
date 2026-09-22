# Backlog

Items with no milestone yet. Pull one into a `progress/M*.md` when it is
scheduled.

| Item | Origin | Notes |
|---|---|---|
| `weft:` handler on macOS and Windows | M19 | `weft-browser register` writes a desktop entry and runs `xdg-mime`; the other platforms need `CFBundleURLTypes` and a registry key, both behind a bundle |
| Recovery in the browser | M22 | `weft recover sign` and `finish` are CLI only; a guardian dialog would show the old and new root and sign with the root key through the daemon, which today never opens the root |
| Theme fallback on a live desktop without a portal | M22 | `theme.rs` picks GSettings then GTK when the portal answers nothing; the mapping is unit tested and the code compiled, but this box has a portal, so neither fallback has stamped a running window |
| TLS in the gateway process | M4 | A reverse proxy's job by decision |
| Petnames | design.md 4.3 | Kind reserved in `protocol.md` 9. Local names over keys, shareable as signed lists, resolved by the address bar before DNS |
| Label lists | design.md 4.7 | Kind reserved in `protocol.md` 9. Signed lists that tag records or keys; the browser subscribes and hides, blurs, warns, or highlights |
| Web of trust | design.md 4.7 | Follows and endorsements as signed records, a trust distance the browser and relays can rate limit on |
| Selective disclosure claims | design.md 4.1 | Login proves the key alone; a claim format and an issuer are both missing |
| Root rotation | design.md 4.1 | A successor manifest signed by both roots. Recovery covers a lost root only |
| Hardware backed root | design.md 4.1 | The root is a passphrase encrypted file; a token or enclave path needs a signing trait in `weft-home` |
| Signed snapshot of an HTTPS page | design.md 4.8 | The browser labels the page unsigned and cannot save it |
| Identity switcher | design.md 5 | One identity per home; throwaways need several keystores or several roots in one |
| Reader pays author | design.md 4.6 | Receipts pay a relay for pinning only; the author side and priority delivery have no receipt shape |
| DHT discovery and relay gossip | design.md 4.4 | Relays are dialed from explicit entries; iroh discovery finds a relay by id, nothing maps a hash to who serves it |
| Publish by drag and drop | design.md 5 | Compose takes typed Markdown; a dropped file should become a blob record and a link |
