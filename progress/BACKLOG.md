# Backlog

Items with no milestone yet. Pull one into a `progress/M*.md` when it is
scheduled.

| Item | Origin | Notes |
|---|---|---|
| `weft:` handler on macOS and Windows | M19 | `weft-browser register` writes a desktop entry and runs `xdg-mime`; the other platforms need `CFBundleURLTypes` and a registry key, both behind a bundle |
| Recovery in the browser | M22 | `weft recover sign` and `finish` are CLI only; a guardian dialog would show the old and new root and sign with the root key through the daemon, which today never opens the root |
| Theme fallback on a live desktop without a portal | M22 | `theme.rs` picks GSettings then GTK when the portal answers nothing; the mapping is unit tested and the code compiled, but this box has a portal, so neither fallback has stamped a running window |
| TLS in the gateway process | M4 | A reverse proxy's job by decision |
