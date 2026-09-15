# Backlog

Items with no milestone yet. Pull one into a `progress/M*.md` when it is
scheduled.

| Item | Origin | Notes |
|---|---|---|
| `weft:` handler on macOS and Windows | M19 | `weft-browser register` writes a desktop entry and runs `xdg-mime`; the other platforms need `CFBundleURLTypes` and a registry key, both behind a bundle |
| LND adapter against a live node | M21 | `crates/relay/src/lnd.rs` posts to `/v1/invoices` with the macaroon header and trusts only `lnd.pem`; it compiles and the fake node covers the relay side, but no LND has answered it. Needs a regtest node, `weft-relay node lnd <url>`, one invoice, one push |
| Light theme on WebKitGTK without a portal | M21 | `theme.rs` reads `org.freedesktop.appearance color-scheme` from the settings portal; a desktop without `xdg-desktop-portal` falls back to `prefers-color-scheme`, which WebKitGTK 2.52 reports as dark on this box whatever GTK says |
| TLS in the gateway process | M4 | A reverse proxy's job by decision |
