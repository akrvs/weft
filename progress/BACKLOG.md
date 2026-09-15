# Backlog

Items with no milestone yet. Pull one into a `progress/M*.md` when it is
scheduled.

| Item | Origin | Notes |
|---|---|---|
| `weft:` handler on macOS and Windows | M19 | `weft-browser register` writes a desktop entry and runs `xdg-mime`; the other platforms need `CFBundleURLTypes` and a registry key, both behind a bundle |
| Light theme screenshot | M19, M20 | The stylesheet's light palette is correct (`--bg` `#f7f6f2` on bare `:root`) but WebKitGTK 2.52 on this Hyprland box renders the web view `prefers-color-scheme: dark` whatever the portal `color-scheme` or `gtk-theme` says; the titlebar flips, the content never does. Needs a `WebKitSettings` call or a `data-theme` override, both reopening the frozen no-toggle decision |
| Drive socket for the gateway login flow | M20 | `smoke.sh` covers every browser dialog but the login consent, which needs a gateway and a challenge; the M19 hand test saw it once |
| Screenshot drift | M20 | `docs/browser-home.png` is refreshed only by `smoke.sh`; a stylesheet change without a rerun leaves the README stale. CI cannot run the script: no display |
| Payment rail behind the voucher | M7, M18 | `Relay::settle` is the seam; the voucher is version 1 |
| TLS in the gateway process | M4 | A reverse proxy's job by decision |
