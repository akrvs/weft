# Backlog

Items with no milestone yet. Pull one into a `progress/M*.md` when it is
scheduled.

| Item | Origin | Notes |
|---|---|---|
| Named links in the renderer | M19 smoke test | `render` keeps only `weft:<address>` and `https:` links; a `weft:author/name` link is dropped together with its text. Frozen since M3, worth reopening with a `Target` parse in `record_address` |
| `weft:` handler on macOS and Windows | M19 | `weft-browser register` writes a desktop entry and runs `xdg-mime`; the other platforms need `CFBundleURLTypes` and a registry key, both behind a bundle |
| Blob total before the pull ends | M19 | iroh-blobs reports offsets only; the bar counts bytes without a total. A `size` request on the relay wire would give the total up front |
| Light theme screenshot | M19 | The stylesheet carries both palettes; only the dark one was seen. WebKitGTK follows the desktop portal and neither `GTK_THEME` nor the gsettings key flipped it on Hyprland |
| Browser UI automation in the smoke test | M19 | Compose, store, history, and bookmark dialogs were exercised by their unit and store tests only; `/dev/uinput` is root only on this machine so no clicks were scripted |
| Payment rail behind the voucher | M7, M18 | `Relay::settle` is the seam; the voucher is version 1 |
| TLS in the gateway process | M4 | A reverse proxy's job by decision |
