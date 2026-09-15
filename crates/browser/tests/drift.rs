#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use sha2::{Digest, Sha256};

#[test]
fn the_screenshots_match_the_ui_sources() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let ui = crate_dir.join("ui");
    let mut hasher = Sha256::new();
    for name in ["index.html", "style.css", "src/main.ts"] {
        hasher.update(std::fs::read(ui.join(name)).unwrap());
    }
    let current = format!("{:x}", hasher.finalize());
    let recorded =
        std::fs::read_to_string(crate_dir.join("../../docs/browser-home.sha256")).unwrap();
    assert_eq!(
        recorded.trim(),
        current,
        "the UI changed after the screenshots were taken; run crates/browser/smoke.sh"
    );
}
