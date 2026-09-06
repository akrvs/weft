#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

struct Machine {
    home: PathBuf,
}

impl Machine {
    fn new(name: &str) -> Self {
        let home = std::env::temp_dir().join(format!("weft-e2e-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        Self { home }
    }

    fn run(&self, args: &[&str]) -> (bool, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_weft"))
            .env("WEFT_PASSPHRASE", "correct horse")
            .arg("--home")
            .arg(&self.home)
            .args(args)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        (out.status.success(), text)
    }

    fn ok(&self, args: &[&str]) -> String {
        let (success, text) = self.run(args);
        assert!(success, "{args:?}: {text}");
        text
    }

    fn records(&self) -> PathBuf {
        self.home.join("records")
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn copy_records(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        std::fs::copy(&path, to.join(path.file_name().unwrap())).unwrap();
    }
}

#[test]
fn sign_on_a_verify_on_b_then_revoke() {
    let a = Machine::new("a");
    let b = Machine::new("b");
    let root = a.ok(&["init"]).lines().next().unwrap().to_owned();
    assert_eq!(root.len(), 60);
    a.ok(&["device", "add", "laptop"]);
    a.ok(&["manifest"]);

    let page = a.home.join("page.html");
    std::fs::write(&page, "<h1>weft</h1>").unwrap();
    let page_path = a.ok(&["sign", page.to_str().unwrap(), "--as", "laptop"]).trim().to_owned();
    let page_addr = Path::new(&page_path).file_stem().unwrap().to_str().unwrap().to_owned();
    a.ok(&["point", "home", &page_addr, "--as", "laptop"]);

    copy_records(&a.records(), &b.records());
    let verified = b.ok(&["verify", &page_path]);
    assert!(verified.contains("kind    page"), "{verified}");
    let resolved = b.ok(&["resolve", &root, "home"]);
    assert!(resolved.starts_with(&page_addr), "{resolved}");
    assert!(resolved.contains("target present"));

    a.ok(&["device", "revoke", "laptop"]);
    a.ok(&["manifest"]);
    copy_records(&a.records(), &b.records());
    let (success, text) = b.run(&["verify", &page_path]);
    assert!(!success);
    assert!(text.contains("signer revoked"), "{text}");
    let (success, _) = b.run(&["resolve", &root, "home"]);
    assert!(!success);

    let whoami = a.ok(&["whoami"]);
    assert!(whoami.contains("revoked"));
    let (success, text) = a.run(&["device", "add", "Bad Label"]);
    assert!(!success && text.contains("label"));
}

#[test]
fn wrong_passphrase_is_rejected() {
    let a = Machine::new("c");
    a.ok(&["init"]);
    let out = Command::new(env!("CARGO_BIN_EXE_weft"))
        .env("WEFT_PASSPHRASE", "wrong")
        .arg("--home")
        .arg(&a.home)
        .args(["device", "add", "phone"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("wrong passphrase"));
    let (success, _) = a.run(&["init"]);
    assert!(!success);
}

#[test]
fn login_round_trip_on_the_command_line() {
    let a = Machine::new("login");
    a.ok(&["init"]);
    a.ok(&["device", "add", "phone"]);
    a.ok(&["manifest"]);
    let root =
        a.ok(&["whoami"]).lines().next().unwrap().split_whitespace().next().unwrap().to_owned();
    let challenge = a.ok(&["login", "challenge", "--service", "http://127.0.0.1:8080"]);
    let challenge = challenge.trim();
    let proof = a.ok(&["login", "sign", challenge, "--as", "phone"]);
    let proof = proof.trim();
    let out = a.ok(&["login", "verify", proof, "--service", "http://127.0.0.1:8080"]);
    assert!(out.starts_with(&root), "{out}");
    let (ok, text) = a.run(&["login", "verify", proof, "--service", "http://127.0.0.1:8081"]);
    assert!(!ok && text.contains("service mismatch"), "{text}");
    let (ok, text) = a.run(&["login", "challenge", "--service", "HTTP://x"]);
    assert!(!ok && text.contains("service"), "{text}");
    let (ok, text) = a.run(&["login", "sign", "!!!", "--as", "phone"]);
    assert!(!ok, "{text}");
    let page = a.home.join("c.txt");
    std::fs::write(&page, "x").unwrap();
    let (ok, text) = a.run(&["sign", page.to_str().unwrap(), "--kind", "login"]);
    assert!(!ok && text.contains("never stored"), "{text}");
    let b = Machine::new("login-b");
    b.ok(&["init"]);
    let out = b.ok(&["login", "verify", proof, "--service", "http://127.0.0.1:8080"]);
    assert!(out.starts_with(&root), "the proof carries its manifest: {out}");
}
