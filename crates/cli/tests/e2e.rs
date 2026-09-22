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
fn guardians_recover_a_lost_root() {
    let a = Machine::new("recover-a");
    let g = Machine::new("recover-g");
    let c = Machine::new("recover-c");
    let b = Machine::new("recover-b");
    let guardian = g.ok(&["init"]).lines().next().unwrap().to_owned();
    let root = a.ok(&["init"]).lines().next().unwrap().to_owned();
    let (failed, text) = a.run(&["manifest", "--guardian", &guardian]);
    assert!(!failed, "{text}");
    assert!(text.contains("threshold"), "{text}");
    let printed = a.ok(&["manifest", "--guardian", &guardian, "--threshold", "1"]);
    assert!(printed.contains("guardians 1 of 1"), "{printed}");
    let page = a.home.join("page.md");
    std::fs::write(&page, "# Old\n").unwrap();
    let old = a.ok(&["sign", page.to_str().unwrap()]).trim().to_owned();
    let old_addr = Path::new(&old).file_stem().unwrap().to_str().unwrap().to_owned();
    a.ok(&["point", "home", &old_addr]);

    let new_root = c.ok(&["init"]).lines().next().unwrap().to_owned();
    copy_records(&a.records(), &c.records());
    let draft = c.ok(&["recover", "draft", &root]);
    let message = draft.lines().last().unwrap().trim().to_owned();
    assert!(draft.contains("seq 1"), "{draft}");
    let signed = g.ok(&["recover", "sign", &message]);
    assert!(signed.contains(&root) && signed.contains(&new_root), "{signed}");
    let sig = signed.lines().last().unwrap().trim().to_owned();
    assert_eq!(sig.len(), 192, "{signed}");
    let (accepted, text) = c.run(&["recover", "finish", &message, "--sig", &"00".repeat(96)]);
    assert!(!accepted, "{text}");
    let (accepted, text) = a.run(&["recover", "finish", &message, "--sig", &sig]);
    assert!(!accepted && text.contains("new root"), "{text}");
    let finished = c.ok(&["recover", "finish", &message, "--sig", &sig]);
    assert!(finished.contains("recovered"), "{finished}");

    let page = c.home.join("page.md");
    std::fs::write(&page, "# New\n").unwrap();
    let new = c.ok(&["sign", page.to_str().unwrap()]).trim().to_owned();
    let new_addr = Path::new(&new).file_stem().unwrap().to_str().unwrap().to_owned();
    c.ok(&["point", "home", &new_addr]);

    copy_records(&a.records(), &b.records());
    copy_records(&c.records(), &b.records());
    let resolved = b.ok(&["resolve", &root, "home"]);
    assert!(resolved.starts_with(&format!("recovered to {new_root}\n{new_addr}")), "{resolved}");
    let direct = b.ok(&["resolve", &new_root, "home"]);
    assert!(direct.starts_with(&new_addr), "{direct}");
    assert!(!direct.contains("recovered"), "{direct}");
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

#[test]
fn a_retired_device_keeps_its_earlier_records() {
    let a = Machine::new("retire");
    let b = Machine::new("retire-reader");
    let root = a.ok(&["init"]).lines().next().unwrap().to_owned();
    a.ok(&["device", "add", "phone"]);
    a.ok(&["manifest"]);
    let page = a.home.join("page.md");
    std::fs::write(&page, "# before").unwrap();
    let before = a.ok(&["sign", page.to_str().unwrap(), "--as", "phone"]).trim().to_owned();
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let (success, text) = a.run(&["device", "retire", "phone", "--at", "1"]);
    assert!(!success && text.contains("after the device was created"), "{text}");
    let retired = a.ok(&["device", "retire", "phone"]);
    assert!(retired.contains("retired") && retired.contains("expires"), "{retired}");
    a.ok(&["manifest"]);
    std::fs::write(&page, "# after").unwrap();
    let after = a.ok(&["sign", page.to_str().unwrap(), "--as", "phone"]).trim().to_owned();

    copy_records(&a.records(), &b.records());
    assert!(b.ok(&["verify", &before]).contains("kind    page"));
    let (success, text) = b.run(&["verify", &after]);
    assert!(!success && text.contains("validity window"), "{text}");
    let whoami = a.ok(&["whoami"]);
    assert!(whoami.contains("phone  created") && whoami.contains("expires"), "{whoami}");
    assert!(whoami.contains(&root));
}

#[test]
fn relay_entries_may_carry_addresses() {
    let a = Machine::new("relays");
    a.ok(&["init"]);
    let id = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    a.ok(&["relay", "add", id]);
    let entry = format!("{id}@192.168.7.2:4433,[fd00::7]:4433");
    a.ok(&["relay", "add", &entry]);
    assert_eq!(a.ok(&["relay", "list"]).trim(), entry, "the addressed entry replaced the bare one");
    let (success, text) = a.run(&["relay", "add", &format!("{id}@192.168.7.2")]);
    assert!(!success && text.contains("host:port"), "{text}");
}

#[test]
fn petnames_and_labels_are_edited_as_signed_lists() {
    let a = Machine::new("lists");
    let root = a.ok(&["init"]).lines().next().unwrap().to_owned();
    a.ok(&["device", "add", "laptop"]);
    a.ok(&["manifest"]);
    let friend = Machine::new("lists-friend");
    let friend_root = friend.ok(&["init"]).lines().next().unwrap().to_owned();

    assert_eq!(a.ok(&["petname", "list"]), "");
    let written = a.ok(&["petname", "add", "friend", &friend_root, "--as", "laptop"]);
    let list = written.lines().next().unwrap().to_owned();
    assert_eq!(written.lines().count(), 2, "{written}");
    assert!(a.ok(&["resolve", &root, "petnames"]).starts_with(&list));
    assert_eq!(a.ok(&["petname", "list"]), format!("friend  {friend_root}\n"));
    a.ok(&["petname", "add", "me", &root]);
    assert_eq!(a.ok(&["petname", "list"]), format!("friend  {friend_root}\nme  {root}\n"));

    let (success, text) = a.run(&["petname", "add", "friend", &root]);
    assert!(!success && text.contains("already names"), "{text}");
    let (success, text) = a.run(&["petname", "add", "Bad.Name", &root]);
    assert!(!success && text.contains("field: name"), "{text}");
    let hash = weft_core::Address::of(b"x").to_string();
    let (success, text) = a.run(&["petname", "add", "x", &hash]);
    assert!(!success && text.contains("not a key address"), "{text}");
    let (success, text) = a.run(&["petname", "remove", "nobody"]);
    assert!(!success && text.contains("no petname nobody"), "{text}");
    let (success, text) = a.run(&["petname", "import", &friend_root]);
    assert!(!success && text.contains("no relays configured"), "{text}");

    a.ok(&["petname", "remove", "me"]);
    a.ok(&["petname", "remove", "friend"]);
    assert_eq!(a.ok(&["petname", "list"]), "");

    assert_eq!(a.ok(&["label", "list"]), "");
    a.ok(&["label", "add", &hash, "spam", "--as", "laptop"]);
    a.ok(&["label", "add", &friend_root, "trusted"]);
    assert_eq!(a.ok(&["label", "list"]), format!("trusted  {friend_root}\nspam  {hash}\n"));
    let (success, text) = a.run(&["label", "add", &hash, "spam"]);
    assert!(!success && text.contains("already carries"), "{text}");
    let (success, text) = a.run(&["label", "add", &hash, "no-go"]);
    assert!(!success && text.contains("field: value"), "{text}");
    let (success, text) = a.run(&["label", "remove", &hash, "nsfw"]);
    assert!(!success && text.contains("carries no nsfw"), "{text}");
    a.ok(&["label", "remove", &hash, "spam"]);
    assert_eq!(a.ok(&["label", "list"]), format!("trusted  {friend_root}\n"));
}
