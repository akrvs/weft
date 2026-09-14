#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use weft_home::Home;

const PASS: &[u8] = b"correct horse";

fn home(name: &str) -> PathBuf {
    let dir = PathBuf::from(format!("/tmp/w{}{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Home::new(dir.clone()).init(PASS).unwrap();
    dir
}

fn spawn(dir: &Path, attach: bool) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_weft-store"));
    command.arg("serve").arg("--device").arg("root").arg("--cache").arg("1");
    if attach {
        command.arg("--attach");
    }
    let mut child = command
        .env("WEFT_HOME", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(PASS).unwrap();
    stdin.write_all(b"\n").unwrap();
    drop(stdin);
    child
}

fn wait_for_socket(child: &mut Child, dir: &Path) {
    let socket = dir.join("store.sock");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !socket.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            let mut err = String::new();
            std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut err).unwrap();
            panic!("weft-store exited {status}: {err}");
        }
        assert!(Instant::now() < deadline, "socket did not appear");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn exited_within(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn a_piped_passphrase_without_attach_outlives_the_pipe() {
    let dir = home("detached");
    let mut child = spawn(&dir, false);
    wait_for_socket(&mut child, &dir);
    assert!(exited_within(&mut child, Duration::from_secs(2)).is_none(), "the daemon stayed up");
    child.kill().unwrap();
    child.wait().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn attach_exits_when_the_pipe_closes() {
    let dir = home("attached");
    let mut child = spawn(&dir, true);
    let status = exited_within(&mut child, Duration::from_secs(60)).expect("attach exits on EOF");
    assert!(status.success(), "{status}");
    assert!(!dir.join("store.sock").exists(), "the socket is removed on exit");
    let _ = std::fs::remove_dir_all(&dir);
}
