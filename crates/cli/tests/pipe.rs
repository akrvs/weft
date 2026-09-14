#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use weft_home::Home;

#[test]
fn a_closed_stdout_pipe_ends_the_command_quietly() {
    let dir = std::env::temp_dir().join(format!("weft-pipe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = Home::new(dir.clone());
    let mut relays = String::new();
    for n in 0..1500u32 {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&n.to_be_bytes());
        relays.push_str(&iroh::SecretKey::from_bytes(&seed).public().to_string());
        relays.push('\n');
    }
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("relays"), relays).unwrap();
    assert_eq!(home.relays().unwrap().len(), 1500);
    let mut child = Command::new(env!("CARGO_BIN_EXE_weft"))
        .arg("--home")
        .arg(&dir)
        .args(["relay", "list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut first).unwrap();
    assert_eq!(first.trim(), home.relays().unwrap()[0].to_string());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", out.status);
    assert!(out.stderr.is_empty(), "{}", String::from_utf8_lossy(&out.stderr));
    let _ = std::fs::remove_dir_all(&dir);
}
