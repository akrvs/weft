#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iroh::EndpointAddr;
use weft_home::{Home, Relay};

fn id(n: u8) -> String {
    iroh::SecretKey::from_bytes(&[n; 32]).public().to_string()
}

#[test]
fn entries_parse_print_and_dial_their_addresses() {
    let bare: Relay = id(1).parse().unwrap();
    assert!(bare.addrs.is_empty());
    assert_eq!(bare.to_string(), id(1));
    let text = format!("{}@10.0.0.2:4433,[fd00::2]:4433,10.0.0.2:4433", id(1));
    let full: Relay = text.parse().unwrap();
    assert_eq!(full.addrs.len(), 2, "duplicates fold");
    assert_eq!(full.to_string(), format!("{}@10.0.0.2:4433,[fd00::2]:4433", id(1)));
    let addr: EndpointAddr = (&full).into();
    assert_eq!(addr.id, full.id);
    assert_eq!(addr.ip_addrs().count(), 2);
    let again: Relay = full.to_string().parse().unwrap();
    assert_eq!(again, full);
}

#[test]
fn bad_entries_are_refused() {
    for bad in [
        "notakey".to_owned(),
        format!("{}@", id(1)),
        format!("{}@10.0.0.2", id(1)),
        format!("{}@10.0.0.2:0", id(1)),
        format!("{}@0.0.0.0:4433", id(1)),
        format!("{}@host.example:4433", id(1)),
        format!(
            "{}@{}",
            id(1),
            (1..=9).map(|n| format!("10.0.0.{n}:1")).collect::<Vec<_>>().join(",")
        ),
    ] {
        assert!(bad.parse::<Relay>().is_err(), "{bad}");
    }
}

#[test]
fn the_list_replaces_an_entry_for_the_same_id() {
    let dir = std::env::temp_dir().join(format!("weft-home-{}-relays", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let home = Home::new(dir.clone());
    assert!(home.relays().unwrap().is_empty());
    home.add_relay(id(1).parse().unwrap()).unwrap();
    home.add_relay(id(2).parse().unwrap()).unwrap();
    home.add_relay(id(1).parse().unwrap()).unwrap();
    assert_eq!(home.relays().unwrap().len(), 2);
    let addressed: Relay = format!("{}@192.168.1.9:4433", id(1)).parse().unwrap();
    home.add_relay(addressed.clone()).unwrap();
    let relays = home.relays().unwrap();
    assert_eq!(relays.len(), 2);
    assert_eq!(relays[0], addressed, "the first entry keeps its place with new addresses");
    std::fs::write(dir.join("relays"), "garbage\n").unwrap();
    assert!(home.relays().is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
