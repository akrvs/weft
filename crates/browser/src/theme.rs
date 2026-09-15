use gtk::gio::prelude::*;
use gtk::gio::{BusType, Cancellable, DBusCallFlags, DBusProxy, DBusProxyFlags};
use gtk::glib::Variant;
use tauri::Webview;

const NAMESPACE: &str = "org.freedesktop.appearance";
const KEY: &str = "color-scheme";
const TIMEOUT_MS: i32 = 1000;

#[derive(Debug)]
pub struct Watch {
    _portal: Option<DBusProxy>,
}

fn portal() -> Option<DBusProxy> {
    DBusProxy::for_bus_sync(
        BusType::Session,
        DBusProxyFlags::NONE,
        None,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Settings",
        Cancellable::NONE,
    )
    .ok()
}

fn scheme(value: &Variant) -> Option<&'static str> {
    let mut value = value.clone();
    while let Some(inner) = value.as_variant() {
        value = inner;
    }
    match value.get::<u32>()? {
        1 => Some("dark"),
        2 => Some("light"),
        _ => None,
    }
}

pub fn current() -> Option<&'static str> {
    let reply = portal()?
        .call_sync(
            "Read",
            Some(&(NAMESPACE, KEY).to_variant()),
            DBusCallFlags::NONE,
            TIMEOUT_MS,
            Cancellable::NONE,
        )
        .ok()?;
    scheme(&reply.child_value(0))
}

pub fn script(theme: Option<&str>) -> String {
    match theme {
        Some(theme) => format!("document.documentElement.dataset.theme='{theme}';"),
        None => "delete document.documentElement.dataset.theme;".to_owned(),
    }
}

pub fn watch(chrome: &Webview) -> Watch {
    let Some(proxy) = portal() else { return Watch { _portal: None } };
    let chrome = chrome.clone();
    proxy.connect_g_signal(move |_, _, signal, parameters| {
        if signal != "SettingChanged" || parameters.n_children() != 3 {
            return;
        }
        let namespace = parameters.child_value(0).get::<String>();
        let key = parameters.child_value(1).get::<String>();
        if namespace.as_deref() == Some(NAMESPACE) && key.as_deref() == Some(KEY) {
            let _ = chrome.eval(script(scheme(&parameters.child_value(2))));
        }
    });
    Watch { _portal: Some(proxy) }
}
