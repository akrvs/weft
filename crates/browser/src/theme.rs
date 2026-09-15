use std::cell::RefCell;

use gtk::gio::prelude::*;
use gtk::gio::{
    BusType, Cancellable, DBusCallFlags, DBusProxy, DBusProxyFlags, Settings as GSettings,
    SettingsSchemaSource,
};
use gtk::glib::Variant;
use gtk::prelude::*;
use tauri::Webview;

const NAMESPACE: &str = "org.freedesktop.appearance";
const KEY: &str = "color-scheme";
const SCHEMA: &str = "org.gnome.desktop.interface";
const TIMEOUT_MS: i32 = 1000;

#[derive(Debug)]
pub enum Source {
    Portal(DBusProxy),
    Settings(GSettings),
    Gtk(gtk::Settings),
}

thread_local! {
    static SOURCE: RefCell<Option<Source>> = const { RefCell::new(None) };
}

fn portal() -> Option<DBusProxy> {
    let proxy = DBusProxy::for_bus_sync(
        BusType::Session,
        DBusProxyFlags::NONE,
        None,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Settings",
        Cancellable::NONE,
    )
    .ok()?;
    portal_scheme(&proxy).map(|_| proxy)
}

fn gsettings() -> Option<GSettings> {
    let schema = SettingsSchemaSource::default()?.lookup(SCHEMA, true)?;
    schema.has_key(KEY).then(|| GSettings::new(SCHEMA))
}

pub fn source() -> Option<Source> {
    portal()
        .map(Source::Portal)
        .or_else(|| gsettings().map(Source::Settings))
        .or_else(|| gtk::Settings::default().map(Source::Gtk))
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

pub fn named(value: &str) -> Option<&'static str> {
    match value {
        "prefer-dark" => Some("dark"),
        "prefer-light" => Some("light"),
        _ => None,
    }
}

fn portal_scheme(proxy: &DBusProxy) -> Option<&'static str> {
    let reply = proxy
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

fn gtk_scheme(settings: &gtk::Settings) -> &'static str {
    if settings.is_gtk_application_prefer_dark_theme() { "dark" } else { "light" }
}

pub fn current(source: &Source) -> Option<&'static str> {
    match source {
        Source::Portal(proxy) => portal_scheme(proxy),
        Source::Settings(settings) => named(&settings.string(KEY))
            .or_else(|| gtk::Settings::default().map(|s| gtk_scheme(&s))),
        Source::Gtk(settings) => Some(gtk_scheme(settings)),
    }
}

pub fn script(theme: Option<&str>) -> String {
    match theme {
        Some(theme) => format!("document.documentElement.dataset.theme='{theme}';"),
        None => "delete document.documentElement.dataset.theme;".to_owned(),
    }
}

pub fn watch(chrome: &Webview, source: Option<Source>) {
    let chrome = chrome.clone();
    match &source {
        Some(Source::Portal(proxy)) => {
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
        }
        Some(Source::Settings(settings)) => {
            settings.connect_changed(Some(KEY), move |settings, _| {
                let _ = chrome.eval(script(current(&Source::Settings(settings.clone()))));
            });
        }
        Some(Source::Gtk(settings)) => {
            settings.connect_gtk_application_prefer_dark_theme_notify(move |settings| {
                let _ = chrome.eval(script(Some(gtk_scheme(settings))));
            });
        }
        None => {}
    }
    SOURCE.with(|slot| *slot.borrow_mut() = source);
}

#[cfg(test)]
mod tests {
    use super::{named, script};

    #[test]
    fn gsettings_values_map_to_themes() {
        assert_eq!(named("prefer-dark"), Some("dark"));
        assert_eq!(named("prefer-light"), Some("light"));
        assert_eq!(named("default"), None);
        assert_eq!(named(""), None);
        assert_eq!(script(Some("dark")), "document.documentElement.dataset.theme='dark';");
        assert_eq!(script(None), "delete document.documentElement.dataset.theme;");
    }
}
