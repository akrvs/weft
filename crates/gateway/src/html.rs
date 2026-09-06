use weft_resolve::{Page, escape};

pub const STYLE: &str = "\
:root { color-scheme: light dark; font: 15px/1.5 system-ui, sans-serif; }
body { margin: 0; }
#bar { display: flex; gap: 8px; align-items: center; height: 48px; padding: 0 8px; border-bottom: 1px solid #8884; }
#bar form { display: flex; flex: 1; gap: 8px; }
#bar input { flex: 1; font: inherit; font-family: ui-monospace, monospace; padding: 6px 10px; border: 1px solid #8886; border-radius: 6px; background: transparent; color: inherit; }
#bar button { font: inherit; padding: 6px 12px; border: 1px solid #8886; border-radius: 6px; background: transparent; color: inherit; cursor: pointer; }
#provenance { display: grid; grid-template-columns: auto 1fr; gap: 0 12px; padding: 6px 12px; font-family: ui-monospace, monospace; font-size: 12px; border-bottom: 1px solid #8884; word-break: break-all; }
#provenance dl { display: contents; }
#provenance dt { opacity: .6; }
#provenance dd { margin: 0; }
#status { grid-column: 1 / -1; font-weight: 600; }
#status.bad { color: #c33; }
main { max-width: 72ch; margin: 0 auto; padding: 16px; }
main img { max-width: 100%; }
main pre { overflow: auto; padding: 8px; border: 1px solid #8884; border-radius: 6px; }
main table { border-collapse: collapse; }
main td { border: 1px solid #8884; padding: 4px 8px; }
";

fn open(out: &mut String, title: &str, value: &str) {
    out.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>");
    escape(out, title);
    out.push_str("</title><link rel=\"stylesheet\" href=\"/style.css\"></head><body>");
    out.push_str("<header id=\"bar\"><form action=\"/go\" method=\"get\">");
    out.push_str("<input name=\"q\" type=\"text\" spellcheck=\"false\" autocomplete=\"off\" ");
    out.push_str("placeholder=\"address, author/name, or domain\" value=\"");
    escape(out, value);
    out.push_str("\"><button type=\"submit\">open</button></form></header>");
}

fn close(out: &mut String) {
    out.push_str("</body></html>");
}

fn row(out: &mut String, key: &str, value: &str) {
    out.push_str("<dt>");
    escape(out, key);
    out.push_str("</dt><dd>");
    escape(out, value);
    out.push_str("</dd>");
}

pub fn form() -> String {
    let mut out = String::with_capacity(1024);
    open(&mut out, "weft gateway", "");
    out.push_str("<main><p>Open a signed record by address, by <code>author/name</code>, or by ");
    out.push_str(
        "domain. Every page comes with the signature that was checked to serve it.</p></main>",
    );
    close(&mut out);
    out
}

pub fn error(status: u16, message: &str) -> String {
    let mut out = String::with_capacity(1024);
    open(&mut out, &format!("{status} weft gateway"), "");
    out.push_str("<section id=\"provenance\"><span id=\"status\" class=\"bad\">");
    escape(&mut out, &status.to_string());
    out.push(' ');
    escape(&mut out, message);
    out.push_str("</span></section>");
    close(&mut out);
    out
}

pub fn page(page: &Page, input: &str) -> String {
    let mut out = String::with_capacity(page.html.len().saturating_add(2048));
    open(&mut out, &format!("{} weft", page.kind), input);
    out.push_str("<section id=\"provenance\"><span id=\"status\">");
    out.push_str(if page.author == page.signer {
        "signed by root key"
    } else {
        "signed by an authorized device"
    });
    out.push_str("</span><dl>");
    row(&mut out, "address", &page.address);
    row(&mut out, "kind", &page.kind);
    row(&mut out, "author", &page.author);
    row(&mut out, "signer", &page.signer);
    row(&mut out, "created", &iso(page.created));
    row(&mut out, "served by", &page.source);
    row(&mut out, "name", &page.name);
    out.push_str("</dl></section><main>");
    match &page.blob {
        Some(blob) => {
            out.push_str("<p><a href=\"/blob/");
            escape(&mut out, blob);
            out.push_str("\">download blob</a></p><img src=\"/blob/");
            escape(&mut out, blob);
            out.push_str("\" alt=\"\">");
        }
        None => out.push_str(&page.html),
    }
    out.push_str("</main>");
    close(&mut out);
    out
}

pub fn iso(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso(1_757_116_799), "2025-09-05T23:59:59Z");
        assert_eq!(iso(4_102_444_800), "2100-01-01T00:00:00Z");
    }

    #[test]
    fn everything_dynamic_is_escaped() {
        let e = error(400, "<script>alert(1)</script>");
        assert!(!e.contains("<script>"));
        assert!(e.contains("&lt;script&gt;"));
        let p = Page {
            address: "a".into(),
            kind: "\"><img src=x onerror=alert(1)>".into(),
            author: "a".into(),
            signer: "b".into(),
            created: 0,
            source: "local store".into(),
            name: "address".into(),
            html: "<p>ok</p>".into(),
            blob: None,
        };
        let html = page(&p, "\"><script>");
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("signed by an authorized device"));
        assert!(html.contains("<p>ok</p>"));
    }
}
