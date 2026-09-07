use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, LinkType, Options, Parser, Tag, TagEnd};
use weft_core::Address;

pub const MAX_INPUT: usize = weft_core::record::MAX_INLINE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Links {
    pub record: &'static str,
    pub blob: &'static str,
}

impl Links {
    pub const WEFT: Self = Self { record: "weft:", blob: "weft://blob/" };
}

pub fn render(markdown: &str, links: &Links) -> String {
    let text = if markdown.len() > MAX_INPUT { "" } else { markdown };
    let options = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    let mut out = String::with_capacity(text.len().saturating_mul(2));
    let mut suppress = 0u32;
    for event in Parser::new_ext(text, options) {
        match event {
            Event::Start(tag) => start(&mut out, &tag, &mut suppress, links),
            Event::End(tag) => end(&mut out, tag, &mut suppress),
            Event::Text(t) | Event::Code(t) if suppress > 0 => {
                let _ = t;
            }
            Event::Text(t) => escape(&mut out, &t),
            Event::Code(t) => {
                out.push_str("<code>");
                escape(&mut out, &t);
                out.push_str("</code>");
            }
            Event::SoftBreak => out.push('\n'),
            Event::HardBreak => out.push_str("<br>"),
            Event::Rule => out.push_str("<hr>"),
            Event::TaskListMarker(_)
            | Event::Html(_)
            | Event::InlineHtml(_)
            | Event::InlineMath(_)
            | Event::DisplayMath(_)
            | Event::FootnoteReference(_) => {}
        }
    }
    out
}

fn start(out: &mut String, tag: &Tag<'_>, suppress: &mut u32, links: &Links) {
    match tag {
        Tag::Paragraph => out.push_str("<p>"),
        Tag::Heading { level, .. } => {
            out.push('<');
            out.push_str(heading(*level));
            out.push('>');
        }
        Tag::BlockQuote(_) => out.push_str("<blockquote>"),
        Tag::CodeBlock(kind) => {
            out.push_str("<pre><code");
            if let CodeBlockKind::Fenced(lang) = kind
                && !lang.is_empty()
                && lang.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                out.push_str(" class=\"lang-");
                out.push_str(lang);
                out.push('"');
            }
            out.push('>');
        }
        Tag::List(Some(_)) => out.push_str("<ol>"),
        Tag::List(None) => out.push_str("<ul>"),
        Tag::Item => out.push_str("<li>"),
        Tag::Emphasis => out.push_str("<em>"),
        Tag::Strong => out.push_str("<strong>"),
        Tag::Strikethrough => out.push_str("<del>"),
        Tag::Table(_) => out.push_str("<table>"),
        Tag::TableHead => out.push_str("<thead><tr>"),
        Tag::TableRow => out.push_str("<tr>"),
        Tag::TableCell => out.push_str("<td>"),
        Tag::Link { dest_url, link_type, .. } => {
            if matches!(link_type, LinkType::Email) {
                *suppress = suppress.saturating_add(1);
                return;
            }
            if let Some(address) = record_address(dest_url) {
                out.push_str("<a href=\"");
                out.push_str(links.record);
                out.push_str(&address.to_string());
                out.push_str("\">");
            } else if safe_web(dest_url) {
                out.push_str("<a href=\"");
                escape(out, dest_url);
                out.push_str("\" rel=\"noopener\">");
            } else {
                *suppress = suppress.saturating_add(1);
            }
        }
        Tag::Image { dest_url, title, .. } => {
            *suppress = suppress.saturating_add(1);
            if let Some(address) = record_address(dest_url) {
                out.push_str("<img src=\"");
                out.push_str(links.blob);
                out.push_str(&address.to_string());
                out.push_str("\" alt=\"");
                escape(out, title);
                out.push_str("\">");
            }
        }
        Tag::HtmlBlock
        | Tag::FootnoteDefinition(_)
        | Tag::DefinitionList
        | Tag::DefinitionListTitle
        | Tag::DefinitionListDefinition
        | Tag::MetadataBlock(_)
        | Tag::Superscript
        | Tag::Subscript => *suppress = suppress.saturating_add(1),
    }
}

fn end(out: &mut String, tag: TagEnd, suppress: &mut u32) {
    match tag {
        TagEnd::Paragraph => out.push_str("</p>"),
        TagEnd::Heading(level) => {
            out.push_str("</");
            out.push_str(heading(level));
            out.push('>');
        }
        TagEnd::BlockQuote(_) => out.push_str("</blockquote>"),
        TagEnd::CodeBlock => out.push_str("</code></pre>"),
        TagEnd::List(true) => out.push_str("</ol>"),
        TagEnd::List(false) => out.push_str("</ul>"),
        TagEnd::Item => out.push_str("</li>"),
        TagEnd::Emphasis => out.push_str("</em>"),
        TagEnd::Strong => out.push_str("</strong>"),
        TagEnd::Strikethrough => out.push_str("</del>"),
        TagEnd::Table => out.push_str("</table>"),
        TagEnd::TableHead => out.push_str("</tr></thead>"),
        TagEnd::TableRow => out.push_str("</tr>"),
        TagEnd::TableCell => out.push_str("</td>"),
        TagEnd::Link => {
            if *suppress > 0 {
                *suppress = suppress.saturating_sub(1);
            } else {
                out.push_str("</a>");
            }
        }
        TagEnd::Image
        | TagEnd::HtmlBlock
        | TagEnd::FootnoteDefinition
        | TagEnd::DefinitionList
        | TagEnd::DefinitionListTitle
        | TagEnd::DefinitionListDefinition
        | TagEnd::MetadataBlock(_)
        | TagEnd::Superscript
        | TagEnd::Subscript => *suppress = suppress.saturating_sub(1),
    }
}

fn heading(level: HeadingLevel) -> &'static str {
    match level {
        HeadingLevel::H1 => "h1",
        HeadingLevel::H2 => "h2",
        HeadingLevel::H3 => "h3",
        HeadingLevel::H4 => "h4",
        HeadingLevel::H5 => "h5",
        HeadingLevel::H6 => "h6",
    }
}

fn record_address(url: &str) -> Option<Address> {
    url.strip_prefix("weft:").and_then(|rest| rest.parse().ok())
}

fn safe_web(url: &str) -> bool {
    url.starts_with("https://") && !url.contains(|c: char| c.is_control())
}

pub fn escape(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::Links;

    fn render(markdown: &str) -> String {
        super::render(markdown, &Links::WEFT)
    }

    #[test]
    fn basic_markdown() {
        let html = render("# Title\n\nSome *em* and **strong** and `code`.\n\n- a\n- b\n");
        assert_eq!(
            html,
            "<h1>Title</h1><p>Some <em>em</em> and <strong>strong</strong> and <code>code</code>.</p><ul><li>a</li><li>b</li></ul>"
        );
    }

    #[test]
    fn raw_html_is_dropped() {
        assert_eq!(render("<script>alert(1)</script>\n\ntext"), "<p>text</p>");
        assert_eq!(render("hello <b onclick=x>there</b>"), "<p>hello there</p>");
        assert_eq!(render("<img src=x onerror=alert(1)>"), "");
    }

    #[test]
    fn text_is_escaped() {
        assert_eq!(render("a < b & c > \"d\""), "<p>a &lt; b &amp; c &gt; &quot;d&quot;</p>");
        assert_eq!(render("`<i>`"), "<p><code>&lt;i&gt;</code></p>");
    }

    #[test]
    fn links_are_filtered() {
        let addr = weft_core::Address::of(b"x").to_string();
        assert_eq!(
            render(&format!("[a](weft:{addr})")),
            format!("<p><a href=\"weft:{addr}\">a</a></p>")
        );
        assert_eq!(
            render("[a](https://example.org/p?q=1)"),
            "<p><a href=\"https://example.org/p?q=1\" rel=\"noopener\">a</a></p>"
        );
        assert_eq!(render("[a](javascript:alert(1))"), "<p></p>");
        assert_eq!(render("[a](http://example.org)"), "<p></p>");
        assert_eq!(render("[a](weft:notanaddress)"), "<p></p>");
        assert_eq!(render("<mail@example.org>"), "<p></p>");
        assert_eq!(
            render("[x](https://a.org/\"onmouseover=\"alert(1))"),
            "<p><a href=\"https://a.org/&quot;onmouseover=&quot;alert(1)\" rel=\"noopener\">x</a></p>"
        );
    }

    #[test]
    fn images_only_from_blobs() {
        let addr = weft_core::Address::of(b"img").to_string();
        assert_eq!(
            render(&format!("![alt](weft:{addr} \"t\")")),
            format!("<p><img src=\"weft://blob/{addr}\" alt=\"t\"></p>")
        );
        assert_eq!(render("![alt](https://evil.example/x.png)"), "<p></p>");
        assert_eq!(render("![alt](data:image/png;base64,AAAA)"), "<p></p>");
    }

    #[test]
    fn links_follow_the_map() {
        let gateway = Links { record: "/", blob: "/blob/" };
        let addr = weft_core::Address::of(b"x").to_string();
        assert_eq!(
            super::render(&format!("[a](weft:{addr}) ![i](weft:{addr})"), &gateway),
            format!("<p><a href=\"/{addr}\">a</a> <img src=\"/blob/{addr}\" alt=\"\"></p>")
        );
        assert_eq!(
            super::render("[a](https://example.org/)", &gateway),
            "<p><a href=\"https://example.org/\" rel=\"noopener\">a</a></p>"
        );
    }

    #[test]
    fn code_block_language_is_restricted() {
        assert_eq!(
            render("```rust\nlet x = 1;\n```"),
            "<pre><code class=\"lang-rust\">let x = 1;\n</code></pre>"
        );
        assert_eq!(render("```a\" onload=\"x\nx\n```"), "<pre><code>x\n</code></pre>");
    }

    #[test]
    fn tables_and_rules() {
        assert_eq!(
            render("| a | b |\n|---|---|\n| 1 | 2 |"),
            "<table><thead><tr><td>a</td><td>b</td></tr></thead><tr><td>1</td><td>2</td></tr></table>"
        );
        assert_eq!(render("---"), "<hr>");
        assert_eq!(render("~~gone~~"), "<p><del>gone</del></p>");
    }

    #[test]
    fn oversized_input_renders_nothing() {
        let big = "a".repeat(super::MAX_INPUT + 1);
        assert_eq!(render(&big), "");
    }
}
