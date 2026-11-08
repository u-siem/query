//! Text helpers shared by the query library, the CLI and the TUI.

use usiem::event::{FieldValue, Timestamp};

/// `YYYY-MM-DD hh:mm:ss.mmm` in UTC; the shape forensic timelines use.
pub fn format_time(t: Timestamp) -> String {
    let rfc = t.to_rfc3339();
    let Some(body) = rfc.strip_suffix('Z') else {
        return rfc;
    };
    let (seconds, fraction) = body.split_once('.').unwrap_or((body, ""));
    let millis: String = fraction.chars().chain("000".chars()).take(3).collect();
    format!("{}.{millis}", seconds.replacen('T', " ", 1))
}

/// Quotes a value for use in a query when it isn't a plain word.
pub fn query_literal(text: &str) -> String {
    let plain = !text.is_empty()
        && !text
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '(' | ')' | ':' | '|' | '*' | '?'));
    if plain {
        text.to_string()
    } else {
        format!("\"{}\"", escape_quotes(text))
    }
}

/// Escapes `"` for use inside an already quoted query value.
pub fn escape_quotes(text: &str) -> String {
    text.replace('"', "\\\"")
}

/// Short display text for a value: times as `YYYY-MM-DD hh:mm:ss.mmm`,
/// arrays comma-joined, objects as `{k=v ...}`, bytes as hex.
pub fn format_value(value: &FieldValue) -> String {
    match value {
        FieldValue::Time(t) => format_time(*t),
        FieldValue::Array(items) => items
            .iter()
            .map(format_value)
            .collect::<Vec<_>>()
            .join(", "),
        FieldValue::Object(map) => {
            let mut entries: Vec<_> = map
                .iter()
                .map(|(k, v)| format!("{k}={}", format_value(v)))
                .collect();
            entries.sort();
            format!("{{{}}}", entries.join(" "))
        }
        FieldValue::Bytes(b) => {
            use std::fmt::Write;
            let mut hex = String::with_capacity(b.len() * 2);
            for byte in b {
                let _ = write!(hex, "{byte:02x}");
            }
            hex
        }
        other => other.to_string(),
    }
}

/// Cuts `text` to at most `width` characters, marking the cut with `…`.
pub fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Lower-case ASCII words joined by `-`, for ids and file names:
/// `"Bob's logons"` → `"bob-s-logons"`.
pub fn slug(text: &str) -> String {
    let mut slug = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    slug.trim_end_matches('-').to_string()
}
