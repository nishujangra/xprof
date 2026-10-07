// Copyright (C) 2026 Nishant <ndjangra1027@gmail.com>

//! Minimal JSON object rendering.
//!
//! One object, string-valued fields, written by hand: xprof has no `serde`
//! dependency, and a label/value report does not need one.

/// Render `fields` as a single flat JSON object, in the given order.
pub fn write_object(fields: &[(&str, &str)]) -> String {
    let body: Vec<String> = fields
        .iter()
        .map(|(key, value)| format!("\"{}\":\"{}\"", escape(key), escape(value)))
        .collect();

    format!("{{{}}}\n", body.join(","))
}

/// Escape the characters that would otherwise break a JSON string: quotes,
/// backslashes, and control characters (program names come straight from the
/// kernel and are not guaranteed to be printable).
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_fields_in_order() {
        let out = write_object(&[("mode", "native"), ("id", "142")]);
        assert_eq!(out, "{\"mode\":\"native\",\"id\":\"142\"}\n");
    }

    #[test]
    fn escapes_quotes_and_backslashes() {
        let out = write_object(&[("name", "weird\"name\\here")]);
        assert_eq!(out, "{\"name\":\"weird\\\"name\\\\here\"}\n");
    }
}
