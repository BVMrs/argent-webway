//! RFC 8785 (JCS) for the values this tool handles: objects, arrays, strings, booleans, null and integers.
//! Non-integer numbers never occur in audit/v0 objects, so they are refused rather than formatted.

use serde_json::Value;

pub fn jcs(v: &Value) -> Vec<u8> {
    let mut out = String::new();
    write(v, &mut out);
    out.into_bytes()
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string())
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string())
            } else {
                panic!("non-integer number in JCS input: {n}")
            }
        }
        Value::String(s) => write_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            // RFC 8785 §3.2.3: sort by UTF-16 code units.
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(k, out);
                out.push(':');
                write(&m[*k], out);
            }
            out.push('}');
        }
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_and_escapes() {
        let v = json!({"b": 1, "a": [true, null, "x\n\u{1}é"], "\u{e9}": 0, "A": -3});
        assert_eq!(
            String::from_utf8(jcs(&v)).unwrap(),
            "{\"A\":-3,\"a\":[true,null,\"x\\n\\u0001é\"],\"b\":1,\"é\":0}"
        );
    }

    #[test]
    fn utf16_order() {
        // U+1F600 (surrogates D83D DE00) sorts before U+FF61 in UTF-16, after it in UTF-8/code points.
        let v = json!({"\u{ff61}": 1, "\u{1f600}": 2});
        assert_eq!(
            String::from_utf8(jcs(&v)).unwrap(),
            "{\"\u{1f600}\":2,\"\u{ff61}\":1}"
        );
    }
}
