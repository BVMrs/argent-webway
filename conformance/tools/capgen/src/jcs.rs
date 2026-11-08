//! JCS (RFC 8785) for the subset this extension uses: objects, arrays, strings, integers,
//! booleans, null. serde_json without `preserve_order` keeps object keys sorted by bytes, which
//! equals JCS order for ASCII keys; non-ASCII keys and non-integer numbers are refused.

use serde_json::Value;

pub fn canonical(v: &Value) -> Option<String> {
    check(v)?;
    serde_json::to_string(v).ok()
}

fn check(v: &Value) -> Option<()> {
    match v {
        Value::Number(n) => {
            let i = n.as_i64()?;
            if i.unsigned_abs() > (1u64 << 53) {
                return None;
            }
            Some(())
        }
        Value::Array(a) => a.iter().try_for_each(check),
        Value::Object(o) => o.iter().try_for_each(|(k, v)| if k.is_ascii() { check(v) } else { None }),
        _ => Some(()),
    }
}

/// Parses bytes that must be exactly the JCS form of a JSON object.
pub fn parse_canonical_object(bytes: &[u8]) -> Option<serde_json::Map<String, Value>> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    let c = canonical(&v)?;
    if c.as_bytes() != bytes {
        return None;
    }
    match v {
        Value::Object(o) => Some(o),
        _ => None,
    }
}
