//! Strict I-JSON parser (RFC 7493 + envelope/v0 §4.1) and RFC 8785 (JCS) serialiser.
//!
//! The parser keeps members in received order and reports duplicates instead of silently
//! overwriting, which off-the-shelf parsers do. It is deliberately small: it exists so the
//! vectors are checked against an implementation of exactly the rules in the spec.

use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// The parsed double. JCS serialises numbers from their double value.
    Number(f64),
    String(String),
    Array(Vec<Value>),
    /// Members in received order. Duplicate names are rejected at parse time.
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_object_mut(&mut self) -> Option<&mut Vec<(String, Value)>> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }
    /// Object without the named members (order of the rest kept).
    pub fn without(&self, names: &[&str]) -> Value {
        match self {
            Value::Object(m) => Value::Object(
                m.iter().filter(|(k, _)| !names.contains(&k.as_str())).cloned().collect(),
            ),
            other => other.clone(),
        }
    }
    /// RFC 6901 JSON Pointer lookup.
    pub fn pointer(&self, ptr: &str) -> Option<&Value> {
        if ptr.is_empty() {
            return Some(self);
        }
        let rest = ptr.strip_prefix('/')?;
        let mut cur = self;
        for raw in rest.split('/') {
            let tok = raw.replace("~1", "/").replace("~0", "~");
            cur = match cur {
                Value::Object(_) => cur.get(&tok)?,
                Value::Array(a) => {
                    if tok == "0" || (!tok.starts_with('0') && tok.bytes().all(|b| b.is_ascii_digit()) && !tok.is_empty()) {
                        a.get(tok.parse::<usize>().ok()?)?
                    } else {
                        return None;
                    }
                }
                _ => return None,
            };
        }
        Some(cur)
    }
}

/// Parse failure reasons, named as in spec §10.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    NotJson,
    InvalidUnicode,
    DuplicateKey,
    NumberOutOfRange,
    UnsafeInteger,
    TooDeep,
}

impl ParseError {
    pub fn reason(self) -> &'static str {
        match self {
            ParseError::NotJson => "not-json",
            ParseError::InvalidUnicode => "invalid-unicode",
            ParseError::DuplicateKey => "duplicate-key",
            ParseError::NumberOutOfRange => "number-out-of-range",
            ParseError::UnsafeInteger => "unsafe-integer",
            ParseError::TooDeep => "too-deep",
        }
    }
}

pub const MAX_DEPTH: usize = 64;
/// 2^53 − 1.
pub const MAX_SAFE_INTEGER: f64 = 9007199254740991.0;

pub fn parse(bytes: &[u8]) -> Result<Value, ParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidUnicode)?;
    let mut p = Parser { s: text.as_bytes(), i: 0, text };
    p.ws();
    let v = p.value(1)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(ParseError::NotJson);
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    text: &'a str,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn eat(&mut self, lit: &str) -> Result<(), ParseError> {
        if self.s[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(ParseError::NotJson)
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        match self.peek().ok_or(ParseError::NotJson)? {
            b'{' => {
                if depth > MAX_DEPTH {
                    return Err(ParseError::TooDeep);
                }
                self.i += 1;
                let mut members: Vec<(String, Value)> = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Value::Object(members));
                }
                loop {
                    self.ws();
                    if self.peek() != Some(b'"') {
                        return Err(ParseError::NotJson);
                    }
                    let k = self.string()?;
                    self.ws();
                    self.eat(":")?;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    if members.iter().any(|(mk, _)| *mk == k) {
                        return Err(ParseError::DuplicateKey);
                    }
                    members.push((k, v));
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Value::Object(members));
                        }
                        _ => return Err(ParseError::NotJson),
                    }
                }
            }
            b'[' => {
                if depth > MAX_DEPTH {
                    return Err(ParseError::TooDeep);
                }
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                loop {
                    self.ws();
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Value::Array(items));
                        }
                        _ => return Err(ParseError::NotJson),
                    }
                }
            }
            b'"' => Ok(Value::String(self.string()?)),
            b't' => self.eat("true").map(|_| Value::Bool(true)),
            b'f' => self.eat("false").map(|_| Value::Bool(false)),
            b'n' => self.eat("null").map(|_| Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(ParseError::NotJson),
        }
    }
    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(ParseError::NotJson),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ParseError::NotJson);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ParseError::NotJson);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        let v: f64 = self.text[start..self.i].parse().map_err(|_| ParseError::NotJson)?;
        if !v.is_finite() {
            return Err(ParseError::NumberOutOfRange);
        }
        // ENV-100 is a rule on the parsed value, not the spelling: an integral value beyond
        // ±(2^53 − 1) is rejected however it is written (9007199254740992, 1e16, 9007199254740993.0).
        // Every double of magnitude ≥ 2^53 is integral, so this is |v| > MAX_SAFE_INTEGER. Because JCS
        // output re-parses to the same value, parse(jcs(parse(x))) succeeds whenever parse(x) does.
        if v.abs() > MAX_SAFE_INTEGER {
            return Err(ParseError::UnsafeInteger);
        }
        Ok(Value::Number(v))
    }
    fn hex4(&mut self) -> Result<u32, ParseError> {
        let h = self.text.get(self.i..self.i + 4).ok_or(ParseError::NotJson)?;
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ParseError::NotJson);
        }
        self.i += 4;
        Ok(u32::from_str_radix(h, 16).unwrap())
    }
    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or(ParseError::NotJson)?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or(ParseError::NotJson)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let u = self.hex4()?;
                            if (0xD800..0xDC00).contains(&u) {
                                // need a trailing low surrogate escape
                                if !self.s[self.i..].starts_with(b"\\u") {
                                    return Err(ParseError::InvalidUnicode);
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(ParseError::InvalidUnicode);
                                }
                                let cp = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                                out.push(char::from_u32(cp).unwrap());
                            } else if (0xDC00..0xE000).contains(&u) {
                                return Err(ParseError::InvalidUnicode);
                            } else {
                                out.push(char::from_u32(u).unwrap());
                            }
                        }
                        _ => return Err(ParseError::NotJson),
                    }
                }
                0x00..=0x1f => return Err(ParseError::NotJson),
                _ => {
                    // copy one UTF-8 scalar (input is valid UTF-8)
                    let ch = self.text[self.i..].chars().next().unwrap();
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }
}

/// RFC 8785 canonical serialisation.
pub fn jcs(v: &Value) -> String {
    let mut out = String::new();
    write_jcs(v, &mut out);
    out
}

fn write_jcs(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&es6_number(*n)),
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut sorted: Vec<&(String, Value)> = m.iter().collect();
            sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (k, x)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_jcs(x, out);
            }
            out.push('}');
        }
    }
}

fn write_string(s: &str, out: &mut String) {
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
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ECMAScript Number.prototype.toString for finite doubles (ECMA-262 Number::toString, radix 10).
pub fn es6_number(v: f64) -> String {
    assert!(v.is_finite());
    if v == 0.0 {
        return "0".into();
    }
    if v < 0.0 {
        return format!("-{}", es6_number(-v));
    }
    // Rust's `{:e}` gives the shortest round-trip digits: "d[.ddd]e<exp>".
    let sci = format!("{:e}", v);
    let (mant, exp) = sci.split_once('e').unwrap();
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp.parse::<i32>().unwrap() + 1; // v = 0.d1d2..dk × 10^n
    if k <= n && n <= 21 {
        format!("{}{}", digits, "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        if k == 1 {
            format!("{}e{}{}", digits, sign, e.abs())
        } else {
            format!("{}.{}e{}{}", &digits[..1], &digits[1..], sign, e.abs())
        }
    }
}

/// Non-canonical serialisation helpers for building test inputs.
/// `pretty` keeps member order as stored and adds whitespace.
pub fn to_text(v: &Value, pretty: bool) -> String {
    let mut out = String::new();
    write_text(v, pretty, 0, &mut out);
    out
}

fn write_text(v: &Value, pretty: bool, ind: usize, out: &mut String) {
    let nl = |out: &mut String, ind: usize| {
        if pretty {
            out.push('\n');
            out.push_str(&"  ".repeat(ind));
        }
    };
    match v {
        Value::Array(a) if !a.is_empty() => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                nl(out, ind + 1);
                write_text(x, pretty, ind + 1, out);
            }
            nl(out, ind);
            out.push(']');
        }
        Value::Object(m) if !m.is_empty() => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                nl(out, ind + 1);
                write_string(k, out);
                out.push(':');
                if pretty {
                    out.push(' ');
                }
                write_text(x, pretty, ind + 1, out);
            }
            nl(out, ind);
            out.push('}');
        }
        other => write_jcs(other, out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es6_numbers() {
        let cases = [
            (1.0, "1"),
            (-0.0, "0"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (1e-7, "1e-7"),
            (0.000001, "0.000001"),
            (123.456, "123.456"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (9007199254740991.0, "9007199254740991"),
            (0.1 + 0.2, "0.30000000000000004"),
            (-1.5e-9, "-1.5e-9"),
            (333333333.3333333, "333333333.3333333"),
        ];
        for (v, s) in cases {
            assert_eq!(es6_number(v), s, "{v}");
        }
    }

    #[test]
    fn rfc8785_sorting_example() {
        // RFC 8785 §3.2.3 sorting example.
        let input = r#"{"€":"Euro Sign","\r":"Carriage Return","דּ":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji: Grinning Face","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis"}"#;
        let v = parse(input.as_bytes()).unwrap();
        let keys: Vec<String> = match serde_json::from_str::<serde_json::Value>(&jcs(&v)).unwrap() {
            serde_json::Value::Object(m) => m.into_iter().map(|(k, _)| k).collect(),
            _ => unreachable!(),
        };
        assert_eq!(keys, ["\r", "1", "\u{80}", "\u{f6}", "\u{20ac}", "\u{1f600}", "\u{fb33}"]);
    }

    /// parse(jcs(parse(x))) succeeds whenever parse(x) does, and JCS is idempotent.
    #[test]
    fn jcs_output_reparses() {
        let mut corpus: Vec<String> = [
            "[1.0, -0, 1e-7, 0.000001, 5e-324, 9007199254740991, -9007199254740991, 0.1, 4.5e-10]",
            "[9007199254740991.4, 9007199254740990.5, 1e15, 123456789012345.67, 1e-400, 2.2250738585072014e-308]",
            r#"{"\u20ac":1,"\ud83d\ude00":"x\u0000\u001f\"\\","a":[[],{}]}"#,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // Pseudo-random doubles across the whole exponent range (xorshift, fixed seed).
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let v = f64::from_bits(x);
            if v.is_finite() {
                corpus.push(format!("[{v:e}]"));
                corpus.push(format!("[{v}]"));
            }
        }
        for text in &corpus {
            if let Ok(v) = parse(text.as_bytes()) {
                let canon = jcs(&v);
                let again = parse(canon.as_bytes()).unwrap_or_else(|e| panic!("{text} -> {canon} -> {e:?}"));
                assert_eq!(jcs(&again), canon, "JCS is idempotent for {text}");
            }
        }
    }

    #[test]
    fn parse_errors() {
        assert_eq!(parse(br#"{"a":1,"a":2}"#), Err(ParseError::DuplicateKey));
        assert_eq!(parse(br#"{"a":"\ud800"}"#), Err(ParseError::InvalidUnicode));
        assert_eq!(parse(br#"[9007199254740992]"#), Err(ParseError::UnsafeInteger));
        assert_eq!(parse(br#"[1e400]"#), Err(ParseError::NumberOutOfRange));
        assert_eq!(parse(b"[\xff]"), Err(ParseError::InvalidUnicode));
        assert!(parse(br#"[9007199254740991, -9007199254740991, 9.007199254740991e15, 1e-300]"#).is_ok());
        for spelled in ["[1e16]", "[9007199254740993.0]", "[1e20]", "[123456789012345678e2]", "[1e300]", "[-9.007199254740992e15]"] {
            assert_eq!(parse(spelled.as_bytes()), Err(ParseError::UnsafeInteger), "{spelled}");
        }
    }
}
