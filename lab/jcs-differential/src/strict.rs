//! Duplicate-key rejection (RFC 7493 §2.3) in front of serde_json::Value, which silently keeps the last key.
//!
//! A first pass walks the text with a visitor that only remembers keys per object and builds nothing; then the
//! normal parse builds the Value. An earlier version built the Value in its own visitor and broke when a
//! dependency switched on serde_json's `arbitrary_precision` feature (numbers then arrive as a private
//! one-key map). This pass builds nothing and skips that one magic key, so the Value is always serde_json's own.

use serde::de::{Deserialize, Deserializer, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

struct NoDup;

impl<'de> Deserialize<'de> for NoDup {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = NoDup;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("JSON") }
            fn visit_bool<E>(self, _: bool) -> Result<NoDup, E> { Ok(NoDup) }
            fn visit_i64<E>(self, _: i64) -> Result<NoDup, E> { Ok(NoDup) }
            fn visit_u64<E>(self, _: u64) -> Result<NoDup, E> { Ok(NoDup) }
            fn visit_f64<E>(self, _: f64) -> Result<NoDup, E> { Ok(NoDup) }
            fn visit_str<E>(self, _: &str) -> Result<NoDup, E> { Ok(NoDup) }
            fn visit_unit<E>(self) -> Result<NoDup, E> { Ok(NoDup) }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<NoDup, A::Error> {
                while a.next_element::<NoDup>()?.is_some() {}
                Ok(NoDup)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<NoDup, A::Error> {
                let mut seen = HashSet::new();
                while let Some(k) = a.next_key::<String>()? {
                    if k == "$serde_json::private::Number" { a.next_value::<IgnoredAny>()?; continue; }
                    a.next_value::<NoDup>()?;
                    if !seen.insert(k.clone()) { return Err(A::Error::custom(format!("duplicate key {:?}", k))); }
                }
                Ok(NoDup)
            }
        }
        d.deserialize_any(V)
    }
}

pub fn parse(t: &str) -> Result<Value, String> {
    serde_json::from_str::<NoDup>(t).map_err(|e| e.to_string())?;
    serde_json::from_str::<Value>(t).map_err(|e| e.to_string())
}
