//! Lab: does any real proto3-JSON serializer emit the envelope/v0 "pinned signer form" for A2A 1.0 (v1.0.1)
//! messages, and do real parsers reject the non-pinned forms that §4.4 says receivers MUST reject?
//!
//!   gen   <dir> <n> <seed>   random A2A messages (binary) + prost-reflect and pbjson JSON + mutants
//!   check <dir> <ser...>     pinned-form check of each serializer's output, JCS cross-comparison,
//!                            and the parser verdicts on the mutants (Rust parsers here, TS ones from files)
//!   probe                    hand-picked edge cases, printed one per line
//!
//! The pinned form checker below is written from §4.4 of docs/due-diligence.md and the proto3 JSON mapping
//! (https://protobuf.dev/programming-guides/json/), independently of the serializers under test.

use base64::{engine::general_purpose::STANDARD, Engine};
use prost::Message as _;
use prost_reflect::{
    DescriptorPool, DeserializeOptions, DynamicMessage, FieldDescriptor, Kind, MapKey, MessageDescriptor,
    SerializeOptions, Value as PV,
};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value as J};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

#[allow(clippy::all, dead_code)]
pub mod a2a {
    include!(concat!(env!("OUT_DIR"), "/lf.a2a.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/lf.a2a.v1.serde.rs"));
}

const FDS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/a2a.binpb"));
const PKG: &str = "lf.a2a.v1";
/// Top-level messages that travel as envelope bodies or are signed on their own (AgentCard).
const TYPES: &[&str] = &[
    "SendMessageRequest",
    "SendMessageResponse",
    "StreamResponse",
    "Task",
    "AgentCard",
    "ListTasksRequest",
    "ListTasksResponse",
    "TaskPushNotificationConfig",
    "GetTaskRequest",
];

fn pool() -> DescriptorPool {
    DescriptorPool::decode(FDS).expect("descriptor pool")
}

// ---------------------------------------------------------------------------------------------------------
// Random generator (biased to defaults, presence corner cases, timestamp precisions and odd doubles)

struct Gen {
    rng: ChaCha20Rng,
}

impl Gen {
    fn string(&mut self) -> String {
        let pool = [
            "", "", "a", "task-1", "é", "\u{1F600}", "\u{0}", "line\nbreak", "\"q\"", "</script>", "\u{2028}",
            "TASK_STATE_WORKING", "0",
        ];
        if self.rng.gen_bool(0.2) {
            let n = self.rng.gen_range(1..12);
            (0..n).map(|_| char::from(self.rng.gen_range(b'a'..=b'z'))).collect()
        } else {
            pool.choose(&mut self.rng).unwrap().to_string()
        }
    }

    fn double(&mut self) -> f64 {
        let pool = [
            0.0, -0.0, 1.0, -1.0, 0.1, 1.5, 1e21, 1e-7, 9007199254740992.0, 9007199254740993.0, 5e-324,
            f64::MAX, 123456789.125, 1e300, 0.30000000000000004,
        ];
        match self.rng.gen_range(0..100) {
            0 => f64::NAN,
            1 => f64::INFINITY,
            2..=40 => *pool.choose(&mut self.rng).unwrap(),
            41..=70 => self.rng.gen_range(-1000i64..1000) as f64,
            _ => f64::from_bits(self.rng.gen::<u64>() & 0x7fef_ffff_ffff_ffff | (self.rng.gen::<u64>() & (1 << 63))),
        }
    }

    fn timestamp(&mut self, d: &MessageDescriptor) -> DynamicMessage {
        let mut m = DynamicMessage::new(d.clone());
        let secs: i64 = match self.rng.gen_range(0..100) {
            0 => 253_402_300_800,  // one past 9999-12-31T23:59:59Z: invalid
            1 => -62_135_596_801, // one before 0001-01-01: invalid
            2..=4 => 253_402_300_799,
            5..=7 => -62_135_596_800,
            8..=12 => 0,
            13..=17 => -1,
            _ => self.rng.gen_range(1_600_000_000..1_900_000_000),
        };
        let nanos: i32 = match self.rng.gen_range(0..100) {
            0 => 1_000_000_000, // invalid
            1 => -1,            // invalid
            2..=35 => 0,
            36..=55 => self.rng.gen_range(0..1000) * 1_000_000,
            56..=70 => self.rng.gen_range(0..1_000_000) * 1_000,
            71..=75 => 999_999_999,
            _ => self.rng.gen_range(0..1_000_000_000),
        };
        m.set_field_by_name("seconds", PV::I64(secs));
        m.set_field_by_name("nanos", PV::I32(nanos));
        m
    }

    fn value(&mut self, p: &DescriptorPool, depth: u32) -> DynamicMessage {
        let d = p.get_message_by_name("google.protobuf.Value").unwrap();
        let mut m = DynamicMessage::new(d);
        let k = if depth > 3 { self.rng.gen_range(0..4) } else { self.rng.gen_range(0..7) };
        match k {
            0 => m.set_field_by_name("null_value", PV::EnumNumber(0)),
            1 => m.set_field_by_name("number_value", PV::F64(self.double())),
            2 => m.set_field_by_name("string_value", PV::String(self.string())),
            3 => m.set_field_by_name("bool_value", PV::Bool(self.rng.gen())),
            4 => m.set_field_by_name("struct_value", PV::Message(self.structv(p, depth + 1))),
            5 => {
                let l = p.get_message_by_name("google.protobuf.ListValue").unwrap();
                let mut lm = DynamicMessage::new(l);
                let n = self.rng.gen_range(0..3);
                let vals = (0..n).map(|_| PV::Message(self.value(p, depth + 1))).collect();
                lm.set_field_by_name("values", PV::List(vals));
                m.set_field_by_name("list_value", PV::Message(lm));
            }
            _ => {
                // (a Value with no kind set has no JSON form; it is covered by `probe`, not generated here)
                m.set_field_by_name("number_value", PV::F64(self.rng.gen_range(0..100) as f64));
            }
        }
        m
    }

    fn structv(&mut self, p: &DescriptorPool, depth: u32) -> DynamicMessage {
        let d = p.get_message_by_name("google.protobuf.Struct").unwrap();
        let mut m = DynamicMessage::new(d);
        let n = self.rng.gen_range(0..4);
        let mut map = std::collections::HashMap::new();
        for _ in 0..n {
            map.insert(MapKey::String(self.string()), PV::Message(self.value(p, depth + 1)));
        }
        m.set_field_by_name("fields", PV::Map(map));
        m
    }

    fn scalar(&mut self, p: &DescriptorPool, f: &FieldDescriptor, kind: &Kind, depth: u32, want_default: bool) -> Option<PV> {
        Some(match kind {
            Kind::String => PV::String(if want_default { String::new() } else { self.string() }),
            Kind::Bool => PV::Bool(!want_default && self.rng.gen()),
            Kind::Int32 => PV::I32(if want_default {
                0
            } else {
                *[1, -1, 7, 100, i32::MAX, i32::MIN].choose(&mut self.rng).unwrap()
            }),
            Kind::Bytes => {
                let n = if want_default { 0 } else { self.rng.gen_range(1..9) };
                PV::Bytes((0..n).map(|_| self.rng.gen::<u8>()).collect::<Vec<u8>>().into())
            }
            Kind::Enum(e) => {
                if want_default {
                    PV::EnumNumber(0)
                } else if self.rng.gen_bool(0.05) {
                    PV::EnumNumber(77) // a value from a newer schema
                } else {
                    PV::EnumNumber(e.values().map(|v| v.number()).collect::<Vec<_>>().choose(&mut self.rng).copied().unwrap())
                }
            }
            Kind::Message(m) => match m.full_name() {
                "google.protobuf.Timestamp" => PV::Message(self.timestamp(m)),
                "google.protobuf.Struct" => PV::Message(self.structv(p, depth)),
                "google.protobuf.Value" => PV::Message(self.value(p, depth)),
                _ => {
                    if depth > 3 && !want_default {
                        return None;
                    }
                    PV::Message(if want_default { DynamicMessage::new(m.clone()) } else { self.message(p, m, depth + 1) })
                }
            },
            other => panic!("unexpected kind {other:?} in {}", f.full_name()),
        })
    }

    fn message(&mut self, p: &DescriptorPool, d: &MessageDescriptor, depth: u32) -> DynamicMessage {
        let mut m = DynamicMessage::new(d.clone());
        let mut oneofs_done = BTreeSet::new();
        for f in d.fields() {
            if let Some(o) = f.containing_oneof() {
                if !o.is_synthetic() {
                    if oneofs_done.contains(o.name()) {
                        continue;
                    }
                    oneofs_done.insert(o.name().to_string());
                    // choose one member (or none)
                    let members: Vec<_> = o.fields().collect();
                    if self.rng.gen_bool(0.85) {
                        let g = members.choose(&mut self.rng).unwrap().clone();
                        let dflt = self.rng.gen_bool(0.25);
                        if let Some(v) = self.scalar(p, &g, &g.kind(), depth, dflt) {
                            m.set_field(&g, v);
                        }
                    }
                    continue;
                }
            }
            if !self.rng.gen_bool(0.55) {
                continue;
            }
            if f.is_map() {
                let entry = match f.kind() {
                    Kind::Message(e) => e,
                    _ => unreachable!(),
                };
                let vf = entry.map_entry_value_field();
                let n = self.rng.gen_range(0..3);
                let mut map = std::collections::HashMap::new();
                for _ in 0..n {
                    let dflt = self.rng.gen_bool(0.2);
                    if let Some(v) = self.scalar(p, &vf, &vf.kind(), depth, dflt) {
                        map.insert(MapKey::String(self.string()), v);
                    }
                }
                m.set_field(&f, PV::Map(map));
            } else if f.is_list() {
                let n = self.rng.gen_range(0..3);
                let mut vals = vec![];
                for _ in 0..n {
                    let dflt = self.rng.gen_bool(0.15);
                    if let Some(v) = self.scalar(p, &f, &f.kind(), depth, dflt) {
                        vals.push(v);
                    }
                }
                m.set_field(&f, PV::List(vals));
            } else {
                let dflt = self.rng.gen_bool(if f.supports_presence() { 0.35 } else { 0.25 });
                if let Some(v) = self.scalar(p, &f, &f.kind(), depth, dflt) {
                    m.set_field(&f, v);
                }
            }
        }
        m
    }
}

// ---------------------------------------------------------------------------------------------------------
// Pinned signer form checker (§4.4). Returns violation classes with JSON paths.

fn is_canonical_b64(s: &str) -> bool {
    match STANDARD.decode(s) {
        Ok(b) => STANDARD.encode(b) == s,
        Err(_) => false,
    }
}

fn ts_class(s: &str) -> Option<&'static str> {
    let b = s.as_bytes();
    let base_ok = b.len() >= 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18].iter().all(|&i| b[i].is_ascii_digit());
    if !base_ok {
        return Some("ts-syntax");
    }
    let rest = &s[19..];
    let (frac, tz) = match rest.strip_prefix('.') {
        Some(r) => {
            let n = r.bytes().take_while(|c| c.is_ascii_digit()).count();
            (&r[..n], &r[n..])
        }
        None => ("", rest),
    };
    if tz != "Z" {
        return Some(if tz.eq_ignore_ascii_case("z") || tz.starts_with('+') || tz.starts_with('-') { "ts-offset" } else { "ts-syntax" });
    }
    if !matches!(frac.len(), 0 | 3 | 6 | 9) {
        return Some("ts-frac-digits");
    }
    // the mapping's generators emit the shortest of 0/3/6/9 digits that is exact
    if frac.len() >= 3 && frac.ends_with("000") {
        return Some("ts-frac-not-minimal");
    }
    None
}

fn is_default_json(f: &FieldDescriptor, v: &J) -> bool {
    if f.is_list() {
        return v.as_array().map(|a| a.is_empty()).unwrap_or(false);
    }
    if f.is_map() {
        return v.as_object().map(|a| a.is_empty()).unwrap_or(false);
    }
    match (f.kind(), v) {
        (Kind::String, J::String(s)) | (Kind::Bytes, J::String(s)) => s.is_empty(),
        (Kind::Bool, J::Bool(b)) => !b,
        (Kind::Int32, J::Number(n)) => n.as_f64() == Some(0.0),
        (Kind::Int32, J::String(s)) => s == "0",
        (Kind::Enum(e), J::String(s)) => e.get_value(0).map(|v| v.name() == s).unwrap_or(false),
        (Kind::Enum(_), J::Number(n)) => n.as_i64() == Some(0),
        _ => false,
    }
}

fn check_scalar(f: &FieldDescriptor, kind: &Kind, v: &J, path: &str, out: &mut Vec<(String, String)>) {
    let mut bad = |c: &str| out.push((c.to_string(), path.to_string()));
    match kind {
        Kind::String => {
            if !v.is_string() {
                bad("type");
            }
        }
        Kind::Bool => {
            if !v.is_boolean() {
                bad(if v.is_string() { "bool-as-string" } else { "type" });
            }
        }
        Kind::Int32 => match v {
            J::Number(n) if n.is_i64() => {}
            J::Number(_) => bad("int-not-integral-literal"),
            J::String(_) => bad("int32-as-string"),
            _ => bad("type"),
        },
        Kind::Bytes => match v {
            J::String(s) if is_canonical_b64(s) => {}
            J::String(_) => bad("bytes-not-std-padded-b64"),
            _ => bad("type"),
        },
        Kind::Enum(e) => match v {
            J::String(s) if e.get_value_by_name(s).is_some() => {}
            J::String(_) => bad("enum-unknown-name"),
            J::Number(_) => bad("enum-number"),
            _ => bad("type"),
        },
        Kind::Message(m) => check_msg(m, v, path, out),
        _ => bad("unexpected-kind"),
    }
    let _ = f;
}

fn check_msg(d: &MessageDescriptor, v: &J, path: &str, out: &mut Vec<(String, String)>) {
    match d.full_name() {
        "google.protobuf.Timestamp" => {
            match v.as_str() {
                Some(s) => {
                    if let Some(c) = ts_class(s) {
                        out.push((c.into(), path.into()))
                    }
                }
                None => out.push(("ts-not-string".into(), path.into())),
            }
            return;
        }
        "google.protobuf.Struct" => {
            if !v.is_object() {
                out.push(("struct-not-object".into(), path.into()));
            }
            return;
        }
        "google.protobuf.Value" => return,
        "google.protobuf.ListValue" => {
            if !v.is_array() {
                out.push(("type".into(), path.into()));
            }
            return;
        }
        _ => {}
    }
    let Some(obj) = v.as_object() else {
        out.push(("type".into(), path.into()));
        return;
    };
    let mut oneof_seen: BTreeMap<String, usize> = BTreeMap::new();
    for (k, val) in obj {
        let p = format!("{path}.{k}");
        let f = d.fields().find(|f| f.json_name() == k);
        let Some(f) = f else {
            if d.get_field_by_name(k).is_some() {
                out.push(("snake-case-name".into(), p));
            } else {
                out.push(("unknown-field".into(), p));
            }
            continue;
        };
        if let Some(o) = f.containing_oneof() {
            if !o.is_synthetic() {
                *oneof_seen.entry(o.name().into()).or_default() += 1;
            }
        }
        let is_value = matches!(f.kind(), Kind::Message(ref m) if m.full_name() == "google.protobuf.Value");
        if val.is_null() && !(is_value && !f.is_list() && !f.is_map()) {
            out.push(("null-for-absent".into(), p));
            continue;
        }
        if !f.supports_presence() && is_default_json(&f, val) {
            out.push(("implicit-presence-default-emitted".into(), p.clone()));
        }
        if f.is_map() {
            let Kind::Message(entry) = f.kind() else { unreachable!() };
            let vf = entry.map_entry_value_field();
            match val.as_object() {
                Some(m) => {
                    for (mk, mv) in m {
                        check_scalar(&vf, &vf.kind(), mv, &format!("{p}[{mk:?}]"), out)
                    }
                }
                None => out.push(("type".into(), p)),
            }
        } else if f.is_list() {
            match val.as_array() {
                Some(a) => {
                    for (i, e) in a.iter().enumerate() {
                        check_scalar(&f, &f.kind(), e, &format!("{p}[{i}]"), out)
                    }
                }
                None => out.push(("type".into(), p)),
            }
        } else {
            check_scalar(&f, &f.kind(), val, &p, out);
        }
    }
    for (o, n) in oneof_seen {
        if n > 1 {
            out.push(("oneof-multiple".into(), format!("{path}.<{o}>")));
        }
    }
}

pub fn pinned_violations(d: &MessageDescriptor, v: &J) -> Vec<(String, String)> {
    let mut out = vec![];
    check_msg(d, v, "$", &mut out);
    out
}

// ---------------------------------------------------------------------------------------------------------
// Serializers and parsers under test (Rust side)

fn ser_prost_reflect(m: &DynamicMessage) -> Result<String, String> {
    let mut buf = vec![];
    let mut s = serde_json::Serializer::new(&mut buf);
    m.serialize_with_options(&mut s, &SerializeOptions::new()).map_err(|e| e.to_string())?;
    Ok(String::from_utf8(buf).unwrap())
}

macro_rules! by_type {
    ($ty:expr, $T:ident => $body:expr) => {
        match $ty {
            "SendMessageRequest" => { type $T = a2a::SendMessageRequest; $body }
            "SendMessageResponse" => { type $T = a2a::SendMessageResponse; $body }
            "StreamResponse" => { type $T = a2a::StreamResponse; $body }
            "Task" => { type $T = a2a::Task; $body }
            "AgentCard" => { type $T = a2a::AgentCard; $body }
            "ListTasksRequest" => { type $T = a2a::ListTasksRequest; $body }
            "ListTasksResponse" => { type $T = a2a::ListTasksResponse; $body }
            "TaskPushNotificationConfig" => { type $T = a2a::TaskPushNotificationConfig; $body }
            "GetTaskRequest" => { type $T = a2a::GetTaskRequest; $body }
            other => panic!("type {other}"),
        }
    };
}

fn ser_pbjson(ty: &str, bin: &[u8]) -> Result<String, String> {
    by_type!(ty, T => {
        let m = T::decode(bin).map_err(|e| format!("decode: {e}"))?;
        serde_json::to_string(&m).map_err(|e| e.to_string())
    })
}

fn parse_prost_reflect(d: &MessageDescriptor, s: &str) -> Result<Vec<u8>, String> {
    let mut de = serde_json::Deserializer::from_str(s);
    let m = DynamicMessage::deserialize_with_options(d.clone(), &mut de, &DeserializeOptions::new()).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(m.encode_to_vec())
}

fn parse_pbjson(ty: &str, s: &str) -> Result<Vec<u8>, String> {
    by_type!(ty, T => {
        let m: T = serde_json::from_str(s).map_err(|e| e.to_string())?;
        Ok(m.encode_to_vec())
    })
}

fn same_message(d: &MessageDescriptor, a: &[u8], b: &[u8]) -> bool {
    match (DynamicMessage::decode(d.clone(), a), DynamicMessage::decode(d.clone(), b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn jcs(s: &str) -> Result<String, String> {
    let v: J = serde_json::from_str(s).map_err(|e| e.to_string())?;
    serde_json_canonicalizer::to_string(&v).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------------------------------------
// Mutations of a pinned-form JSON into forms §4.4 says a receiver MUST reject (or, for unknown-field, keep).

fn collect_sites(d: &MessageDescriptor, v: &J, path: Vec<J>, sites: &mut Vec<(Vec<J>, FieldDescriptor, bool)>, absent: &mut Vec<(Vec<J>, FieldDescriptor)>) {
    if d.full_name().starts_with("google.protobuf.") {
        return;
    }
    let Some(obj) = v.as_object() else { return };
    for f in d.fields() {
        match obj.get(f.json_name()) {
            Some(val) => {
                let mut p = path.clone();
                p.push(J::String(f.json_name().into()));
                sites.push((p.clone(), f.clone(), true));
                if let Kind::Message(m) = f.kind() {
                    if f.is_list() {
                        for (i, e) in val.as_array().into_iter().flatten().enumerate() {
                            let mut q = p.clone();
                            q.push(json!(i));
                            collect_sites(&m, e, q, sites, absent);
                        }
                    } else if f.is_map() {
                        let vf = m.map_entry_value_field();
                        if let Kind::Message(vm) = vf.kind() {
                            for (k, e) in val.as_object().into_iter().flatten() {
                                let mut q = p.clone();
                                q.push(J::String(k.clone()));
                                collect_sites(&vm, e, q, sites, absent);
                            }
                        }
                    } else {
                        collect_sites(&m, val, p, sites, absent);
                    }
                }
            }
            None => {
                let in_real_oneof = f.containing_oneof().map(|o| !o.is_synthetic()).unwrap_or(false);
                if !in_real_oneof {
                    absent.push((path.clone(), f.clone()));
                }
            }
        }
    }
}

fn at<'a>(root: &'a mut J, path: &[J]) -> &'a mut J {
    let mut cur = root;
    for k in path {
        cur = match k {
            J::String(s) => cur.get_mut(s.as_str()).unwrap(),
            J::Number(n) => cur.get_mut(n.as_u64().unwrap() as usize).unwrap(),
            _ => unreachable!(),
        };
    }
    cur
}

fn default_json(f: &FieldDescriptor) -> J {
    if f.is_list() {
        return json!([]);
    }
    if f.is_map() {
        return json!({});
    }
    match f.kind() {
        Kind::String | Kind::Bytes => json!(""),
        Kind::Bool => json!(false),
        Kind::Int32 => json!(0),
        Kind::Enum(e) => json!(e.get_value(0).unwrap().name()),
        _ => J::Null,
    }
}

const MUTATIONS: &[&str] = &[
    "identity (control)",
    "enum-number",
    "snake-case-name",
    "implicit-presence-default-emitted",
    "null-for-absent",
    "ts-frac-not-minimal",
    "ts-offset",
    "bytes-urlsafe-unpadded",
    "int32-as-string",
    "unknown-field",
];

fn mutate(kind: &str, d: &MessageDescriptor, v: &J, rng: &mut ChaCha20Rng) -> Option<J> {
    let mut sites = vec![];
    let mut absent = vec![];
    collect_sites(d, v, vec![], &mut sites, &mut absent);
    let mut out = v.clone();
    let scalar_sites = |pred: &dyn Fn(&FieldDescriptor, &J) -> bool, out: &J| -> Vec<Vec<J>> {
        let mut r = vec![];
        for (p, f, _) in &sites {
            let mut o = out.clone();
            let val = at(&mut o, p).clone();
            if f.is_list() {
                for (i, e) in val.as_array().into_iter().flatten().enumerate() {
                    if pred(f, e) {
                        let mut q = p.clone();
                        q.push(json!(i));
                        r.push(q);
                    }
                }
            } else if !f.is_map() && pred(f, &val) {
                r.push(p.clone());
            }
        }
        r
    };
    match kind {
        "enum-number" => {
            let c = scalar_sites(&|f, e| matches!(f.kind(), Kind::Enum(_)) && e.is_string(), &out);
            let p = c.choose(rng)?.clone();
            let (_, f, _) = sites.iter().find(|(sp, _, _)| p.starts_with(sp) && p.len() <= sp.len() + 1)?;
            let Kind::Enum(e) = f.kind() else { return None };
            let t = at(&mut out, &p);
            let n = e.get_value_by_name(t.as_str()?)?.number();
            *t = json!(n);
        }
        "snake-case-name" => {
            let c: Vec<_> = sites.iter().filter(|(_, f, _)| f.json_name() != f.name()).collect();
            let (p, f, _) = c.choose(rng)?;
            let parent = at(&mut out, &p[..p.len() - 1]).as_object_mut()?;
            let val = parent.remove(f.json_name())?;
            parent.insert(f.name().into(), val);
        }
        "implicit-presence-default-emitted" | "null-for-absent" => {
            let c: Vec<_> = absent
                .iter()
                .filter(|(_, f)| {
                    if kind == "null-for-absent" {
                        !matches!(f.kind(), Kind::Message(ref m) if m.full_name() == "google.protobuf.Value")
                    } else {
                        !f.supports_presence()
                    }
                })
                .collect();
            let (p, f) = c.choose(rng)?;
            let parent = at(&mut out, p).as_object_mut()?;
            let val = if kind == "null-for-absent" { J::Null } else { default_json(f) };
            parent.insert(f.json_name().into(), val);
        }
        "ts-frac-not-minimal" | "ts-offset" => {
            let c = scalar_sites(&|f, e| matches!(f.kind(), Kind::Message(ref m) if m.full_name() == "google.protobuf.Timestamp") && e.is_string(), &out);
            let p = c.choose(rng)?.clone();
            let t = at(&mut out, &p);
            let s = t.as_str()?.to_string();
            let core = s.strip_suffix('Z')?;
            if kind != "ts-offset" && core.split('.').nth(1).map(|f| f.len() > 6).unwrap_or(false) {
                return None;
            }
            *t = if kind == "ts-offset" {
                json!(format!("{core}+00:00"))
            } else if core.contains('.') {
                json!(format!("{core}000Z"))
            } else {
                json!(format!("{core}.000Z"))
            };
        }
        "bytes-urlsafe-unpadded" => {
            let c = scalar_sites(&|f, e| matches!(f.kind(), Kind::Bytes) && e.as_str().map(|s| !s.is_empty()).unwrap_or(false), &out);
            let p = c.choose(rng)?.clone();
            let t = at(&mut out, &p);
            let b = STANDARD.decode(t.as_str()?).ok()?;
            let u = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
            if u == t.as_str()? {
                return None;
            }
            *t = json!(u);
        }
        "int32-as-string" => {
            let c = scalar_sites(&|f, e| matches!(f.kind(), Kind::Int32) && e.is_number(), &out);
            let p = c.choose(rng)?.clone();
            let t = at(&mut out, &p);
            *t = json!(t.to_string());
        }
        "unknown-field" => {
            let objs: Vec<_> = std::iter::once(vec![])
                .chain(sites.iter().filter(|(_, f, _)| matches!(f.kind(), Kind::Message(ref m) if !m.full_name().starts_with("google.")) && !f.is_list() && !f.is_map()).map(|(p, _, _)| p.clone()))
                .collect();
            let p = objs.choose(rng)?;
            at(&mut out, p).as_object_mut()?.insert("webwayFutureField".into(), json!({"x": 1}));
        }
        "identity (control)" => {}
        _ => unreachable!(),
    }
    Some(out)
}

// ---------------------------------------------------------------------------------------------------------

fn read_jsonl(path: &Path) -> Vec<J> {
    let f = File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    BufReader::new(f).lines().map(|l| serde_json::from_str(&l.unwrap()).unwrap()).collect()
}

fn gen(dir: &Path, n: usize, seed: u64) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("a2a.binpb"), FDS).unwrap();
    let p = pool();
    let mut g = Gen { rng: ChaCha20Rng::seed_from_u64(seed) };
    let mut mrng = ChaCha20Rng::seed_from_u64(seed ^ 0x5eed);
    let mut cases = BufWriter::new(File::create(dir.join("cases.jsonl")).unwrap());
    let mut pr = BufWriter::new(File::create(dir.join("prost-reflect.jsonl")).unwrap());
    let mut pj = BufWriter::new(File::create(dir.join("pbjson.jsonl")).unwrap());
    let mut mu = BufWriter::new(File::create(dir.join("mutants.jsonl")).unwrap());
    let mut nm = 0;
    for i in 0..n {
        let ty = TYPES[i % TYPES.len()];
        let d = p.get_message_by_name(&format!("{PKG}.{ty}")).unwrap();
        let m = g.message(&p, &d, 0);
        let bin = m.encode_to_vec();
        writeln!(cases, "{}", json!({"i": i, "type": ty, "bin": STANDARD.encode(&bin)})).unwrap();
        let r1 = ser_prost_reflect(&m);
        let r2 = ser_pbjson(ty, &bin);
        for (w, r) in [(&mut pr, &r1), (&mut pj, &r2)] {
            let line = match r {
                Ok(s) => json!({"i": i, "json": s}),
                Err(e) => json!({"i": i, "err": e}),
            };
            writeln!(w, "{line}").unwrap();
        }
        // mutants are derived from a pinned-form base: prost-reflect output, if it passes the checker
        if let Ok(s) = &r1 {
            let v: J = serde_json::from_str(s).unwrap();
            if pinned_violations(&d, &v).is_empty() {
                for k in MUTATIONS {
                    if *k == "identity (control)" || mrng.gen_bool(0.25) {
                        if let Some(mv) = mutate(k, &d, &v, &mut mrng) {
                            writeln!(mu, "{}", json!({"i": i, "type": ty, "kind": k, "json": mv.to_string()})).unwrap();
                            nm += 1;
                        }
                    }
                }
            }
        }
    }
    eprintln!("gen: {n} cases, {nm} mutants in {}", dir.display());
}

#[derive(Default)]
struct Tally {
    n: usize,
    err: usize,
    err_kinds: BTreeMap<String, usize>,
    pinned_ok: usize,
    viol_cases: BTreeMap<String, usize>,
    examples: BTreeMap<String, String>,
    jcs_eq_ref: usize,
    jcs_ne_ref: usize,
    ne_example: Option<String>,
}

fn err_kind(e: &str) -> String {
    let e = e.to_lowercase();
    for (k, pat) in [
        ("timestamp out of range", "range"),
        ("timestamp out of range", "invalid timestamp"),
        ("timestamp out of range", "timestamp"),
        ("non-finite double in Value", "nan"),
        ("non-finite double in Value", "infinit"),
        ("non-finite double in Value", "finite"),
        ("Value with no kind", "kind"),
    ] {
        if e.contains(pat) {
            return k.into();
        }
    }
    let mut s: String = e.chars().take(70).collect();
    s.retain(|c| !c.is_ascii_digit());
    s
}

fn check(dir: &Path, sers: &[String]) {
    let p = pool();
    let cases = read_jsonl(&dir.join("cases.jsonl"));
    let reference: Vec<J> = read_jsonl(&dir.join("prost-reflect.jsonl"));
    println!("cases: {}", cases.len());
    // ground truth for "is this message representable at all": prost-reflect error or not
    for name in sers {
        let rows = read_jsonl(&dir.join(format!("{name}.jsonl")));
        assert_eq!(rows.len(), cases.len(), "{name}");
        let mut t = Tally::default();
        for ((c, r), rf) in cases.iter().zip(&rows).zip(&reference) {
            t.n += 1;
            let ci = c["i"].clone();
            let ty = c["type"].as_str().unwrap();
            let d = p.get_message_by_name(&format!("{PKG}.{ty}")).unwrap();
            let Some(s) = r["json"].as_str() else {
                t.err += 1;
                *t.err_kinds.entry(err_kind(r["err"].as_str().unwrap_or("?"))).or_default() += 1;
                continue;
            };
            let v: J = match serde_json::from_str(s) {
                Ok(v) => v,
                Err(e) => {
                    t.err += 1;
                    *t.err_kinds.entry(format!("emitted invalid JSON: {e}")).or_default() += 1;
                    continue;
                }
            };
            let viol = pinned_violations(&d, &v);
            if viol.is_empty() {
                t.pinned_ok += 1;
            }
            let classes: BTreeSet<_> = viol.iter().map(|(c, _)| c.clone()).collect();
            for c in classes {
                *t.viol_cases.entry(c.clone()).or_default() += 1;
                t.examples.entry(c.clone()).or_insert_with(|| {
                    let (_, path) = viol.iter().find(|(k, _)| *k == c).unwrap();
                    let val = lookup(&v, path);
                    format!("case {} {ty} at {path} = {}", ci, val)
                });
            }
            if let Some(rs) = rf["json"].as_str() {
                if jcs(s) == jcs(rs) {
                    t.jcs_eq_ref += 1;
                } else {
                    t.jcs_ne_ref += 1;
                    if t.ne_example.is_none() {
                        t.ne_example = Some(format!("case {}: {}", c["i"], first_diff(&jcs(rs).unwrap(), &jcs(s).unwrap())));
                    }
                }
            }
        }
        let emitted = t.n - t.err;
        println!("\n## {name}");
        println!("  emitted {emitted}/{} ({} refused)", t.n, t.err);
        for (k, v) in &t.err_kinds {
            println!("    refused: {k}: {v}");
        }
        println!(
            "  pinned form: {}/{emitted} pass ({:.2} %)",
            t.pinned_ok,
            100.0 * t.pinned_ok as f64 / emitted.max(1) as f64
        );
        for (k, v) in &t.viol_cases {
            println!("    {k}: {v} cases ({:.2} %)   e.g. {}", 100.0 * *v as f64 / emitted.max(1) as f64, t.examples[k]);
        }
        println!("  JCS-equal to prost-reflect: {} / differ: {}", t.jcs_eq_ref, t.jcs_ne_ref);
        if let Some(e) = t.ne_example {
            println!("    first diff: {e}");
        }
    }
    // Parsers on mutants
    let mutants = read_jsonl(&dir.join("mutants.jsonl"));
    let bins: BTreeMap<u64, Vec<u8>> = cases.iter().map(|c| (c["i"].as_u64().unwrap(), STANDARD.decode(c["bin"].as_str().unwrap()).unwrap())).collect();
    let mut parsers: Vec<(String, Vec<J>)> = vec![];
    let mut rust_pr = vec![];
    let mut rust_pj = vec![];
    for m in &mutants {
        let ty = m["type"].as_str().unwrap();
        let d = p.get_message_by_name(&format!("{PKG}.{ty}")).unwrap();
        let s = m["json"].as_str().unwrap();
        for (out, r) in [(&mut rust_pr, parse_prost_reflect(&d, s)), (&mut rust_pj, parse_pbjson(ty, s))] {
            out.push(match r {
                Ok(b) => json!({"ok": true, "bin": STANDARD.encode(b)}),
                Err(e) => json!({"ok": false, "err": e}),
            });
        }
    }
    parsers.push(("prost-reflect".into(), rust_pr));
    parsers.push(("pbjson".into(), rust_pj));
    for name in sers {
        let f = dir.join(format!("{name}.parse.jsonl"));
        if f.exists() {
            parsers.push((name.clone(), read_jsonl(&f)));
        }
    }
    roundtrips(dir, &p, &mutants);
    card_canon(dir);
    println!("\n## parsers on {} mutants (accepted = parsed without error; same = decodes to the original message)", mutants.len());
    let kinds: BTreeSet<&str> = mutants.iter().map(|m| m["kind"].as_str().unwrap()).collect();
    print!("  {:36} {:>6} {:>8}", "mutation", "n", "checker");
    for (n, _) in &parsers {
        print!(" {:>24}", n);
    }
    println!();
    for k in &kinds {
        let idx: Vec<usize> = (0..mutants.len()).filter(|&i| mutants[i]["kind"] == *k).collect();
        let checker_rejects = idx
            .iter()
            .filter(|&&i| {
                let ty = mutants[i]["type"].as_str().unwrap();
                let d = p.get_message_by_name(&format!("{PKG}.{ty}")).unwrap();
                let v: J = serde_json::from_str(mutants[i]["json"].as_str().unwrap()).unwrap();
                !pinned_violations(&d, &v).is_empty()
            })
            .count();
        print!("  {:36} {:>6} {:>7}r", k, idx.len(), checker_rejects);
        for (_, rows) in &parsers {
            let acc = idx.iter().filter(|&&i| rows[i]["ok"] == true).count();
            let same = idx
                .iter()
                .filter(|&&i| {
                    rows[i]["ok"] == true && {
                        let ty = mutants[i]["type"].as_str().unwrap();
                        let d = p.get_message_by_name(&format!("{PKG}.{ty}")).unwrap();
                        let b = STANDARD.decode(rows[i]["bin"].as_str().unwrap()).unwrap();
                        same_message(&d, &bins[&mutants[i]["i"].as_u64().unwrap()], &b)
                    }
                })
                .count();
            print!(" {:>13}a {:>8}s", acc, same);
            if std::env::var("DEBUG").is_ok() {
                for &i in idx.iter().filter(|&&i| rows[i]["ok"] == true).take(400) {
                    let ty = mutants[i]["type"].as_str().unwrap();
                    let d = p.get_message_by_name(&format!("{PKG}.{ty}")).unwrap();
                    let b = STANDARD.decode(rows[i]["bin"].as_str().unwrap()).unwrap();
                    if !same_message(&d, &bins[&mutants[i]["i"].as_u64().unwrap()], &b) {
                        let orig = ser_prost_reflect(&DynamicMessage::decode(d.clone(), &bins[&mutants[i]["i"].as_u64().unwrap()][..]).unwrap()).unwrap();
                        let got = ser_prost_reflect(&DynamicMessage::decode(d.clone(), &b[..]).unwrap()).unwrap_or_default();
                        let od = format!("{:?}", DynamicMessage::decode(d.clone(), &bins[&mutants[i]["i"].as_u64().unwrap()][..]).unwrap());
                        let gd = format!("{:?}", DynamicMessage::decode(d.clone(), &b[..]).unwrap());
                        eprintln!("[{k}] non-same case {}: {}{}", mutants[i]["i"], first_diff(&jcs(&orig).unwrap(), &jcs(&got).unwrap()), first_diff(&od, &gd));
                        break;
                    }
                }
            }
        }
        println!();
    }
}

/// Typed JSON -> JSON round trips of pinned-form inputs (identity mutants): does the library give back the same JCS?
fn roundtrips(dir: &Path, p: &DescriptorPool, mutants: &[J]) {
    let ids: Vec<&J> = mutants.iter().filter(|m| m["kind"] == "identity (control)").collect();
    let mut libs: Vec<(String, Vec<Result<String, String>>)> = vec![];
    let mut pr = vec![];
    let mut pj = vec![];
    for m in &ids {
        let ty = m["type"].as_str().unwrap();
        let d = p.get_message_by_name(&format!("{PKG}.{ty}")).unwrap();
        let s = m["json"].as_str().unwrap();
        pr.push(parse_prost_reflect(&d, s).and_then(|b| ser_prost_reflect(&DynamicMessage::decode(d.clone(), &b[..]).unwrap())));
        pj.push(serde_json::from_str::<J>(s).map_err(|e| e.to_string()).and_then(|_| {
            by_type!(ty, T => {
                let t: T = serde_json::from_str(s).map_err(|e| e.to_string())?;
                serde_json::to_string(&t).map_err(|e| e.to_string())
            })
        }));
    }
    libs.push(("prost-reflect".into(), pr));
    libs.push(("pbjson".into(), pj));
    for name in ["bufbuild", "a2a-js"] {
        let f = dir.join(format!("{name}.rt.jsonl"));
        if f.exists() {
            libs.push((name.into(), read_jsonl(&f).iter().map(|r| r["json"].as_str().map(String::from).ok_or_else(|| r["err"].to_string())).collect()));
        }
    }
    println!("\n## typed JSON -> JSON round trip of {} pinned-form inputs (JCS-identical = signature survives)", ids.len());
    for (name, rows) in &libs {
        let mut same = 0;
        let mut err = 0;
        let mut ex = None;
        for (m, r) in ids.iter().zip(rows) {
            match r {
                Ok(o) if jcs(o) == jcs(m["json"].as_str().unwrap()) => same += 1,
                Ok(o) => {
                    if ex.is_none() {
                        ex = Some(format!("case {}: {}", m["i"], first_diff(&jcs(m["json"].as_str().unwrap()).unwrap(), &jcs(o).unwrap())));
                    }
                }
                Err(_) => err += 1,
            }
        }
        println!("  {name:14} identical {same}/{} ({:.2} %), changed {}, error {err}", ids.len(), 100.0 * same as f64 / ids.len() as f64, ids.len() - same - err);
        if let Some(e) = ex {
            println!("    first change: {e}");
        }
    }
}

/// a2a-js `canonicalizeAgentCard` (A2A §8.4.1) vs JCS of the pinned card, and its behaviour on mutated cards.
fn card_canon(dir: &Path) {
    let f = dir.join("a2a-js.cardcanon.jsonl");
    if !f.exists() {
        return;
    }
    let rows = read_jsonl(&f);
    let muts: BTreeMap<(u64, String), String> = read_jsonl(&dir.join("mutants.jsonl"))
        .into_iter()
        .filter(|m| m["type"] == "AgentCard")
        .map(|m| ((m["i"].as_u64().unwrap(), m["kind"].as_str().unwrap().to_string()), m["json"].as_str().unwrap().to_string()))
        .collect();
    let mut base: BTreeMap<u64, String> = BTreeMap::new();
    let (mut n, mut agree, mut err) = (0, 0, 0);
    let mut ex = None;
    let mut why: BTreeMap<&str, usize> = BTreeMap::new();
    for r in rows.iter().filter(|r| r["kind"] == "identity (control)") {
        n += 1;
        let i = r["i"].as_u64().unwrap();
        let Some(c) = r["canon"].as_str() else {
            err += 1;
            continue;
        };
        base.insert(i, c.to_string());
        let mut v: J = serde_json::from_str(&muts[&(i, "identity (control)".to_string())]).unwrap();
        v.as_object_mut().unwrap().remove("signatures");
        let ours = serde_json_canonicalizer::to_string(&v).unwrap();
        if ours == c {
            agree += 1;
        } else {
            // classify: what does cleanEmpty remove that the pinned form keeps?
            let s = ours.as_str();
            if s.contains(":{}") { *why.entry("empty message/Struct (e.g. `capabilities: {}`)").or_default() += 1; }
            if s.contains(":\"\"") { *why.entry("empty string inside Struct or map").or_default() += 1; }
            if s.contains(":[]") { *why.entry("empty list inside Struct").or_default() += 1; }
            if s.contains(":null") { *why.entry("null inside Struct").or_default() += 1; }
            if ex.is_none() {
                ex = Some(format!("case {i}: {}", first_diff(&ours, c)));
            }
        }
    }
    println!("\n## A2A §8.4.1 card canonicalisation (a2a-js canonicalizeAgentCard) vs JCS(pinned card minus signatures)");
    println!("  {n} AgentCards: equal {agree} ({:.2} %), differ {}, a2a-js error {err}", 100.0 * agree as f64 / n.max(1) as f64, n - agree - err);
    for (k, v) in &why {
        println!("    differing cards containing {k}: {v}");
    }
    if let Some(e) = ex {
        println!("    first diff (ours vs a2a-js): {e}");
    }
    println!("  mutated cards whose a2a-js canonical form is unchanged (a signature over the original still verifies):");
    let mut by: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for r in rows.iter().filter(|r| r["kind"] != "identity (control)") {
        let i = r["i"].as_u64().unwrap();
        let Some(b) = base.get(&i) else { continue };
        let e = by.entry(r["kind"].as_str().unwrap().to_string()).or_default();
        e.0 += 1;
        if r["canon"].as_str() == Some(b.as_str()) {
            e.1 += 1;
        }
    }
    for (k, (t, same)) in by {
        println!("    {k:36} {same:>6}/{t:<6} ({:.1} %)", 100.0 * same as f64 / t.max(1) as f64);
    }
}

fn lookup(v: &J, path: &str) -> String {
    // best effort: walk "$.a.b[0]" paths, used for examples only
    let mut cur = v;
    let rest = path.trim_start_matches('$');
    for seg in rest.split('.').filter(|s| !s.is_empty()) {
        let (name, idx) = match seg.find('[') {
            Some(i) => (&seg[..i], Some(&seg[i..])),
            None => (seg, None),
        };
        cur = match cur.get(name) {
            Some(x) => x,
            None => return "?".into(),
        };
        if let Some(ix) = idx {
            for part in ix.split(']').filter(|s| !s.is_empty()) {
                let k = &part[1..];
                cur = match k.parse::<usize>() {
                    Ok(n) => match cur.get(n) {
                        Some(x) => x,
                        None => return "?".into(),
                    },
                    Err(_) => match cur.get(k.trim_matches('"')) {
                        Some(x) => x,
                        None => return "?".into(),
                    },
                };
            }
        }
    }
    let s = cur.to_string();
    if s.len() > 80 {
        format!("{}…", &s[..s.char_indices().nth(80).map(|(i, _)| i).unwrap_or(s.len())])
    } else {
        s
    }
}

fn first_diff(a: &str, b: &str) -> String {
    let i = a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count();
    let i = (0..=i).rev().find(|&j| a.is_char_boundary(j) && b.is_char_boundary(j)).unwrap_or(0);
    let s = i.saturating_sub(40);
    let s = (0..=s).rev().find(|&j| a.is_char_boundary(j) && b.is_char_boundary(j)).unwrap_or(0);
    let cut = |x: &str| x[s..].chars().take(90).collect::<String>();
    format!("\n      ref: …{}\n      got: …{}", cut(a), cut(b))
}

fn probe() {
    let p = pool();
    for j in [r#"{"metadata":{"a":null}}"#, r#"{"metadata":{"a":[null]}}"#, r#"{"metadata":{"a":1}}"#] {
        let d = p.get_message_by_name("lf.a2a.v1.Task").unwrap();
        let a = parse_prost_reflect(&d, j).unwrap();
        let b = parse_pbjson("Task", j).unwrap();
        println!("parse {j}\n  prost-reflect bin: {:02x?}\n  pbjson bin:        {:02x?}  same={}", a, b, same_message(&d, &a, &b));
    }
    {
        // Part{data: Value{}} - a Value with no kind set has no JSON form in the mapping
        let part = p.get_message_by_name("lf.a2a.v1.Part").unwrap();
        let v = DynamicMessage::new(p.get_message_by_name("google.protobuf.Value").unwrap());
        let mut m = DynamicMessage::new(part.clone());
        m.set_field_by_name("data", PV::Message(v));
        let mut t = DynamicMessage::new(p.get_message_by_name("lf.a2a.v1.Message").unwrap());
        t.set_field_by_name("parts", PV::List(vec![PV::Message(m)]));
        let mut r = DynamicMessage::new(p.get_message_by_name("lf.a2a.v1.SendMessageRequest").unwrap());
        r.set_field_by_name("message", PV::Message(t));
        println!("SendMessageRequest{{message.parts[0].data = Value{{}} (no kind)}}\n  prost-reflect: {:?}\n  pbjson:        {:?}", ser_prost_reflect(&r), ser_pbjson("SendMessageRequest", &r.encode_to_vec()));
    }
    let task = p.get_message_by_name("lf.a2a.v1.Task").unwrap();
    let part = p.get_message_by_name("lf.a2a.v1.Part").unwrap();
    let cfg = p.get_message_by_name("lf.a2a.v1.SendMessageConfiguration").unwrap();
    let show = |label: &str, d: &MessageDescriptor, m: &DynamicMessage| {
        let bin = m.encode_to_vec();
        let ty = d.name();
        let pr = ser_prost_reflect(m);
        let pj = if TYPES.contains(&ty) { ser_pbjson(ty, &bin) } else { Err("n/a".into()) };
        println!("{label}\n  prost-reflect: {pr:?}\n  pbjson:        {pj:?}");
    };
    // explicit presence at default
    let mut m = DynamicMessage::new(cfg.clone());
    m.set_field_by_name("history_length", PV::I32(0));
    show("SendMessageConfiguration{historyLength: 0}", &cfg, &m);
    let mut m = DynamicMessage::new(part.clone());
    m.set_field_by_name("text", PV::String(String::new()));
    show("Part{text: \"\"}", &part, &m);
    let mut m = DynamicMessage::new(task.clone());
    let ts = p.get_message_by_name("google.protobuf.Timestamp").unwrap();
    let st = p.get_message_by_name("lf.a2a.v1.TaskStatus").unwrap();
    for nanos in [0, 120_000_000, 123_456_000, 1] {
        let mut t = DynamicMessage::new(ts.clone());
        t.set_field_by_name("seconds", PV::I64(1_762_646_400));
        t.set_field_by_name("nanos", PV::I32(nanos));
        let mut s = DynamicMessage::new(st.clone());
        s.set_field_by_name("timestamp", PV::Message(t));
        m.set_field_by_name("status", PV::Message(s));
        show(&format!("Task{{status.timestamp nanos={nanos}}}"), &task, &m);
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("gen") => gen(Path::new(&a[2]), a[3].parse().unwrap(), a[4].parse().unwrap()),
        Some("check") => check(Path::new(&a[2]), &a[3..]),
        Some("probe") => probe(),
        _ => {
            eprintln!("usage: gen <dir> <n> <seed> | check <dir> <ser...> | probe");
            std::process::exit(2)
        }
    }
}
