//! Field formats of envelope/v0 §3.2: agent IDs, UUIDv7, timestamps, hashes, signatures.
//! Every decoder accepts exactly one string form per value.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lowercase, no padding.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Strict decoder: lowercase alphabet only, no padding, zero trailing bits.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
        buf &= (1 << bits) - 1;
    }
    // leftover bits must be fewer than 5 and all zero (canonical)
    if bits >= 5 || buf != 0 {
        return None;
    }
    if base32_encode(&out) != s {
        return None;
    }
    Some(out)
}

pub fn agent_id(pk: &[u8; 32]) -> String {
    format!("wwa:{}", base32_encode(pk))
}

pub fn parse_agent_id(s: &str) -> Option<[u8; 32]> {
    let rest = s.strip_prefix("wwa:")?;
    if rest.len() != 52 {
        return None;
    }
    base32_decode(rest)?.try_into().ok()
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Canonical base64url without padding (re-encoding must reproduce the input).
pub fn parse_b64url(s: &str) -> Option<Vec<u8>> {
    let b = URL_SAFE_NO_PAD.decode(s).ok()?;
    (b64url(&b) == s).then_some(b)
}

/// Canonical standard base64 with padding (proto3 `bytes` signer form).
pub fn is_canonical_b64std(s: &str) -> bool {
    match STANDARD.decode(s) {
        Ok(b) => STANDARD.encode(b) == s,
        Err(_) => false,
    }
}

pub fn hash_str(digest: &[u8; 32]) -> String {
    format!("blake3:{}", hex::encode(digest))
}

pub fn is_hash_str(s: &str) -> bool {
    match s.strip_prefix("blake3:") {
        Some(h) => h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        None => false,
    }
}

/// RFC 9562 UUIDv7 in lowercase hyphenated form.
pub fn is_uuid_v7(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
        };
        if !ok {
            return false;
        }
    }
    b[14] == b'7' && matches!(b[19], b'8' | b'9' | b'a' | b'b')
}

/// Builds a UUIDv7 from a millisecond timestamp and 10 bytes of "random" data (deterministic in vectors).
pub fn uuid_v7(unix_ms: u64, rand: [u8; 10]) -> String {
    let mut u = [0u8; 16];
    u[..6].copy_from_slice(&unix_ms.to_be_bytes()[2..]);
    u[6] = 0x70 | (rand[0] & 0x0f);
    u[7] = rand[1];
    u[8] = 0x80 | (rand[2] & 0x3f);
    u[9..].copy_from_slice(&rand[3..]);
    let h = hex::encode(u);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// Time as nanoseconds since the Unix epoch.
pub type Nanos = i128;
pub const SEC: Nanos = 1_000_000_000;

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM-DDTHH:MM:SS[.fff|.ffffff|.fffffffff]Z`, seconds 00–59.
pub fn parse_ts(s: &str) -> Option<Nanos> {
    let b = s.as_bytes();
    if b.len() < 20 || *b.last()? != b'Z' {
        return None;
    }
    let dig = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok())?
    };
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d) = (dig(0..4)?, dig(5..7)?, dig(8..10)?);
    let (h, mi, se) = (dig(11..13)?, dig(14..16)?, dig(17..19)?);
    let frac = &s[19..s.len() - 1];
    let nanos: i128 = match frac.len() {
        0 => 0,
        4 | 7 | 10 if frac.starts_with('.') && frac[1..].bytes().all(|c| c.is_ascii_digit()) => {
            let f = &frac[1..];
            f.parse::<i128>().ok()? * 10i128.pow(9 - f.len() as u32)
        }
        _ => return None,
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mo) || d < 1 || d > mdays[(mo - 1) as usize] || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let secs = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    Some(secs as i128 * SEC + nanos)
}

/// Formats with 0 or 3 fractional digits (whichever is exact), for building vectors.
pub fn fmt_ts(t: Nanos) -> String {
    let secs = t.div_euclid(SEC) as i64;
    let nanos = t.rem_euclid(SEC);
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, d) = civil_from_days(days);
    let base = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", y, m, d, rem / 3600, rem % 3600 / 60, rem % 60);
    if nanos == 0 {
        format!("{base}Z")
    } else if nanos % 1_000_000 == 0 {
        format!("{base}.{:03}Z", nanos / 1_000_000)
    } else {
        format!("{base}.{:09}Z", nanos)
    }
}

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58btc(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![];
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    std::iter::repeat_n('1', zeros)
        .chain(digits.iter().rev().map(|&d| B58[d as usize] as char))
        .collect()
}

/// `did:key` for an Ed25519 public key (multicodec 0xed01, multibase base58btc).
pub fn did_key(pk: &[u8; 32]) -> String {
    let mut b = vec![0xed, 0x01];
    b.extend_from_slice(pk);
    format!("did:key:z{}", base58btc(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip_and_strictness() {
        let pk = [0xffu8; 32];
        let s = base32_encode(&pk);
        assert_eq!(s.len(), 52);
        assert_eq!(base32_decode(&s).unwrap(), pk);
        assert!(base32_decode(&s.to_uppercase()).is_none());
        // set an unused trailing bit: last char of 0xff..ff is '7' (11111 -> only 1 bit used, must be 'q' = 10000)
        assert_eq!(s.chars().last(), Some('q'));
        let mut bad = s.clone();
        bad.pop();
        bad.push('r');
        assert!(base32_decode(&bad).is_none());
    }

    #[test]
    fn timestamps() {
        let t = parse_ts("2026-11-07T12:00:00Z").unwrap();
        assert_eq!(fmt_ts(t), "2026-11-07T12:00:00Z");
        assert_eq!(parse_ts("2026-11-07T12:00:00.250Z").unwrap() - t, SEC / 4);
        assert!(parse_ts("2026-11-07T12:00:00.25Z").is_none());
        assert!(parse_ts("2026-11-07T12:00:00+00:00").is_none());
        assert!(parse_ts("2026-11-07T12:00:60Z").is_none());
        assert!(parse_ts("2026-02-29T12:00:00Z").is_none());
        assert!(parse_ts("2028-02-29T12:00:00Z").is_some());
        assert!(parse_ts("2026-11-07t12:00:00z").is_none());
        assert_eq!(parse_ts("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn did_key_known_vector() {
        // did:key spec test vector (Ed25519): public key from the W3C CCG did:key test suite.
        let pk: [u8; 32] = hex::decode("2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6").unwrap().try_into().unwrap();
        assert_eq!(did_key(&pk), "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    }

    #[test]
    fn uuid() {
        let u = uuid_v7(0x0192_3456_789a, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert!(is_uuid_v7(&u), "{u}");
        assert!(!is_uuid_v7(&u.to_uppercase()));
        assert!(!is_uuid_v7("550e8400-e29b-41d4-a716-446655440000"));
    }
}
