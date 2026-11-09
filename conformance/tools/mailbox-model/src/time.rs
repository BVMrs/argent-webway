//! RFC 3339 UTC timestamps in the form of `ext/envelope.md` §3.2, as nanoseconds since the Unix epoch.

pub const SECOND: i128 = 1_000_000_000;
pub const MS: i128 = 1_000_000;

/// Parses `YYYY-MM-DDTHH:MM:SS[.f{3,6,9}]Z`. Returns `None` for any other form.
pub fn parse(s: &str) -> Option<i128> {
    let b = s.as_bytes();
    if b.len() < 20 || *b.last()? != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let frac = &s[19..s.len() - 1];
    let nanos: i128 = if frac.is_empty() {
        0
    } else {
        let digits = frac.strip_prefix('.')?;
        if ![3, 6, 9].contains(&digits.len()) || !digits.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let v: i128 = digits.parse().ok()?;
        v * 10i128.pow(9 - digits.len() as u32)
    };
    let days = days_from_civil(y, mo, d) as i128;
    Some(((days * 86_400 + (h * 3600 + mi * 60 + sec) as i128) * SECOND) + nanos)
}

/// Formats with no fraction, 3 or 9 fractional digits, whichever is exact.
pub fn format(t: i128) -> String {
    let secs = t.div_euclid(SECOND);
    let nanos = t.rem_euclid(SECOND);
    let days = secs.div_euclid(86_400) as i64;
    let sod = secs.rem_euclid(86_400) as i64;
    let (y, mo, d) = civil_from_days(days);
    let base = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", y, mo, d, sod / 3600, (sod / 60) % 60, sod % 60);
    if nanos == 0 {
        format!("{base}Z")
    } else if nanos % MS == 0 {
        format!("{base}.{:03}Z", nanos / MS)
    } else {
        format!("{base}.{:09}Z", nanos)
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's algorithms.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for s in ["2026-11-07T12:00:00Z", "2026-11-07T12:00:00.250Z", "2024-02-29T23:59:59.000000001Z"] {
            assert_eq!(format(parse(s).unwrap()), s);
        }
        assert_eq!(parse("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn rejects() {
        for s in [
            "2026-11-07T12:00:00",
            "2026-11-07T12:00:60Z",
            "2026-02-29T00:00:00Z",
            "2026-11-07T12:00:00.25Z",
            "2026-11-07 12:00:00Z",
        ] {
            assert_eq!(parse(s), None, "{s}");
        }
    }
}
