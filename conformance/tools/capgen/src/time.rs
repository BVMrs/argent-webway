//! RFC 3339 UTC times with `Z` and whole seconds, as unix seconds.

pub const SKEW: i64 = 300;
pub const HOUR: i64 = 3600;
pub const DAY: i64 = 86400;

pub fn parse(s: &str) -> Option<i64> {
    let t = chrono::DateTime::parse_from_rfc3339(s).ok()?;
    let t = t.with_timezone(&chrono::Utc);
    if fmt(t.timestamp()) != s {
        return None;
    }
    Some(t.timestamp())
}

pub fn fmt(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0).expect("time in range").format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn system(secs: i64) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64)
}
