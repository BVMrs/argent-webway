//! Exact decimal expansion of the midpoint between a double and the next one up.

fn mul_small(n: &mut Vec<u32>, k: u32) {
    let mut carry = 0u64;
    for d in n.iter_mut() {
        let x = *d as u64 * k as u64 + carry;
        *d = (x % 1_000_000_000) as u32;
        carry = x / 1_000_000_000;
    }
    while carry > 0 { n.push((carry % 1_000_000_000) as u32); carry /= 1_000_000_000; }
}

fn to_dec(n: &[u32]) -> String {
    let mut s = format!("{}", n.last().unwrap());
    for d in n.iter().rev().skip(1) { s.push_str(&format!("{:09}", d)); }
    s
}

/// Midpoint between f > 0 and its successor, as "<digits>e<exp>" with an exact value.
pub fn midpoint_above(f: f64) -> String {
    let b = f.to_bits();
    let (ef, frac) = ((b >> 52) & 0x7ff, b & ((1u64 << 52) - 1));
    let (m, e) = if ef == 0 { (frac, -1074i64) } else { (frac | (1 << 52), ef as i64 - 1075) };
    // midpoint = (2m+1) * 2^(e-1)
    let odd = 2 * m + 1;
    let mut n = vec![(odd % 1_000_000_000) as u32, ((odd / 1_000_000_000) % 1_000_000_000) as u32, (odd / 1_000_000_000_000_000_000) as u32];
    while n.len() > 1 && *n.last().unwrap() == 0 { n.pop(); }
    let p = e - 1;
    if p >= 0 {
        for _ in 0..p { mul_small(&mut n, 2); }
        format!("{}e0", to_dec(&n))
    } else {
        for _ in 0..(-p) { mul_small(&mut n, 5); }
        format!("{}e{}", to_dec(&n), p)
    }
}

/// A value a hair above (D1e(x-1)) or below ((D*10-1)e(x-1)) the exact decimal "De x".
pub fn nudge(s: &str, up: bool) -> String {
    let (d, x) = s.split_once('e').unwrap();
    let x: i64 = x.parse().unwrap();
    if up { return format!("{}1e{}", d, x - 1); }
    // D*10 - 1 = (D-1) followed by 9
    let mut ds: Vec<u8> = d.bytes().collect();
    let mut i = ds.len();
    loop { i -= 1; if ds[i] == b'0' { ds[i] = b'9' } else { ds[i] -= 1; break; } }
    let mut t = String::from_utf8(ds).unwrap().trim_start_matches('0').to_string();
    if t.is_empty() { t.push('0'); }
    format!("{}9e{}", t, x - 1)
}

#[cfg(test)]
mod tests {
    #[test]
    fn midpoints() {
        // 1.0 and 1+2^-52: midpoint 1+2^-53 = 1.00000000000000011102230246251565404236316680908203125
        let m = super::midpoint_above(1.0);
        let (d, x) = m.split_once('e').unwrap();
        let v: f64 = format!("{}e{}", d, x).parse().unwrap();
        assert!(v == 1.0); // ties-to-even
        let up: f64 = super::nudge(&m, true).parse().unwrap();
        assert!(up > 1.0);
        let dn: f64 = super::nudge(&m, false).parse().unwrap();
        assert!(dn == 1.0);
        let m2 = super::midpoint_above(9007199254740992.0); // 2^53, ulp 2: midpoint 2^53+1
        assert_eq!(m2, "9007199254740993e0");
    }
}
