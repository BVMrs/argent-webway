//! How biscuit-auth 6 evaluates TTL checks, as it affects the time-of-check rule for capability/v0.
//! Each case prints expected vs actual.
use biscuit_auth::{
    builder::{date, fact, Algorithm, AuthorizerBuilder, BlockBuilder},
    Biscuit, KeyPair,
};
use rand::{rngs::StdRng, SeedableRng};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}
fn rfc(t: SystemTime) -> String {
    // biscuit date literal: RFC 3339 UTC
    let s = t.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let (days, rem) = (s / 86400, s % 86400);
    // civil-from-days (Howard Hinnant)
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn authz(t: &Biscuit, times: &[SystemTime], wall: bool) -> Result<(), String> {
    let mut ab = AuthorizerBuilder::new();
    for &x in times {
        ab = ab.fact(fact("time", &[date(&x)])).unwrap();
    }
    if wall {
        ab = ab.time();
    }
    ab = ab.policy("allow if right(\"skill:run-tests\")").unwrap();
    let mut a = ab.build(t).map_err(|e| e.to_string())?;
    a.authorize().map(|_| ()).map_err(|e| format!("{e:?}").chars().take(400).collect())
}

fn main() {
    let mut rng = StdRng::seed_from_u64(7);
    let root = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let c = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    // Fake devnet clock far from the wall clock: token issued at T0 with ttl = 1 h.
    let t0 = at(1_900_000_000); // 2030-03-17
    let exp = t0 + Duration::from_secs(3600);
    let tok = Biscuit::builder()
        .fact("right(\"skill:run-tests\")").unwrap()
        .check(format!("check if time($t), $t <= {}", rfc(exp)).as_str()).unwrap()
        .build_with_rng(&root, Default::default(), &mut rng)
        .unwrap();
    let after = exp + Duration::from_secs(86400);
    let before = t0 + Duration::from_secs(600);

    let mut n = 0;
    let mut bad = 0;
    let mut case = |name: &str, want_ok: bool, r: Result<(), String>| {
        n += 1;
        let ok = r.is_ok();
        if ok != want_ok {
            bad += 1;
        }
        println!(
            "{} | {:<78} | expect {:<6} | got {:<6} {}",
            if ok == want_ok { "PASS" } else { "FAIL" },
            name,
            if want_ok { "accept" } else { "reject" },
            if ok { "accept" } else { "reject" },
            r.err().unwrap_or_default()
        );
    };

    case("B1 node clock injected explicitly, before exp", true, authz(&tok, &[before], false));
    case("B2 node clock injected explicitly, 1 d after exp", false, authz(&tok, &[after], false));
    case("B3 no time fact at all (fails closed)", false, authz(&tok, &[], false));
    // AuthorizerBuilder::time() uses SystemTime::now(), ignoring the devnet fake clock: the token expires
    // in 2030, so a fake clock one day past exp is still accepted.
    case("B4 AuthorizerBuilder::time() (wall clock) while fake clock is 1 d past exp", false, authz(&tok, &[], true));
    // Injecting two candidate times (e.g. now and postmark, 'check at both') is an OR, not an AND.
    case("B5 two time facts injected: postmark (before exp) and now (after exp)", false, authz(&tok, &[before, after], false));

    // A delegator's TTL check that trusts the next holder's key lets that holder assert its own time().
    let plain = Biscuit::builder()
        .fact("right(\"skill:run-tests\")").unwrap()
        .build_with_rng(&root, Default::default(), &mut rng)
        .unwrap();
    let req = plain.third_party_request().unwrap();
    let ttl_block = BlockBuilder::new()
        .check(format!("check if time($t), $t <= {} trusting authority, ed25519/{}", rfc(exp), c.public().to_bytes_hex()).as_str())
        .unwrap();
    let t1 = plain.append(ttl_block).unwrap();
    let _ = req;
    let forged = BlockBuilder::new().fact(fact("time", &[date(&before)])).unwrap();
    let req = t1.third_party_request().unwrap();
    let blk = req.create_block(&c.private(), forged).unwrap();
    let t2 = t1.append_third_party(c.public(), blk).unwrap();
    case("B6a control: same token without the forged time() block", false, authz(&t1, &[after], false));
    case("B6 delegator TTL check (no authority TTL), `trusting ed25519/<next holder>`; holder asserts old time()", false, authz(&t2, &[after], false));
    // Same forged fact against the authority-block TTL check (default scope): not visible.
    let req = tok.third_party_request().unwrap();
    let blk = req.create_block(&c.private(), BlockBuilder::new().fact(fact("time", &[date(&before)])).unwrap()).unwrap();
    let t3 = tok.append_third_party(c.public(), blk).unwrap();
    case("B7 authority TTL check (default scope); third-party block asserts old time()", false, authz(&t3, &[after], false));
    let t4 = tok.append(BlockBuilder::new().fact(fact("time", &[date(&before)])).unwrap()).unwrap();
    case("B8 authority TTL check (default scope); ephemeral block asserts old time()", false, authz(&t4, &[after], false));
    println!("{bad} of {n} cases differ from the safe expectation");
}
