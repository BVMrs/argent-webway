//! Lab 2026-11-11 queued-cancel: can a requester cancel a task whose create envelope is still queued?
//! Usage: cargo run --release -- [mc_trials_per_cell]
mod exhaustive;
mod mc;
mod rng;

use exhaustive::{Cfg, Design as XD};
use mc::{Cell, Design, Profile, Timer};

fn main() {
    let n: u64 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(20_000);

    println!("== Part A: exhaustive interleavings ==");
    println!("cfg                      faults(hf,roff,crash) states  term  q_intent q_work lost unsent run_after_x misled uncertain spurious");
    for &d in &[XD::D0, XD::D1, XD::D2, XD::D3s, XD::D3r] {
        for &fifo in &[false, true] {
            let vols: &[bool] = if matches!(d, XD::D3s | XD::D3r) { &[false, true] } else { &[false] };
            for &vol in vols {
                for mask in 0..8u8 {
                    let cfg = Cfg { design: d, fifo, tomb_volatile: vol, hfail: mask & 1 != 0, roff: mask & 2 != 0, crash: mask & 4 != 0 };
                    let t = exhaustive::run(cfg);
                    let name = format!("{:?}/{}{}", d, if fifo { "O2-fifo" } else { "O1-any" }, if vol { "/vol-tomb" } else { "" });
                    println!(
                        "{:<24} {}{}{}                   {:>6} {:>5} {:>8} {:>6} {:>4} {:>6} {:>11} {:>6} {:>9} {:>8}",
                        name, mask & 1, (mask >> 1) & 1, (mask >> 2) & 1, t.states, t.terminals, t.queued_intent,
                        t.queued_work_started, t.lost, t.unsent, t.run_after_cancel, t.misled, t.uncertain, t.spurious
                    );
                }
            }
        }
    }

    println!();
    println!("== Part B: Monte Carlo, {} trials per cell, cancel intent while create is queued ==", n);
    let profiles = [
        Profile { name: "restart", d_lo: 5.0, d_hi: 60.0, d_exp_mean: 0.0, backlog_hi: 10.0 },
        Profile { name: "flaky", d_lo: 5.0, d_hi: 0.0, d_exp_mean: 600.0, backlog_hi: 50.0 },
        Profile { name: "overnight", d_lo: 8.0 * 3600.0, d_hi: 16.0 * 3600.0, d_exp_mean: 0.0, backlog_hi: 500.0 },
    ];
    let designs: [(&str, Design, bool); 6] = [
        ("D0 a2a-taskId", Design::D0, false),
        ("D1 ref,short", Design::D1, true),
        ("D1 ref,match", Design::D1, false),
        ("D2 retry,match", Design::D2, false),
        ("D3s tomb,short", Design::D3, true),
        ("D3r tomb,match", Design::D3, false),
    ];
    println!("design          timer    profile    R-off M    hf   | started% complete% canceled% lost% x-expired% misled% uncertain% | work-s/trial sends/trial");
    let mut seed = 1u64;
    for &(dn, d, short) in &designs {
        for &timer in &[Timer::PerEnv, Timer::PerDest] {
            for p in &profiles {
                for &roff in &[false, true] {
                    for &(ms, hf) in &[(false, 0.0), (false, 0.02), (true, 0.0), (true, 0.02)] {
                        let cell = Cell { design: d, timer, profile: *p, r_goes_offline: roff, x_ttl_short: short, p_hf: hf, m_serial: ms };
                        let mut r = rng::Rng::new(seed);
                        seed += 1;
                        let mut o = mc::Out::default();
                        for _ in 0..n { mc::trial(cell, &mut r, &mut o); }
                        let pc = |x: u64| 100.0 * x as f64 / o.n as f64;
                        println!(
                            "{:<15} {:<8} {:<10} {:<5} {:<4} {:<4} | {:>8.3} {:>9.3} {:>9.3} {:>5.3} {:>10.3} {:>7.3} {:>10.3} | {:>12.1} {:>11.1}",
                            dn, format!("{:?}", timer), p.name, roff, if ms { "ser" } else { "pipe" }, hf, pc(o.work_started), pc(o.completed), pc(o.canceled), pc(o.lost),
                            pc(o.x_expired), pc(o.misled), pc(o.uncertain), o.work_secs / o.n as f64, o.r_sends as f64 / o.n as f64
                        );
                    }
                }
            }
        }
    }
}
