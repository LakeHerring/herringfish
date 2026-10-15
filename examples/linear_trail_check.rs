// Regression check for the linear-trail rule used by examples/trail_search.rs.
// (Supersedes examples/linear_bias_test.rs, which validated the RETRACTED
// 16-round trail; see docs/cryptanalysis/trail_search_v0.3.0-solo.md §3.)
//
// Construction: Herringfish Feistel ARX v0.2, solo-arx ARX key schedule.
//
// A. EXACT IDENTITY (no statistics). For the reported greedy and beam trails,
//    r = 1..16, the real cipher must satisfy, on every sample,
//      phi(P, C) == XOR_t ( u_t.S(x_t) ^ w_t.R_{t-1} ).
//    Any error in the mask propagation rule breaks this on ~half the samples.
// B. POSITIVE CONTROL. 1 round, correct rule, output masks (0, beta) with
//    beta = the S-box output mask byte of a max-|LAT| pair at byte 0
//    (3 active S-boxes, |W| = 32 each, predicted |bias| = 2^-10 ~ 9.8e-4):
//    the measured bias must agree with the signed prediction within 3 sigma.
// C. STATISTICAL CHECK. Every reported trail (beam r = 2..16, greedy r = 2..16)
//    with predicted |bias| >= 1e-3 is measured with N = 2^log2n random
//    plaintexts for 3 keys; the measured bias must match the SIGNED prediction
//    -1/2 * prod(LAT/256) * (-1)^(sum w_t.k_t) within 3 sigma. Trails below
//    1e-3 are reported but not statistically testable at this N.
// D. RETRACTION REPLAY (negative control). Re-implements the retracted rule
//    (XOR the S-box OUTPUT mask into the other half, LAT[beta byte][u byte])
//    and shows the trails it claimed are NOT present in the real cipher.
//
// Exit code 1 if any check fails. Seeds are fixed (SplitMix64, see seed_for).
// Run: cargo run --release --example linear_trail_check [-- <log2 N, default 24>]

#![allow(clippy::needless_range_loop)]

#[path = "common/lin_trail.rs"]
mod lin_trail;

use herringfish::cipher::feistel_arx::FeistelArx;
use lin_trail::{
    DEFAULT_BEAM, Lat, LinTrail, Rng, best_lin_trail_greedy, best_lin_trails_beam, bytes,
    check_diffuse_transpose, check_identity, diffuse_t, parity, propagate_greedy,
};

const MAX_ROUNDS: usize = 16;
const KEYS: u8 = 3;
const MIN_TESTABLE_BIAS: f64 = 1e-3;

fn make_key(k: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8)
            .wrapping_mul(37)
            .wrapping_add(k.wrapping_mul(101))
            .wrapping_add(11);
    }
    key
}

fn seed_for(k: u8) -> u64 {
    0x9E37_79B9_7F4A_7C15 ^ (k as u64 * 0x0123_4567)
}

/// Measured Pr[phi = 1] - 1/2 over `n` random plaintexts.
fn measure(c: &FeistelArx, phi: impl Fn((u64, u64), (u64, u64)) -> u32, n: u64, seed: u64) -> f64 {
    let mut rng = Rng(seed);
    let mut ones = 0u64;
    for _ in 0..n {
        let p = (rng.next_u64(), rng.next_u64());
        let mut blk = [0u8; 16];
        blk[..8].copy_from_slice(&p.0.to_le_bytes());
        blk[8..].copy_from_slice(&p.1.to_le_bytes());
        c.encrypt_block(&mut blk);
        let cc = (
            u64::from_le_bytes(blk[..8].try_into().unwrap()),
            u64::from_le_bytes(blk[8..].try_into().unwrap()),
        );
        ones += phi(p, cc) as u64;
    }
    ones as f64 / n as f64 - 0.5
}

/// Measure `t` for every key and compare with the signed prediction.
fn verify(label: &str, t: &LinTrail, lat: &Lat, n: u64) -> bool {
    let mut ok = true;
    for k in 0..KEYS {
        let c = FeistelArx::new_with_rounds(&make_key(k), t.rounds);
        let pred = -t.signed_corr(lat, c.round_keys()) / 2.0;
        let meas = measure(&c, |p, cc| t.phi(p, cc), n, seed_for(k));
        let p1 = 0.5 + pred;
        let sigma = (p1 * (1.0 - p1) / n as f64).sqrt();
        let z = (meas - pred) / sigma;
        let pass = z.abs() <= 3.0;
        ok &= pass;
        println!(
            "    key{k}: predicted {pred:+.3e}  measured {meas:+.3e}  sigma {sigma:.1e}  z={z:+.2}  {}",
            if pass { "ok" } else { "FAIL" }
        );
    }
    println!("  [{}] {label}", if ok { "PASS" } else { "FAIL" });
    ok
}

// ---------- D: the retracted rule, kept only as a negative control ----------

fn old_prob(lat: &Lat, a: u8, b: u8) -> f64 {
    if a == 0 && b == 0 {
        1.0
    } else if a == 0 || b == 0 {
        0.5
    } else {
        (256.0 - lat.get(a, b).unsigned_abs() as f64) / 512.0
    }
}

/// RETRACTED rule: (gl, gr) -> (gr, gl ^ Dt(gr)), per-byte factor LAT[gr byte][Dt(gr) byte].
/// Returns (min product, start mask on L, final masks).
fn old_rule_best(lat: &Lat, rounds: usize) -> (f64, u64, (u64, u64)) {
    let (mut bp, mut bs, mut bf) = (2.0f64, 0u64, (0u64, 0u64));
    for pos in 0..8 {
        for ga in 1..256u64 {
            let start = ga << (8 * pos);
            let (mut gl, mut gr, mut lp) = (start, 0u64, 0.0f64);
            for _ in 0..rounds {
                let (ol, or) = (gl, gr);
                let f = diffuse_t(or);
                let (grb, fb) = (bytes(or), bytes(f));
                for i in 0..8 {
                    if grb[i] != 0 {
                        lp += old_prob(lat, grb[i], fb[i]).log2();
                    }
                }
                (gl, gr) = (or, ol ^ f);
            }
            let p = 2f64.powf(lp);
            if p < bp {
                (bp, bs, bf) = (p, start, (gl, gr));
            }
        }
    }
    (bp, bs, bf)
}

fn retraction_replay(lat: &Lat, n: u64) -> bool {
    println!(
        "\n[D] Retraction replay: trails claimed by the retracted rule, measured on the real cipher (N=2^{})",
        n.ilog2()
    );
    let mut ok = true;
    for r in [2usize, 4] {
        let (p, start, fin) = old_rule_best(lat, r);
        // The old tool read the product p as the bias (work = 2^(-2 log2 p)); a
        // single-S-box product near 1/2 (e.g. 0.4375 = (256-32)/512) corresponds
        // to bias 1/2 - p.
        let claimed = if p > 0.25 { 0.5 - p } else { p };
        let c = FeistelArx::new_with_rounds(&make_key(0), r);
        let sigma = 0.5 / (n as f64).sqrt();
        let a = measure(
            &c,
            |pl, cc| parity(start & pl.0) ^ parity(fin.0 & cc.0) ^ parity(fin.1 & cc.1),
            n,
            seed_for(0),
        );
        let b = measure(
            &c,
            |pl, cc| parity(fin.0 & pl.0) ^ parity(fin.1 & pl.1) ^ parity(start & cc.0),
            n,
            seed_for(0),
        );
        let refuted = a.abs() < claimed / 4.0 && b.abs() < claimed / 4.0;
        ok &= refuted;
        println!(
            "  r={r}: retracted rule claims product {p:.3e} (bias ~{claimed:.3e}); measured |bias| {:.1e} (as reported), {:.1e} (swapped); sigma {sigma:.1e}  [{}]",
            a.abs(),
            b.abs(),
            if refuted {
                "claim NOT present in cipher"
            } else {
                "UNEXPECTED: bias present"
            }
        );
    }
    ok
}

fn main() {
    let log2n: u32 = std::env::args()
        .nth(1)
        .map_or(24, |a| a.parse().expect("log2 N"));
    let n = 1u64 << log2n;
    println!(
        "linear_trail_check: N = 2^{log2n} per key, {KEYS} keys, SplitMix64 seeds 0x9E3779B97F4A7C15 ^ (key_index * 0x1234567)"
    );
    check_diffuse_transpose().expect("diffuse_t must be diffuse^T");
    let lat = Lat::v02();
    let mut all_ok = true;

    // trails exactly as trail_search reports them
    let beam = best_lin_trails_beam(&lat, MAX_ROUNDS, DEFAULT_BEAM.0, DEFAULT_BEAM.1);
    let greedy: Vec<LinTrail> = (1..=MAX_ROUNDS)
        .map(|r| best_lin_trail_greedy(&lat, r))
        .collect();

    // A. exact identity
    println!(
        "\n[A] Exact identity phi(P,C) == XOR_t(u_t.S(x_t) ^ w_t.R_(t-1)), 2^14 samples x 2 keys"
    );
    for (name, set) in [("beam", &beam), ("greedy", &greedy)] {
        for t in set.iter() {
            for k in 0..2u8 {
                if let Err(e) = check_identity(t, &make_key(k), 1 << 14, seed_for(k)) {
                    println!("  FAIL {name} r={}: {e}", t.rounds);
                    all_ok = false;
                }
            }
        }
        println!("  {name}: r=1..={MAX_ROUNDS} checked");
    }

    // B. positive control
    let (mut bw, mut bu, mut bm) = (0u8, 0u8, 0u16);
    for w in 1..=255u8 {
        for u in 1..=255u8 {
            let m = lat.get(w, u).unsigned_abs();
            if m > bm {
                (bw, bu, bm) = (w, u, m);
            }
        }
    }
    let control = propagate_greedy(&lat, (0, bu as u64), 1);
    println!(
        "\n[B] Positive control: 1 round, output masks (0, {:016x}), {} active S-boxes, |W|={bm} (w={bw:#04x}, u={bu:#04x}), predicted |bias| {:.3e}",
        bu as u64,
        control.active,
        control.bias_abs()
    );
    assert_eq!(control.active, 3);
    all_ok &= verify("positive control (1 round)", &control, &lat, n);

    // C. statistical check of every reported trail that is testable at this N
    println!("\n[C] Reported trails with predicted |bias| >= {MIN_TESTABLE_BIAS:.0e}");
    let mut tested = 0;
    for (name, set) in [("beam", &beam), ("greedy", &greedy)] {
        for t in set.iter().filter(|t| t.weight > 0.0) {
            if t.bias_abs() >= MIN_TESTABLE_BIAS {
                tested += 1;
                all_ok &= verify(
                    &format!(
                        "{name} r={} weight {:.0} ({} active), |bias| {:.3e}",
                        t.rounds,
                        t.weight,
                        t.active,
                        t.bias_abs()
                    ),
                    t,
                    &lat,
                    n,
                );
            } else {
                println!(
                    "  [skip] {name} r={}: weight {:.0}, predicted |bias| {:.3e} < {MIN_TESTABLE_BIAS:.0e} (not testable at N=2^{log2n})",
                    t.rounds,
                    t.weight,
                    t.bias_abs()
                );
            }
        }
    }
    println!("  {tested} reported trails statistically tested");

    all_ok &= retraction_replay(&lat, 1 << log2n.min(22));

    println!(
        "\nRESULT: {}",
        if all_ok {
            "ALL CHECKS PASSED"
        } else {
            "CHECKS FAILED"
        }
    );
    if !all_ok {
        std::process::exit(1);
    }
}
