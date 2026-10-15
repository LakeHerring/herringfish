// Fast, deterministic regression tests for the linear mask-propagation rule
// used by examples/trail_search.rs (see examples/common/lin_trail.rs).
//
// The rule (L' = R, R' = L ^ D(S(R^k)); u = D^T b; input masks (b, a ^ w)) is
// checked against the real cipher via an EXACT per-sample identity, so no
// statistics are involved. The retracted rule of the original trail_search
// (XOR the S-box OUTPUT mask into the other half) fails the same check.
// The statistical regression (positive control, 3-sigma check) is
// examples/linear_trail_check.rs.

#[path = "../examples/common/lin_trail.rs"]
mod lin_trail;

use lin_trail::{
    Lat, Rng, best_lin_trail_greedy, best_lin_trails_beam, check_diffuse_transpose, check_identity,
    diffuse_t, diffuse_t_inv, propagate_greedy,
};

fn key(k: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(k).wrapping_add(11);
    }
    key
}

#[test]
fn diffuse_t_is_the_exact_transpose_of_diffuse() {
    check_diffuse_transpose().unwrap();
}

#[test]
fn diffuse_t_inv_inverts_diffuse_t() {
    let mut rng = Rng(7);
    for _ in 0..1000 {
        let x = rng.next_u64();
        assert_eq!(diffuse_t(diffuse_t_inv(x)), x);
        assert_eq!(diffuse_t_inv(diffuse_t(x)), x);
    }
}

#[test]
fn lat_matches_parseval_and_known_maximum() {
    let lat = Lat::v02();
    assert_eq!(lat.max_abs(), 32);
    for u in 1..=255u8 {
        let s: i64 = (0..=255u8)
            .map(|w| (lat.get(w, u) as i64) * (lat.get(w, u) as i64))
            .sum();
        assert_eq!(s, 256 * 256, "Parseval fails for output mask {u:#04x}");
        assert_eq!(lat.get(0, u), 0, "S is a bijection: LAT[0][u] = 0");
    }
}

#[test]
fn greedy_and_beam_trails_satisfy_the_exact_identity() {
    let lat = Lat::v02();
    let beam = best_lin_trails_beam(&lat, 6, 1 << 10, 2);
    for t in &beam {
        check_identity(t, &key(0), 2048, 11).unwrap();
        check_identity(t, &key(1), 2048, 12).unwrap();
    }
    for r in [1usize, 2, 3, 5] {
        let g = best_lin_trail_greedy(&lat, r);
        check_identity(&g, &key(2), 2048, 13).unwrap();
    }
}

#[test]
fn best_two_round_trail_has_one_active_sbox() {
    // Correct rule: 2 rounds can be approximated through a single S-box
    // (alpha = w cancels the first-round S-box layer). The retracted rule
    // reported no such trail.
    let lat = Lat::v02();
    let beam = best_lin_trails_beam(&lat, 3, 1 << 10, 2);
    assert_eq!(beam[1].active, 1);
    assert_eq!(beam[1].weight, 3.0);
    assert_eq!(beam[2].active, 2);
}

#[test]
fn positive_control_one_round_three_active_sboxes() {
    let lat = Lat::v02();
    let (mut bu, mut bm) = (0u8, 0u16);
    for w in 1..=255u8 {
        for u in 1..=255u8 {
            let m = lat.get(w, u).unsigned_abs();
            if m > bm {
                (bu, bm) = (u, m);
            }
        }
    }
    let t = propagate_greedy(&lat, (0, bu as u64), 1);
    assert_eq!((t.active, bm), (3, 32));
    assert_eq!(t.weight, 9.0);
    check_identity(&t, &key(0), 4096, 21).unwrap();
}

#[test]
fn identity_check_detects_a_wrong_mask() {
    let lat = Lat::v02();
    let beam = best_lin_trails_beam(&lat, 3, 1 << 10, 2);
    let mut bad = beam[2].clone();
    bad.input.1 ^= 1; // corrupt one plaintext mask bit: phi flips on ~half the samples
    assert!(check_identity(&bad, &key(0), 2048, 31).is_err());
}
