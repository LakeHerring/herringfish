// Lower bound on the number of ACTIVE S-boxes over r Feistel rounds
// (Herringfish Feistel ARX v0.2 / solo-arx, frozen S-box HERRINGFISH_SBOX_V02).
// Replaces the former examples/active_sbox_count.rs, which printed hard-coded
// claims and computed nothing.
//
// MODEL (single characteristic / single linear trail):
//   Round: L' = R, R' = L ^ D(S(R ^ k)); D: y_i = x_i ^ x_{i+1} ^ x_{i+3}.
//   A byte is "active" if non-zero (difference, or mask). Only byte activity
//   is tracked (truncated model); the bound is the minimum, over all start
//   states and all byte-activity patterns allowed by the relaxations below,
//   of the total number of active S-boxes A(r).
//
//   Differential: state (ΔL, ΔR); active S-boxes = supp(ΔR); output activity
//     o = supp(D(S-out diff)); (supp ΔR, o) must be a pair of the exact
//     diffusion pair set of D; new state (ΔR, ΔL ^ o).
//   Linear (backward): state (α, β) on (L', R'); u = Dᵀβ; active S-boxes =
//     supp(u) (= supp(w), S is a bijection); (supp β, supp u) must be a pair
//     of the exact pair set of Dᵀ; new state (β, α ^ w), supp(w) = supp(u).
//
// WHAT IS EXACT: the set of achievable (input activity, output activity)
//   pairs of D and Dᵀ for ARBITRARY byte values. A byte vector is 8 bit-planes
//   p_k ∈ {0,1}^8; supp(x) = OR_k p_k and supp(Mx) = OR_k M p_k, so the pairs
//   are the OR-closure (up to 8 planes) of {(p, M p)}.
//
// RELAXATIONS (each can only LOWER the minimum, so the bound stays valid):
//   1. Cancellation at the XOR with the other half is per byte and
//      independent: a byte active in both operands may be zero or non-zero in
//      the result, for every byte, regardless of actual values.
//   2. Values are not tracked across rounds (no value equalities).
//
// PER-S-BOX BOUNDS (measured from the S-box below, not assumed):
//   differential: p <= DDTmax/256 = 2^-6 per active S-box;
//   linear:       |corr| <= LATmax/256 = 2^-3 per active S-box.
//   So  p(characteristic) <= 2^(-6 A(r)),  |corr(trail)| <= 2^(-3 A(r))
//   under the usual independent-round-key assumption.
//
// NOT COVERED: differentials and linear hulls (sums over many characteristics
//   / trails with the same end masks), key-dependent effects, integral /
//   algebraic / related-key / MITM attacks. This is a single-trail bound;
//   it is NOT a proof of security of the cipher.
//
// Self-checks: pair sets are sampled for soundness; found linear trails
// (greedy and beam, from lin_trail) must have at least A(r) active S-boxes.
//
// Deterministic. Run: cargo run --release --example active_sbox_bound

#![allow(clippy::needless_range_loop)]

#[path = "common/lin_trail.rs"]
mod lin_trail;

use herringfish::cipher::feistel_arx::{HERRINGFISH_SBOX_V02, diffuse};
use lin_trail::{Lat, Rng, best_lin_trail_greedy, best_lin_trails_beam, bytes, diffuse_t};

const INF: u8 = 255;
const MAX_ROUNDS: usize = 16;

/// Exact (supp x, supp Mx) pairs, M(x)_i = x_{i+o0} ^ x_{i+o1} ^ x_{i+o2}.
/// Index = (supp x) << 8 | supp(Mx).
fn pair_set(offs: [usize; 3]) -> Vec<bool> {
    let mut gens = vec![];
    for p in 1..256usize {
        let mut q = 0usize;
        for i in 0..8 {
            let bit = offs
                .iter()
                .fold(0, |acc, &o| acc ^ ((p >> ((i + o) % 8)) & 1));
            q |= bit << i;
        }
        gens.push((p, q));
    }
    let mut set = vec![false; 65536];
    set[0] = true;
    for _ in 0..8 {
        let cur: Vec<usize> = (0..65536).filter(|&i| set[i]).collect();
        for &s in &cur {
            let (a, b) = (s >> 8, s & 255);
            for &(p, q) in &gens {
                set[((a | p) << 8) | (b | q)] = true;
            }
        }
    }
    set
}

fn branch_number(set: &[bool]) -> u32 {
    (1..65536usize)
        .filter(|&i| set[i] && (i >> 8) != 0)
        .map(|i| ((i >> 8) as u32).count_ones() + ((i & 255) as u32).count_ones())
        .min()
        .unwrap()
}

fn supp(v: u64) -> usize {
    bytes(v)
        .iter()
        .enumerate()
        .fold(0, |s, (i, &b)| s | (usize::from(b != 0) << i))
}

/// Soundness: every sampled byte vector must give a pair inside the set.
fn sample_check(set: &[bool], f: fn(u64) -> u64, seed: u64) {
    let mut rng = Rng(seed);
    for _ in 0..200_000 {
        // random sparsity: AND a few random words so many bytes are zero
        let mut x = rng.next_u64();
        for _ in 0..(rng.next_u64() % 4) {
            x &= rng.next_u64();
        }
        let mut keep = 0u64;
        for i in 0..8 {
            if rng.next_u64() & 1 == 1 {
                keep |= 0xff << (8 * i);
            }
        }
        x &= keep;
        assert!(
            set[supp(x) << 8 | supp(f(x))],
            "pair set not sound for x={x:016x}"
        );
    }
}

/// One DP round. State = (x, y) activities. `active_is_first`: differential
/// (cost = popcount of the pair's first element y), linear (cost = popcount
/// of the pair's second element o).
fn step(cost: &[u8], outs: &[Vec<u8>], active_is_first: bool) -> Vec<u8> {
    let mut next = vec![INF; 65536];
    for x in 0..256usize {
        for y in 0..256usize {
            let c = cost[x << 8 | y];
            if c == INF {
                continue;
            }
            for &o in &outs[y] {
                let o = o as usize;
                let (must, free) = (x ^ o, x & o);
                let add = if active_is_first { y } else { o }.count_ones() as u8;
                let nc = c.saturating_add(add);
                // new second element = x ^ o; where both are active the byte may cancel
                let mut sub = free;
                loop {
                    let idx = y << 8 | (must | sub);
                    if nc < next[idx] {
                        next[idx] = nc;
                    }
                    if sub == 0 {
                        break;
                    }
                    sub = (sub - 1) & free;
                }
            }
        }
    }
    next
}

fn dp(set: &[bool], active_is_first: bool) -> Vec<u32> {
    let outs: Vec<Vec<u8>> = (0..256usize)
        .map(|y| {
            (0..256usize)
                .filter(|&o| set[y << 8 | o])
                .map(|o| o as u8)
                .collect()
        })
        .collect();
    let mut cost: Vec<u8> = (0..65536usize)
        .map(|s| if s == 0 { INF } else { 0 })
        .collect();
    (1..=MAX_ROUNDS)
        .map(|_| {
            cost = step(&cost, &outs, active_is_first);
            *cost.iter().min().unwrap() as u32
        })
        .collect()
}

fn main() {
    // per-S-box bounds from the actual S-box
    let mut ddt_max = 0u32;
    for dx in 1..256usize {
        let mut row = [0u32; 256];
        for x in 0..256usize {
            row[(HERRINGFISH_SBOX_V02[x] ^ HERRINGFISH_SBOX_V02[x ^ dx]) as usize] += 1;
        }
        ddt_max = ddt_max.max(*row.iter().max().unwrap());
    }
    let lat = Lat::v02();
    let lat_max = lat.max_abs() as u32;
    assert_eq!(256 % ddt_max, 0);
    assert_eq!(256 % lat_max, 0);
    let (bits_d, bits_l) = ((256 / ddt_max).ilog2(), (256 / lat_max).ilog2());
    println!(
        "S-box: DDT max {ddt_max} -> p <= 2^-{bits_d} per active S-box; LAT max |W| {lat_max} -> |corr| <= 2^-{bits_l} per active S-box"
    );

    let pd = pair_set([0, 1, 3]); // y_i = x_i ^ x_{i+1} ^ x_{i+3}  (D)
    let pl = pair_set([0, 7, 5]); // u_j = b_j ^ b_{j-1} ^ b_{j-3}  (Dᵀ)
    sample_check(&pd, diffuse, 0x1234_5678_9ABC_DEF1);
    sample_check(&pl, diffuse_t, 0x0FED_CBA9_8765_4321);
    println!(
        "pair sets: {} pairs for D (branch number {}), {} pairs for Dᵀ (branch number {}); sampled soundness check passed",
        pd.iter().filter(|&&b| b).count(),
        branch_number(&pd),
        pl.iter().filter(|&&b| b).count(),
        branch_number(&pl)
    );

    let ad = dp(&pd, true);
    let al = dp(&pl, false);

    println!("\nMinimum active S-boxes A(r) over r rounds (relaxed model, single trail)");
    println!("rounds | differential A  p <= 2^- | linear A  |corr| <= 2^-  1/corr^2 >= 2^");
    for r in 1..=MAX_ROUNDS {
        let (d, l) = (ad[r - 1], al[r - 1]);
        println!(
            "{r:>6} | {d:>14}  {:>9} | {l:>8}  {:>13}  {:>11}",
            bits_d * d,
            bits_l * l,
            2 * bits_l * l
        );
    }

    // cross-check: real linear trails must not beat the bound
    let beam = best_lin_trails_beam(&lat, MAX_ROUNDS, 1 << 12, 2);
    for r in 1..=MAX_ROUNDS {
        assert!(
            beam[r - 1].active >= al[r - 1],
            "beam trail with {} active S-boxes beats the bound {} at r={r}",
            beam[r - 1].active,
            al[r - 1]
        );
    }
    for r in [2usize, 4, 8] {
        let g = best_lin_trail_greedy(&lat, r);
        assert!(
            g.active >= al[r - 1],
            "greedy trail beats the bound at r={r}"
        );
    }
    println!(
        "\ncross-check passed: beam (r=1..={MAX_ROUNDS}) and greedy (r=2,4,8) linear trails have >= A(r) active S-boxes"
    );
    println!(
        "found/bound at r=16: beam trail has {} active S-boxes, bound is {}",
        beam[MAX_ROUNDS - 1].active,
        al[MAX_ROUNDS - 1]
    );
}
