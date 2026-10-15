// Shared linear-trail machinery for Herringfish Feistel ARX v0.2 (solo-arx).
//
// Included with `#[path = "common/lin_trail.rs"] mod lin_trail;` by
//   examples/trail_search.rs, examples/linear_trail_check.rs,
//   examples/active_sbox_bound.rs and tests/linear_trail_identity.rs.
//
// ROUND (encryption, src/cipher/feistel_arx.rs):
//     L' = R,   R' = L ^ F(R),   F(R) = D(S(R ^ k)),
//     S = byte-wise 8-bit S-box layer, D = byte diffusion y_i = x_i ^ x_{i+1} ^ x_{i+3}.
//
// MASK PROPAGATION (backward, exact). Output masks (a, b) on (L', R'):
//     a.L' ^ b.R' = a.R ^ b.L ^ b.F(R)
//     b.F(R) = b.D(s) = (D^T b).s = u.s            with s = S(R ^ k), u = D^T b
//   u_j = b_j ^ b_{j-1} ^ b_{j-3} is the mask on the S-box layer OUTPUT.
//   Each active byte i (u_i != 0) is approximated u_i.S(x) ~ w_i.x with
//   correlation LAT[w_i][u_i] / 256 (x = R ^ k); w is the mask on the S-box
//   layer INPUT. Since x = R ^ k:  u.s ~ w.R ^ w.k, so the input masks are
//     (a_prev, b_prev) = (b, a ^ w)                  (L-mask, R-mask).
//   w_i != 0 exactly when u_i != 0 (S is a bijection, LAT[w][0] = 0 for w != 0).
//   Trail correlation = prod_{active bytes} LAT[w_i][u_i]/256, times a
//   key-dependent sign (-1)^(w.k) per round. Magnitude is key-independent.
//   Exact identity (telescoping over rounds), for the whole trail:
//     phi(P, C) = XOR_t ( u_t.S(x_t) ^ w_t.R_{t-1} )
//   where phi is the parity of the input/output masks on (P, C). This is
//   checked against the real cipher by `check_identity` (no statistics).
//
// Deterministic: no randomness except the explicit SplitMix64 seeds passed in.

#![allow(dead_code, clippy::needless_range_loop)]

use herringfish::cipher::feistel_arx::{FeistelArx, HERRINGFISH_SBOX_V02, diffuse, sbox_layer};
use rustc_hash::FxHashMap;

pub fn bytes(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

pub fn pack(b: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*b)
}

pub fn parity(v: u64) -> u32 {
    v.count_ones() & 1
}

/// D^T: u_j = b_j ^ b_{j-1} ^ b_{j-3} (indices mod 8, byte j = bits 8j..8j+7).
pub fn diffuse_t(b: u64) -> u64 {
    b ^ b.rotate_left(8) ^ b.rotate_left(24)
}

/// (D^T)^-1. D^T is a unit of GF(2)[x]/(x^8+1) (value 1 at x = 1), a local
/// ring whose unit group has order 2^7, so (D^T)^128 = id and inverse = (D^T)^127.
pub fn diffuse_t_inv(u: u64) -> u64 {
    let mut x = u;
    for _ in 0..127 {
        x = diffuse_t(x);
    }
    x
}

/// Exact check over all 64x64 basis pairs that a.D(b) == D^T(a).b, i.e. that
/// `diffuse_t` is the GF(2) transpose of the cipher's `diffuse`.
pub fn check_diffuse_transpose() -> Result<(), String> {
    for i in 0..64 {
        for j in 0..64 {
            let lhs = parity((1u64 << i) & diffuse(1u64 << j));
            let rhs = parity(diffuse_t(1u64 << i) & (1u64 << j));
            if lhs != rhs {
                return Err(format!("diffuse_t is not diffuse^T at (i={i}, j={j})"));
            }
        }
    }
    Ok(())
}

/// SplitMix64. Deliberately NOT an F2-linear generator (xorshift): successive
/// outputs of a linear PRNG satisfy fixed linear relations, which would make
/// (L0, R0) samples lie on a 64-dim subspace and can bias linear-mask tests.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

// ---------- exact LAT ----------

/// Exact 256x256 LAT: `get(w, u) = sum_x (-1)^(w.x ^ u.S(x))`
/// (w = input mask, u = output mask), plus per-column partner lists.
pub struct Lat {
    w: Vec<i16>,
    /// cols[u] = [(w, |LAT[w][u]|)] for |LAT| > 0, sorted by |LAT| desc then w asc.
    cols: Vec<Vec<(u8, u16)>>,
}

impl Lat {
    pub fn new(sbox: &[u8; 256]) -> Self {
        let mut w = vec![0i16; 65536];
        for a in 0..256usize {
            for b in 0..256usize {
                let mut s = 0i16;
                for x in 0..256usize {
                    let p = ((a & x).count_ones() ^ (b & sbox[x] as usize).count_ones()) & 1;
                    s += if p == 0 { 1 } else { -1 };
                }
                w[a * 256 + b] = s;
            }
        }
        let cols = (0..256usize)
            .map(|u| {
                let mut v: Vec<(u8, u16)> = (1..256usize)
                    .filter_map(|a| {
                        let m = w[a * 256 + u].unsigned_abs();
                        (m > 0).then_some((a as u8, m))
                    })
                    .collect();
                v.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
                v
            })
            .collect();
        Lat { w, cols }
    }

    pub fn v02() -> Self {
        Self::new(&HERRINGFISH_SBOX_V02)
    }

    pub fn get(&self, w: u8, u: u8) -> i16 {
        self.w[w as usize * 256 + u as usize]
    }

    /// Best input mask for output mask `u != 0`: (w, |LAT[w][u]|).
    pub fn best(&self, u: u8) -> (u8, u16) {
        self.cols[u as usize][0]
    }

    /// max |LAT[w][u]| over w != 0, u != 0.
    pub fn max_abs(&self) -> u16 {
        (1..256).map(|u| self.best(u as u8).1).max().unwrap()
    }
}

/// -log2 of one S-box correlation |W|/256.
pub fn sbox_bits(abs_w: u16) -> f64 {
    8.0 - (abs_w as f64).log2()
}

/// Per-byte optimal S-box input mask for S-box output mask `u`.
pub fn best_w(lat: &Lat, u: u64) -> u64 {
    let mut w = [0u8; 8];
    for (i, &ub) in bytes(u).iter().enumerate() {
        if ub != 0 {
            w[i] = lat.best(ub).0;
        }
    }
    pack(&w)
}

// ---------- trails ----------

#[derive(Clone, Debug)]
pub struct LinTrail {
    pub rounds: usize,
    /// -log2 |correlation| (sum of per-S-box -log2(|W|/256)).
    pub weight: f64,
    pub active: u32,
    /// Masks on plaintext (L0, R0).
    pub input: (u64, u64),
    /// Masks on ciphertext (L_r, R_r).
    pub output: (u64, u64),
    /// u[t-1]: mask on S-box layer OUTPUT of round t (= D^T of the R_t mask).
    pub u: Vec<u64>,
    /// w[t-1]: mask on S-box layer INPUT of round t (x = R_{t-1} ^ k_t).
    pub w: Vec<u64>,
}

impl LinTrail {
    /// Propagate `output` masks backward through `w.len()` rounds with the
    /// given S-box input masks `w[t-1]` (round t = 1..r). Validates the rule.
    pub fn from_masks(lat: &Lat, output: (u64, u64), w: &[u64]) -> Result<LinTrail, String> {
        let r = w.len();
        let (mut a, mut b) = output;
        let mut u = vec![0u64; r];
        let mut weight = 0.0;
        let mut active = 0u32;
        for t in (0..r).rev() {
            let ut = diffuse_t(b);
            let (ub, wb) = (bytes(ut), bytes(w[t]));
            for i in 0..8 {
                if (ub[i] == 0) != (wb[i] == 0) {
                    return Err(format!(
                        "round {}: byte {i}: support of w ({:#04x}) != support of u ({:#04x})",
                        t + 1,
                        wb[i],
                        ub[i]
                    ));
                }
                if ub[i] != 0 {
                    let c = lat.get(wb[i], ub[i]).unsigned_abs();
                    if c == 0 {
                        return Err(format!(
                            "round {}: byte {i}: LAT[{:#04x}][{:#04x}] = 0",
                            t + 1,
                            wb[i],
                            ub[i]
                        ));
                    }
                    weight += sbox_bits(c);
                    active += 1;
                }
            }
            u[t] = ut;
            (a, b) = (b, a ^ w[t]);
        }
        Ok(LinTrail {
            rounds: r,
            weight,
            active,
            input: (a, b),
            output,
            u,
            w: w.to_vec(),
        })
    }

    /// |correlation| of the single trail (key-independent).
    pub fn corr_abs(&self) -> f64 {
        2f64.powf(-self.weight)
    }

    /// |bias| = |Pr[phi = 0] - 1/2| = |corr| / 2.
    pub fn bias_abs(&self) -> f64 {
        self.corr_abs() / 2.0
    }

    /// Signed correlation E[(-1)^phi] predicted for a concrete key
    /// (`round_keys[t-1]` = k_t): product of LAT/256 times (-1)^(w_t.k_t).
    pub fn signed_corr(&self, lat: &Lat, round_keys: &[u64]) -> f64 {
        let mut c = 1.0;
        for t in 0..self.rounds {
            let (ub, wb) = (bytes(self.u[t]), bytes(self.w[t]));
            for i in 0..8 {
                if ub[i] != 0 {
                    c *= lat.get(wb[i], ub[i]) as f64 / 256.0;
                }
            }
            if parity(self.w[t] & round_keys[t]) == 1 {
                c = -c;
            }
        }
        c
    }

    /// phi(P, C): parity of the trail's input masks on P and output masks on C.
    pub fn phi(&self, p: (u64, u64), c: (u64, u64)) -> u32 {
        parity(self.input.0 & p.0)
            ^ parity(self.input.1 & p.1)
            ^ parity(self.output.0 & c.0)
            ^ parity(self.output.1 & c.1)
    }
}

/// Greedy backward propagation: in every round take, per active byte, the
/// input mask w_i maximising |LAT[w_i][u_i]| (ties: smallest w_i).
pub fn propagate_greedy(lat: &Lat, output: (u64, u64), rounds: usize) -> LinTrail {
    let (mut a, mut b) = output;
    let mut w = vec![0u64; rounds];
    for t in (0..rounds).rev() {
        w[t] = best_w(lat, diffuse_t(b));
        (a, b) = (b, a ^ w[t]);
    }
    LinTrail::from_masks(lat, output, &w).expect("greedy w is consistent by construction")
}

/// Corrected version of the old `best_lin_trail`: greedy propagation (optimal
/// w per byte per round) from every output mask with one active byte on L or
/// on R (2 x 8 x 255 starts). Local choice only, NOT a global optimum.
pub fn best_lin_trail_greedy(lat: &Lat, rounds: usize) -> LinTrail {
    let mut best: Option<LinTrail> = None;
    for bp in 0..8 {
        for v in 1..256u64 {
            for out in [(v << (8 * bp), 0), (0, v << (8 * bp))] {
                let t = propagate_greedy(lat, out, rounds);
                if best.as_ref().is_none_or(|b| t.weight < b.weight) {
                    best = Some(t);
                }
            }
        }
    }
    best.unwrap()
}

// ---------- beam search over mask sequences ----------
//
// Reparametrise a trail by the S-box-output masks u_1..u_r (u_t = D^T b_t,
// b_t = R-mask after round t). Propagation b_{t-1} = b_{t+1} ^ w_t becomes
//     u_{t+1} = u_{t-1} ^ D^T w_t        (t = 2..r-1, supp(w_t) = supp(u_t)).
// State (u_{t-1}, u_t); u_1, u_2 free; ends (t = 1, r) take the best w.
// Cost of round t = sum over active bytes of 8 - log2 |LAT[w_i][u_i]|.
// Beam: keep the `width` cheapest states per round, `k` best w per byte.
// Any trail returned is a real trail (re-propagated by `from_masks`); the
// weight is an UPPER bound on the optimum (heuristic), not the optimum.

/// Beam parameters used for the trails reported by trail_search and re-checked
/// by linear_trail_check: (width, k best w per byte).
pub const DEFAULT_BEAM: (usize, usize) = (1 << 16, 2);

const FP: f64 = 1_048_576.0;
const NONE: u32 = u32::MAX;

struct Node {
    parent: u32,
    w: u64,
}

#[derive(Clone, Copy)]
struct State {
    key: (u64, u64),
    acc: u64,
    node: u32,
}

/// Best trail per round count r = 1..=max_rounds (index r-1). r = 1 is the
/// trivial weight-0 identity trail (beta = 0).
pub fn best_lin_trails_beam(lat: &Lat, max_rounds: usize, width: usize, k: usize) -> Vec<LinTrail> {
    assert!(max_rounds >= 1 && width >= 1 && k >= 1);
    let mut fpt = vec![0u64; 257];
    for m in 1..=256usize {
        fpt[m] = (sbox_bits(m as u16) * FP).round() as u64;
    }
    let cost_best = |u: u64| -> u64 {
        bytes(u)
            .iter()
            .map(|&b| {
                if b == 0 {
                    0
                } else {
                    fpt[lat.best(b).1 as usize]
                }
            })
            .sum()
    };

    let mut out = vec![propagate_greedy(lat, (1, 0), 1)];
    if max_rounds == 1 {
        return out;
    }

    // Initial states (u_1, u_2), both with <= 1 active byte, not both zero.
    // Byte-rotation symmetry: u_2 (or u_1 if u_2 = 0) sits at byte 0.
    let mut nodes: Vec<Node> = Vec::new();
    let mut cur: Vec<State> = Vec::new();
    let mut singles = vec![0u64];
    for pos in 0..8 {
        for v in 1..256u64 {
            singles.push(v << (8 * pos));
        }
    }
    for &u1 in &singles {
        nodes.push(Node {
            parent: NONE,
            w: best_w(lat, u1),
        });
        let node = (nodes.len() - 1) as u32;
        for v in 1..256u64 {
            cur.push(State {
                key: (u1, v),
                acc: cost_best(u1),
                node,
            });
        }
    }
    for v in 1..256u64 {
        nodes.push(Node {
            parent: NONE,
            w: best_w(lat, v),
        });
        cur.push(State {
            key: (v, 0),
            acc: cost_best(v),
            node: (nodes.len() - 1) as u32,
        });
    }

    cur.sort_unstable_by_key(|a| (a.acc, a.key));
    for t in 2..=max_rounds {
        // best trail ending at round t: last round takes the best w
        let mut best: Option<(u64, State)> = None;
        for s in &cur {
            let total = s.acc + cost_best(s.key.1);
            if best.as_ref().is_none_or(|b| total < b.0) {
                best = Some((total, *s));
            }
        }
        let (total, s) = best.expect("beam is never empty");
        let mut ws = Vec::with_capacity(t);
        let mut n = s.node;
        while n != NONE {
            ws.push(nodes[n as usize].w);
            n = nodes[n as usize].parent;
        }
        ws.reverse();
        assert_eq!(ws.len(), t - 1);
        let (p, q) = s.key;
        let wt = best_w(lat, q);
        ws.push(wt);
        let output = (diffuse_t_inv(p) ^ wt, diffuse_t_inv(q));
        let trail = LinTrail::from_masks(lat, output, &ws).expect("beam trail is consistent");
        assert!(
            (trail.weight - total as f64 / FP).abs() < 1e-3,
            "beam cost {} != re-propagated weight {} (r={t})",
            total as f64 / FP,
            trail.weight
        );
        out.push(trail);
        if t == max_rounds {
            break;
        }

        // expand every state: choose w_t among the k best partners of each active byte.
        // `cur` is sorted by cost, so `thresh` (cost of the width-th best candidate
        // after a prune) tightens quickly and bounds memory.
        let mut next: FxHashMap<(u64, u64), (u64, u32, u64)> = FxHashMap::default();
        let mut thresh = u64::MAX;
        for s in &cur {
            let (p, q) = s.key;
            let qb = bytes(q);
            let act: Vec<usize> = (0..8).filter(|&i| qb[i] != 0).collect();
            let lens: Vec<usize> = act
                .iter()
                .map(|&i| k.min(lat.cols[qb[i] as usize].len()))
                .collect();
            let mut idx = vec![0usize; act.len()];
            'odo: loop {
                let (mut w, mut c) = (0u64, 0u64);
                for (j, &i) in act.iter().enumerate() {
                    let (wb, ab) = lat.cols[qb[i] as usize][idx[j]];
                    w |= (wb as u64) << (8 * i);
                    c += fpt[ab as usize];
                }
                let key = (q, p ^ diffuse_t(w));
                let acc = s.acc + c;
                if acc <= thresh {
                    next.entry(key)
                        .and_modify(|e| {
                            if acc < e.0 {
                                *e = (acc, s.node, w);
                            }
                        })
                        .or_insert((acc, s.node, w));
                    if next.len() > 4 * width {
                        let mut v: Vec<_> = next.drain().collect();
                        v.sort_unstable_by_key(|a| (a.1.0, a.0));
                        v.truncate(width);
                        thresh = v[v.len() - 1].1.0;
                        next.extend(v);
                    }
                }
                let mut j = 0;
                loop {
                    if j == act.len() {
                        break 'odo;
                    }
                    idx[j] += 1;
                    if idx[j] < lens[j] {
                        break;
                    }
                    idx[j] = 0;
                    j += 1;
                }
            }
        }
        let mut v: Vec<_> = next.into_iter().collect();
        v.sort_unstable_by_key(|a| (a.1.0, a.0));
        v.truncate(width);
        cur = v
            .into_iter()
            .map(|(key, (acc, parent, w))| {
                nodes.push(Node { parent, w });
                State {
                    key,
                    acc,
                    node: (nodes.len() - 1) as u32,
                }
            })
            .collect();
    }
    out
}

// ---------- exact identity check against the real cipher ----------

/// Verify, for `samples` random blocks and the given key, that
///   phi(P, C) == XOR_t ( u_t.S(x_t) ^ w_t.R_{t-1} )
/// holds EXACTLY for the trail's masks (no statistics), and that a local
/// re-implementation of the round agrees with `FeistelArx::encrypt_block`.
pub fn check_identity(
    trail: &LinTrail,
    key: &[u8; 32],
    samples: u64,
    seed: u64,
) -> Result<(), String> {
    let c = FeistelArx::new_with_rounds(key, trail.rounds);
    let (ks, sbox) = (c.round_keys(), c.sbox());
    let mut rng = Rng(seed);
    for n in 0..samples {
        let p = (rng.next_u64(), rng.next_u64());
        let (mut l, mut r) = p;
        let mut rhs = 0u32;
        for t in 0..trail.rounds {
            let s = sbox_layer(r, ks[t], sbox);
            rhs ^= parity(trail.u[t] & s) ^ parity(trail.w[t] & r);
            (l, r) = (r, l ^ diffuse(s));
        }
        let mut blk = [0u8; 16];
        blk[..8].copy_from_slice(&p.0.to_le_bytes());
        blk[8..].copy_from_slice(&p.1.to_le_bytes());
        c.encrypt_block(&mut blk);
        let cc = (
            u64::from_le_bytes(blk[..8].try_into().unwrap()),
            u64::from_le_bytes(blk[8..].try_into().unwrap()),
        );
        if cc != (l, r) {
            return Err(format!("sample {n}: local round model != encrypt_block"));
        }
        if trail.phi(p, cc) != rhs {
            return Err(format!(
                "sample {n}: phi != XOR_t(u.S ^ w.R) (r={})",
                trail.rounds
            ));
        }
    }
    Ok(())
}
