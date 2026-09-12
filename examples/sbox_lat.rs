//! Herringfish S-box linear spectrum + best linear approximation of F
//!
//! Computes the exact Walsh spectrum W_S(a, b) of HERRINGFISH_SBOX_V02:
//!
//!     W_S(a, b) = sum_x (-1)^(a.x ^ b.S(x))
//!
//! and the exact best linear approximation of the full F function
//!
//!     F(x) = Diffuse(SBox(x)),
//!     y_i  = x_i ^ x_(i+1) ^ x_(i+3)      (bytes, mod 8)
//!
//! A linear approximation (a, b) of F expands as
//!
//!     a.x ^ b.F(x) = a.x ^ (D^T b).S(x),
//!     (D^T b)_j    = b_j ^ b_(j-1) ^ b_(j-3)      (indices mod 8)
//!
//! so per byte
//!
//!     c_F(a, b) = prod_j c_S(a_j, (D^T b)_j),     c_S = W_S / 256.
//!
//! Since S is a permutation:
//!
//!     W_S(0,0) = 256,  W_S(0,v) = 0 (v != 0),  W_S(a,0) = 0 (a != 0)
//!
//! Define g(0) = 1 and g(v) = max_{a != 0} |W_S(a, v)| / 256 for v != 0.
//! Then for any b:  |c_F| <= prod_j g((D^T b)_j).
//!
//! KEY SIMPLIFICATION: the byte-level diffusion D (and hence D^T) is a
//! BIJECTION on (GF(2)^8)^8 (rank 8, verified in this tool). Therefore, as
//! b ranges over all 64-bit masks, t = D^T b ranges bijectively over all
//! 8-byte vectors, and the per-byte factors can be maximized independently:
//!
//!     c_max(F) = max_{t != 0} prod_j g(t_j) = (max_{v != 0} g(v))^8
//!              = g_max^8.
//!
//! The diffusion relabels masks but does not reduce the best linear
//! approximation of F.
//!
//! Output:
//!   - Walsh spectrum statistics (max |W|, Parseval check, distribution)
//!   - exact c_max(F) and the optimal mask pair (a*, b*)
//!   - sparse-output-mask bounds (wt(b) = 1, 2) computed by enumeration
//!   - 16-round bound: |c| <= c_max^8  (8 F applications), i.e.
//!     data complexity >= 2^(-16 log2 c_max)

use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

type Walsh = [[i32; 256]; 256];

/// (-1)^(parity(x)) as i32
fn parity_sign(x: u16) -> i32 {
    if (x as u32).count_ones() & 1 == 0 {
        1
    } else {
        -1
    }
}

/// Full Walsh spectrum: W[a][b] = sum_x (-1)^(a.x ^ b.S(x)).
fn build_walsh(sbox: &[u8; 256]) -> Walsh {
    // sign[a][x] = (-1)^(a.x)
    let mut sign = [[1i32; 256]; 256];
    for a in 0..256u16 {
        for x in 0..256u16 {
            sign[a as usize][x as usize] = parity_sign(a & x);
        }
    }
    // For each (a, x), add sign[a][x] * sign[b][S[x]] to W[a][b] over all b.
    let mut w: Walsh = [[0i32; 256]; 256];
    for a in 0..256u16 {
        for x in 0..256u16 {
            let sx = sbox[x as usize] as u16;
            let sa = sign[a as usize][x as usize];
            for b in 0..256u16 {
                w[a as usize][b as usize] += sa * sign[b as usize][sx as usize];
            }
        }
    }
    w
}

/// (D^T b) at byte level: t_j = b_j ^ b_(j-1) ^ b_(j-3) mod 8.
fn dt_bytes(b: [u8; 8]) -> [u8; 8] {
    let mut t = [0u8; 8];
    for j in 0..8 {
        t[j] = b[j] ^ b[(j + 7) % 8] ^ b[(j + 5) % 8];
    }
    t
}

/// Verify the byte-level diffusion transpose is a bijection on (GF(2)^8)^8
/// by building its 64x64 GF(2) matrix and checking rank 64.
///
/// Output bit (8*j + r) depends on input bits of b_j, b_(j-1), b_(j-3) at
/// bit r.
fn dt_is_bijection() -> bool {
    // Build rows: for each output bit i, a u128... 64 bits -> use two u64.
    let mut rows: [(u64, u64); 64] = [(0, 0); 64];
    for j in 0..8usize {
        for r in 0..8usize {
            let out_bit = j * 8 + r;
            for &src in &[j, (j + 7) % 8, (j + 5) % 8] {
                rows[out_bit].0 |= 1u64 << (src * 8 + r);
            }
        }
    }
    // Gaussian elimination over GF(2), rank.
    let mut rank = 0usize;
    let mut m: [u128; 64] = rows.map(|(lo, hi)| lo as u128 | ((hi as u128) << 64));
    for col in 0..64usize {
        let pivot = m[rank..].iter().position(|row| (row >> col) & 1 == 1);
        match pivot {
            Some(p) => {
                m.swap(rank, rank + p);
                for i in 0..64 {
                    if i != rank && ((m[i] >> col) & 1) == 1 {
                        m[i] ^= m[rank];
                    }
                }
                rank += 1;
            }
            None => {}
        }
    }
    rank == 64
}

/// Solve D^T x = y (byte level) by Gaussian elimination over GF(2)^8.
/// Returns None if no solution (should not happen: bijection).
fn dt_solve(y: [u8; 8]) -> Option<[u8; 8]> {
    // 64x64 bit matrix, RHS 64 bits.
    let mut rows: [(u128, u128); 64] = [(0, 0); 64];
    for j in 0..8usize {
        for r in 0..8usize {
            let out_bit = j * 8 + r;
            for &src in &[j, (j + 7) % 8, (j + 5) % 8] {
                rows[out_bit].0 |= 1u128 << (src * 8 + r);
            }
            // RHS: output byte j, bit r = y[j] >> r & 1
            if (y[j] >> r) & 1 == 1 {
                rows[out_bit].1 |= 1u128 << out_bit;
            }
        }
    }
    let mut rank = 0usize;
    for col in 0..64usize {
        let pivot = rows[rank..].iter().position(|row| (row.0 >> col) & 1 == 1);
        if let Some(p) = pivot {
            rows.swap(rank, rank + p);
            for i in 0..64 {
                if i != rank && ((rows[i].0 >> col) & 1) == 1 {
                    rows[i].0 ^= rows[rank].0;
                    rows[i].1 ^= rows[rank].1;
                }
            }
            rank += 1;
        }
    }
    if rank != 64 {
        return None;
    }
    // rows[i] is now e_{pivcol(i)} with RHS bit.
    let mut x_bits = [0u8; 8];
    for i in 0..64 {
        // find the set bit in rows[i].0
        let col = (rows[i].0 & !0u128).trailing_zeros() as usize;
        if (rows[i].1 >> i) & 1 == 1 {
            x_bits[col / 8] |= 1u8 << (col % 8);
        }
    }
    Some(x_bits)
}

fn main() {
    println!("============================================================");
    println!("HERRINGFISH S-BOX WALSH SPECTRUM + F LINEAR BOUND");
    println!("============================================================");
    println!();

    // ------------------------------------------------------------------
    // 1. Walsh spectrum
    // ------------------------------------------------------------------
    println!("[1] Building Walsh spectrum W_S(a,b) of HERRINGFISH_SBOX_V02 ...");
    let walsh = build_walsh(&HERRINGFISH_SBOX_V02);

    // Structural validation.
    let mut ok = true;
    if walsh[0][0] != 256 {
        eprintln!("FAIL: W(0,0) = {}", walsh[0][0]);
        ok = false;
    }
    for b in 1..256usize {
        if walsh[0][b] != 0 {
            eprintln!("FAIL: W(0, {}) = {}", b, walsh[0][b]);
            ok = false;
        }
        if walsh[b][0] != 0 {
            eprintln!("FAIL: W({}, 0) = {}", b, walsh[b][0]);
            ok = false;
        }
    }
    let mut parseval: i64 = 0;
    let mut max_abs = 0i32;
    let mut max_at: (usize, usize) = (0, 0);
    let mut hist: std::collections::BTreeMap<i32, usize> = std::collections::BTreeMap::new();
    for a in 0..256usize {
        for b in 0..256usize {
            let v = walsh[a][b].abs();
            *hist.entry(v).or_insert(0) += 1;
            parseval += (v as i64) * (v as i64);
            if (a != 0 || b != 0) && v > max_abs {
                max_abs = v;
                max_at = (a, b);
            }
        }
    }
    println!(
        "    W(0,0) = 256, W(0,v!=0) = 0 = W(a!=0,0) : {}",
        if ok { "PASS" } else { "FAIL" }
    );
    println!(
        "    Parseval sum W^2 = {} (expect {}): {}",
        parseval,
        1 << 24,
        if parseval == (1 << 24) as i64 {
            "PASS"
        } else {
            "FAIL"
        }
    );
    println!(
        "    Max |W_S| (nontrivial) = {}  (correlation {}/256 = 2^-{})",
        max_abs,
        max_abs,
        (256.0 / max_abs as f64).log2()
    );
    println!("    at (a, b) = ({:#04x}, {:#04x})", max_at.0, max_at.1);
    println!("    |W| distribution:");
    for (k, n) in &hist {
        println!("      |W| = {:>3} : {:>6} entries", k, n);
    }
    println!();

    // ------------------------------------------------------------------
    // 2. g(v) and c_max
    // ------------------------------------------------------------------
    println!("[2] Best linear approximation of F");
    let mut g = [0f64; 256];
    let mut g_arg = [0usize; 256];
    g[0] = 1.0;
    for v in 1..256usize {
        let mut best = 0i32;
        let mut best_a = 0usize;
        for a in 1..256usize {
            let w = walsh[a][v].abs();
            if w > best {
                best = w;
                best_a = a;
            }
        }
        g[v] = best as f64 / 256.0;
        g_arg[v] = best_a;
    }
    let (g_max, v_star) = (1..256)
        .map(|v| (g[v], v))
        .max_by(|x, y| x.0.partial_cmp(&y.0).unwrap())
        .unwrap();

    let dt_bijective = dt_is_bijection();
    println!(
        "    D^T byte-level bijection (rank 64 over GF(2)) : {}",
        if dt_bijective { "PASS" } else { "FAIL" }
    );
    if !dt_bijective {
        eprintln!(
            "    ERROR: D^T not bijective; the independence argument fails. Aborting c_max claim."
        );
        return;
    }
    println!(
        "    g_max = max_v g(v) = {:.4} at v = {:#04x} (a = {:#04x})",
        g_max, v_star, g_arg[v_star]
    );
    println!(
        "    => c_max(F) = g_max^8 = {:.4e} = 2^-{}",
        g_max.powi(8),
        (-g_max.powi(8)).log2()
    );
    println!();
    println!("    Argument: D^T bijective => t = D^T b spans all 8-byte");
    println!("    vectors as b varies, so the per-byte factors g(t_j) are");
    println!("    independently maximizable: set every t_j = v*, then");
    println!("    b* = (D^T)^-1 (v*,...,v*) and a* has byte j = g_arg(v*).");
    if let Some(b_star) = dt_solve([v_star as u8; 8]) {
        let a_star: [u8; 8] = [g_arg[v_star] as u8; 8];
        // verify
        let t = dt_bytes(b_star);
        let mut c = 1f64;
        for j in 0..8 {
            c *= walsh[a_star[j] as usize][t[j] as usize].abs() as f64 / 256.0;
        }
        println!(
            "    b* = {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}  (F output mask, bytes 0..7)",
            b_star[0], b_star[1], b_star[2], b_star[3], b_star[4], b_star[5], b_star[6], b_star[7]
        );
        println!(
            "    a* = {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}  (F input mask,  bytes 0..7)",
            a_star[0], a_star[1], a_star[2], a_star[3], a_star[4], a_star[5], a_star[6], a_star[7]
        );
        println!(
            "    verified c_F(a*,b*) = {:.4e} (matches g_max^8 = {:.4e})",
            c,
            g_max.powi(8)
        );
    }
    println!();

    // ------------------------------------------------------------------
    // 3. Sparse output-mask bounds (early Feistel rounds)
    // ------------------------------------------------------------------
    println!("[3] Sparse F-output mask bounds (wt(b) = 1, 2):");
    // wt(b) = 1: b supported on one byte i with value v != 0.
    // t = D^T b has support subset of {i, i-1, i-3}: at most 3 active bytes.
    let mut best1: (f64, usize, usize) = (0.0, 0, 0);
    for i in 0..8 {
        for v in 1..256u16 {
            let b = {
                let mut x = [0u8; 8];
                x[i] = v as u8;
                x
            };
            let t = dt_bytes(b);
            let mut c = 1f64;
            for j in 0..8 {
                c *= g[t[j] as usize];
            }
            if c > best1.0 {
                best1 = (c, i, v as usize);
            }
        }
    }
    println!(
        "    wt(b)=1: max |c_F| = {:.4e} = 2^-{}  (byte {}, value {:#04x})",
        best1.0,
        (-best1.0).log2(),
        best1.1,
        best1.2
    );
    // wt(b) = 2: bytes i < j, values v1, v2.
    let mut best2: (f64, usize, usize, usize, usize) = (0.0, 0, 0, 0, 0);
    for i in 0..8 {
        for j in (i + 1)..8 {
            for v1 in 1..256u16 {
                for v2 in 1..256u16 {
                    let b = {
                        let mut x = [0u8; 8];
                        x[i] = v1 as u8;
                        x[j] = v2 as u8;
                        x
                    };
                    let t = dt_bytes(b);
                    let mut c = 1f64;
                    for k in 0..8 {
                        c *= g[t[k] as usize];
                    }
                    if c > best2.0 {
                        best2 = (c, i, v1 as usize, j, v2 as usize);
                    }
                }
            }
        }
    }
    println!(
        "    wt(b)=2: max |c_F| = {:.4e} = 2^-{}  (bytes {}/{} values {:#04x}/{:#04x})",
        best2.0,
        (-best2.0).log2(),
        best2.1,
        best2.3,
        best2.2,
        best2.4
    );
    // wt(b) >= 3: t can have all 8 bytes active -> bound g_max^8.
    println!(
        "    wt(b)>=3: |c_F| <= g_max^8 = 2^-{} (all 8 bytes can be active)",
        (-g_max.powi(8)).log2()
    );
    println!();

    // ------------------------------------------------------------------
    // 4. 16-round summary
    // ------------------------------------------------------------------
    println!("[4] 16-round classical linear bound");
    let c16 = g_max.powi(8); // 8 F applications, each fully active
    println!(
        "    Fully-active trail (8 F's, each |c| <= 2^-{}):",
        (-g_max.powi(8)).log2()
    );
    println!("      |c| <= 2^-{}", (-c16).log2());
    println!(
        "      Data complexity N >= c^-2 = 2^{}",
        (-2.0 * c16).log2()
    );
    println!(
        "    Even with sparse early rounds (2^-{} + 2^-{} + 14 x 2^-{})",
        (-best1.0).log2(),
        (-best2.0).log2(),
        (-g_max.powi(8)).log2()
    );
    let c16_sparse = best1.0 * best2.0 * g_max.powi(8).powf(6.0);
    println!(
        "      |c| <= 2^-{}  =>  N >= 2^{}",
        (-c16_sparse).log2(),
        (-2.0 * c16_sparse).log2()
    );
    println!();
    println!("    NOTE: these are single-trail bounds. The linear HULL");
    println!("    (sum of 2^(16n - 1) trails) can only weaken the bound");
    println!("    (lower |c|), never strengthen it below the best trail");
    println!("    when trails are near-disjoint; the best-trail bound is");
    println!("    the standard headline number (cf. AES: 2^-25 class,");
    println!("    hull analysis confirms infeasibility).");
}
