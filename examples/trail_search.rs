// Multi-round trail search for Herringfish Feistel ARX v0.2 (solo-arx).
//
// Trails are single characteristics / single linear trails. The S-box layer
// is key-invariant under XOR (z = x ^ k reparametrizes the 256 inputs), so
// F-input/output differences and masks are key-independent; for linear
// trails the magnitude of the correlation is key-independent (the sign is
// not). Per-S-box values are the exact DDT / LAT entries of the frozen S-box.
//
//   1. DIFFERENTIAL (forward, greedy): state (ΔL, ΔR); round update
//        ΔL' = ΔR,  ΔR' = ΔL ^ ΔF(ΔR)
//      ΔF = diffuse ∘ SboxLayer-diff. For each active byte the output
//      difference is the max-probability DDT entry (best-greedy trail); the
//      per-byte probabilities are multiplied. Start: ΔL0 = 0, ΔR0 = 1 byte.
//
//   2. LINEAR (backward). Round: L' = R, R' = L ^ D(S(R ^ k)). With output
//      masks (α on L', β on R'):
//        u = Dᵀβ                     mask on the S-box layer OUTPUT
//        w_i  chosen per active byte  mask on the S-box layer INPUT,
//                                     per-byte correlation LAT[w_i][u_i]/256
//        input masks = (β, α ^ w)    (L-mask, R-mask)
//      Two searches, both exact per trail:
//        - greedy: optimal w_i per byte per round, from every output mask
//          with one active byte on L or R (local choices only);
//        - beam:   beam search over the S-box-output-mask sequence
//          (u_{t+1} = u_{t-1} ^ Dᵀ w_t), `width` cheapest states per round,
//          `k` best w per byte. Real trails, heuristic optimum (upper bound
//          on the best single-trail weight). Lower bound: active_sbox_bound.
//      The rule is verified against the real cipher by linear_trail_check
//      and tests/linear_trail_identity.rs (exact identity, no statistics).
//
// RETRACTION: an earlier version of this tool applied the wrong linear rule
// (it XORed the S-box OUTPUT mask u into the other half and looked up
// LAT[ΓR byte][u byte]); its 2^75.7 "candidate weakness" was an artifact.
// See docs/cryptanalysis/trail_search_v0.3.0-solo.md §3.
//
// Round counts are explicit in output. Deterministic (no randomness).
// Run: cargo run --release --example trail_search [-- <beam_width> <beam_k>]

// Index loops mirror the math (masks, byte positions); same allow as src/cipher/mod.rs.
#![allow(clippy::needless_range_loop)]

#[path = "common/lin_trail.rs"]
mod lin_trail;

use herringfish::cipher::feistel_arx::{HERRINGFISH_SBOX_V02, diffuse};
use lin_trail::{
    DEFAULT_BEAM, Lat, best_lin_trail_greedy, best_lin_trails_beam, check_diffuse_transpose,
};

// ---------- exact S-box DDT ----------

fn compute_ddt(sbox: &[u8; 256]) -> [[u16; 256]; 256] {
    let mut d = [[0u16; 256]; 256];
    for in_ in 1..256usize {
        for x in 0..256usize {
            let out = sbox[x] ^ sbox[x ^ in_];
            d[in_][out as usize] += 1;
        }
    }
    d
}

fn byte_arr(v: &u64) -> [u8; 8] {
    let mut b = [0u8; 8];
    for i in 0..8 {
        b[i] = ((v >> (8 * i)) & 0xff) as u8;
    }
    b
}

fn pack(b: &[u8; 8]) -> u64 {
    let mut v = 0u64;
    for i in 0..8 {
        v |= (b[i] as u64) << (8 * i);
    }
    v
}

// ---------- per-byte probabilities ----------

// best (max-prob) output diff for an input diff byte; returns (dy, prob)
fn best_byte_diff(ddt: &[[u16; 256]; 256], dx: u8) -> (u8, f64) {
    if dx == 0 {
        return (0, 1.0);
    }
    let mut best_dy = 0u8;
    let mut best_c = 0u16;
    for dy in 0..256usize {
        if ddt[dx as usize][dy] > best_c {
            best_c = ddt[dx as usize][dy];
            best_dy = dy as u8;
        }
    }
    (best_dy, best_c as f64 / 256.0)
}

// ---------- differential trail (greedy best) ----------

fn best_diff_trail(ddt: &[[u16; 256]; 256], rounds: usize) -> (f64, u64, u64, u32) {
    // returns (prob, final_dL, final_dR, active_bytes_at_end)
    let mut best_p = 0.0f64;
    let mut best_dl = 0u64;
    let mut best_dr = 0u64;
    let mut best_act = 0u32;

    // start: ΔL0 = 0, ΔR0 = single active byte (8 pos × 255 values)
    for bp in 0..8u32 {
        for dx in 1..256usize {
            let mut dl: u64 = 0;
            let mut dr: u64 = (dx as u64) << (8 * bp);
            let mut log_p = 0.0f64;
            let mut dead = false;

            for _r in 0..rounds {
                let old_dl = dl;
                let old_dr = dr;
                // ΔF = best-greedy SboxLayer-diff(old_dr) then diffuse
                let drb = byte_arr(&old_dr);
                let mut f_bytes = [0u8; 8];
                let mut any = false;
                for i in 0..8 {
                    if drb[i] != 0 {
                        any = true;
                        let (dy, p) = best_byte_diff(ddt, drb[i]);
                        f_bytes[i] = dy;
                        log_p += p.log2();
                    }
                }
                let df = pack(&f_bytes);
                let df_diffused = diffuse(df);
                // ΔL' = ΔR, ΔR' = ΔL ^ ΔF
                dl = old_dr;
                dr = old_dl ^ df_diffused;
                if !any && df_diffused == 0 {
                    // all-zero: prob 1, degenerate
                }
                if log_p <= -1e18 {
                    dead = true;
                    break;
                }
            }
            if dead {
                continue;
            }
            let p = 2f64.powf(log_p);
            let act = byte_arr(&dr).iter().filter(|&&b| b != 0).count() as u32
                + byte_arr(&dl).iter().filter(|&&b| b != 0).count() as u32;
            if p > best_p {
                best_p = p;
                best_dl = dl;
                best_dr = dr;
                best_act = act;
            }
        }
    }
    (best_p, best_dl, best_dr, best_act)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let width: usize = args
        .next()
        .map_or(DEFAULT_BEAM.0, |a| a.parse().expect("beam_width"));
    let k: usize = args
        .next()
        .map_or(DEFAULT_BEAM.1, |a| a.parse().expect("beam_k"));

    check_diffuse_transpose().expect("diffuse_t must be the exact transpose of diffuse");
    println!("[check] diffuse_t == diffuse^T (all 64x64 basis pairs)");
    println!("Computing exact DDT and LAT for HERRINGFISH_SBOX_V02 ...");
    let ddt = compute_ddt(&HERRINGFISH_SBOX_V02);
    let lat = Lat::v02();
    println!("Done.\n");

    // sanity: DDT max, LAT max
    let ddt_max = (1..256)
        .flat_map(|in_| (0..256).map(move |out| ddt[in_][out]))
        .max()
        .unwrap();
    println!("DDT max (in!=0): {}", ddt_max);
    let lat_max = lat.max_abs();
    println!(
        "LAT max |W| (a!=0,b!=0): {}  (max per-byte bias = {:.6})",
        lat_max,
        lat_max as f64 / 512.0
    );

    println!("\n=== Exact differential trails (greedy best, start: 1 active byte on R, ΔL0=0) ===");
    for r in [4usize, 6, 8, 12, 14, 16] {
        let (p, dl, dr, act) = best_diff_trail(&ddt, r);
        let work = if p > 0.0 {
            (1.0 / p).log2()
        } else {
            f64::INFINITY
        };
        println!(
            "  rounds={:<2}  p={:.6e}  work≈2^{:.1}  final ΔL={:016x} ΔR={:016x} (active bytes={})",
            r, p, work, dl, dr, act
        );
    }

    println!(
        "\n=== Linear trails, corrected mask rule (single trail, |corr| = 2^-weight, |bias| = |corr|/2) ==="
    );
    println!("greedy: optimal w per byte per round, 4080 single-byte output masks (L or R)");
    println!(
        "beam:   width={width}, k={k} best w per byte (heuristic; weight is an upper bound on the best trail)"
    );
    let rounds = [2usize, 3, 4, 6, 8, 12, 14, 16];
    let max_r = *rounds.last().unwrap();
    let beam = best_lin_trails_beam(&lat, max_r, width, k);
    for &r in &rounds {
        let g = best_lin_trail_greedy(&lat, r);
        let b = &beam[r - 1];
        println!(
            "  rounds={:<2} greedy: weight={:6.2} active={:<3} |  beam: weight={:6.2} active={:<3} |corr|=2^-{:.2} |bias|=2^-{:.2}",
            r,
            g.weight,
            g.active,
            b.weight,
            b.active,
            b.weight,
            b.weight + 1.0
        );
        println!(
            "             beam masks: plaintext (L0,R0)=({:016x},{:016x})  ciphertext (L{r},R{r})=({:016x},{:016x})",
            b.input.0, b.input.1, b.output.0, b.output.1
        );
    }
}
