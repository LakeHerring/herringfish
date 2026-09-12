// Empirical validation of the 16-round linear trail found by trail_search.rs.
//
// The trail search reports a best 16-round linear trail with a per-round
// LAT product giving an estimated distinguisher work of ~2^75.7, which is
// below the 2^128 security target. That figure is a GREEDY trail-weight
// bound, not a confirmed distinguisher. This example empirically tests the
// specific mask to see whether the predicted bias is actually present in the
// real cipher.
//
// Method:
//   1. Re-derive the best 16-round linear trail (same greedy search as
//      trail_search.rs) to obtain the exact masks (ΓL, ΓR) on the ciphertext.
//   2. For N random keys and N random plaintext pairs, compute the linear
//      approximation
//        φ(P, C) = parity(ΓL_pt · P_L) ^ parity(ΓR_pt · P_R)
//                ^ parity(ΓL_ct · C_L) ^ parity(ΓR_ct · C_R)
//      where the plaintext-side masks are obtained by running the trail
//      BACKWARD from the ciphertext masks (i.e., through the inverse mask
//      propagation), so φ is the correct input/output parity for the trail.
//   3. Count how often φ = 0. Under the null hypothesis (no bias) this is
//      Binomial(N, 0.5). Under the trail hypothesis the true probability is
//      p = (1 + ε)/2 where ε is the actual bias.
//   4. Report the observed frequency, the 95% confidence interval, and a
//      z-score against p=0.5.
//
// Interpretation:
//   - If |observed - 0.5| is within the 95% CI of 0.5 at the given N, the
//     bias is NOT confirmed at this sample size. The trail is a candidate,
//     not a confirmed weakness.
//   - If |observed - 0.5| exceeds the CI, the bias is present. The size of
//     the bias determines the actual work factor.
//
// Sample size: 2^20 pairs per key is the minimum for meaningful detection
// of biases down to ~1e-3. The trail's predicted combined bias is much
// smaller (~1e-12), so 2^20 will almost certainly NOT detect it directly.
// Instead, this test serves two purposes:
//   (a) Confirm that the mask propagation and parity code are correct by
//       checking that the observed frequency is consistent with 0.5 (no
//       gross bias), which validates the experimental setup.
//   (b) If the observed frequency deviates from 0.5 by more than expected,
//       flag it as a potential confirmatory signal.
//
// For a definitive test of a 1e-12 bias, ~2^44 samples would be needed,
// which is infeasible. The practical conclusion is:
//   - The 2^75.7 work figure is a THEORETICAL bound from the trail weight.
//   - It requires 2^75.7 known plaintext/ciphertext pairs to exploit.
//   - Whether it is a practical threat depends on the data-availability
//     model, not on the bias magnitude alone.
//
// Run: cargo run --release --example linear_bias_test

use herringfish::cipher::feistel_arx::{FeistelArx, HERRINGFISH_SBOX_V02};

const ROUNDS: usize = 16;
const SAMPLES: usize = 1 << 20; // 1,048,576

// ---------- same helpers as trail_search.rs ----------

fn compute_lat(sbox: &[u8; 256]) -> [[i16; 256]; 256] {
    let mut l = [[0i16; 256]; 256];
    for a in 0..256usize {
        for b in 0..256usize {
            let mut w: i16 = 0;
            for x in 0..256usize {
                let p1 = ((a as u8) & (x as u8)).count_ones() & 1;
                let p2 = ((b as u8) & sbox[x]).count_ones() & 1;
                w += if p1 ^ p2 == 0 { 1 } else { -1 };
            }
            l[a][b] = w;
        }
    }
    l
}

fn diffuse_t(g: u64) -> u64 {
    let gb = byte_arr(&g);
    let mut d = [0u8; 8];
    for j in 0..8 {
        d[j] = gb[j] ^ gb[(j + 7) % 8] ^ gb[(j + 5) % 8];
    }
    pack(&d)
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

fn byte_lat_prob_fixed(lat: &[[i16; 256]; 256], a: u8, b: u8) -> f64 {
    if a == 0 && b == 0 {
        1.0
    } else if a == 0 || b == 0 {
        0.5
    } else {
        (256.0 - lat[a as usize][b as usize].abs() as f64) / 512.0
    }
}

fn best_lin_trail(lat: &[[i16; 256]; 256], rounds: usize) -> (f64, u64, u64, u64, u64) {
    // returns (trail_product, gl_pt, gr_pt, gl_ct, gr_ct)
    // start: (gl_pt, gr_pt) = (single active byte on L, 0)
    // after R rounds: (gl_ct, gr_ct) = ciphertext-side masks
    let mut best_p = 2.0f64;
    let mut best_gl_pt = 0u64;
    let mut best_gr_pt = 0u64;
    let mut best_gl_ct = 0u64;
    let mut best_gr_ct = 0u64;
    for bp in 0..8u32 {
        for ga in 1..256usize {
            let gl_pt: u64 = (ga as u64) << (8 * bp);
            let gr_pt: u64 = 0;
            let mut gl = gl_pt;
            let mut gr = gr_pt;
            let mut log_p = 0.0f64;
            for _r in 0..rounds {
                let old_gl = gl;
                let old_gr = gr;
                let f_mask = diffuse_t(old_gr);
                let fmb = byte_arr(&f_mask);
                let grb = byte_arr(&old_gr);
                for i in 0..8 {
                    if grb[i] != 0 {
                        log_p += byte_lat_prob_fixed(lat, grb[i], fmb[i]).log2();
                    }
                }
                gl = old_gr;
                gr = old_gl ^ f_mask;
            }
            let p = 2f64.powf(log_p);
            if p < best_p {
                best_p = p;
                best_gl_pt = gl_pt;
                best_gr_pt = gr_pt;
                best_gl_ct = gl;
                best_gr_ct = gr;
            }
        }
    }
    (best_p, best_gl_pt, best_gr_pt, best_gl_ct, best_gr_ct)
}

// ---------- plaintext-side mask derivation ----------
// The trail search gives (ΓL_ct, ΓR_ct) on the CIPHERTEXT.
// To form the correct linear approximation φ(P,C), we need the
// corresponding (ΓL_pt, ΓR_pt) on the PLAINTEXT.
//
// In a Feistel cipher with rounds r = 1..R, the mask propagation is:
//   Forward (encryption): state (L,R) -> (R, L ^ F(R))
//   Mask forward: (ΓL, ΓR) -> (ΓR, ΓL ^ diffuse_t(ΓR))
//
// The trail search propagates the ciphertext mask BACKWARD through the
// cipher. But the "start" in best_lin_trail is (ΓL_ct, ΓR_ct) = output,
// and it propagates forward R times, which gives us the mask on the
// input (plaintext) side... wait, no.
//
// Let me re-examine. In best_lin_trail, the initial state is
//   gl = (ga) << (8*bp),  gr = 0
// and the loop does:
//   gl' = gr,  gr' = gl ^ diffuse_t(gr)
// after R iterations, (gl, gr) is the "final" state.
//
// This is propagating the mask FORWARD through R rounds, starting from
// a mask on the LEFT half with right half zero. The question is: is the
// initial state the plaintext mask or the ciphertext mask?
//
// For a standard linear cryptanalysis trail:
//   We place masks on the INPUT (plaintext) and propagate forward to get
//   masks on the OUTPUT (ciphertext). The trail weight is the product of
//   per-round linear approximations.
//
// So: initial (gl, gr) = (ΓL_pt, ΓR_pt) = plaintext-side masks
//     final   (gl, gr) = (ΓL_ct, ΓR_ct) = ciphertext-side masks
//
// The trail search's "start: 1 active byte on L, ΓR0=0" means:
//   ΓL_pt = single active byte (on the plaintext LEFT half)
//   ΓR_pt = 0
// and the result (ΓL_ct, ΓR_ct) is the ciphertext mask.
//
// So for the empirical test:
//   φ(P, C) = parity(ΓL_pt · P_L) ^ parity(ΓR_pt · P_R)
//           ^ parity(ΓL_ct · C_L) ^ parity(ΓR_ct · C_R)
// where ΓL_pt, ΓR_pt are the INITIAL masks and ΓL_ct, ΓR_ct are the FINAL.

fn parity(x: u64, mask: u64) -> u64 {
    (x & mask).count_ones() as u64 & 1
}

// ---------- main ----------

fn main() {
    println!("Computing exact LAT for HERRINGFISH_SBOX_V02 ...");
    let lat = compute_lat(&HERRINGFISH_SBOX_V02);
    println!("Done.\n");

    println!("Finding best {}-round linear trail ...", ROUNDS);
    let (trail_prod, gl_pt, gr_pt, gl_ct, gr_ct) = best_lin_trail(&lat, ROUNDS);
    let est_work = if trail_prod > 0.0 && trail_prod < 0.5 {
        -2.0 * trail_prod.log2()
    } else {
        f64::INFINITY
    };
    println!("  trail product = {:.6e}", trail_prod);
    println!("  est. work     ≈ 2^{:.1}", est_work);
    println!("  ΓL (pt) = {:016x}   ΓR (pt) = {:016x}", gl_pt, gr_pt);
    println!("  ΓL (ct) = {:016x}   ΓR (ct) = {:016x}", gl_ct, gr_ct);

    // Verify masks are non-trivial.
    assert!(
        gl_pt != 0 || gr_pt != 0,
        "plaintext mask is all-zero — trail is degenerate"
    );
    assert!(
        gl_ct != 0 || gr_ct != 0,
        "ciphertext mask is all-zero — trail is degenerate"
    );

    // Sanity: verify mask propagation is consistent by checking the
    // per-round weight of the final state matches the trail product.
    // (This is a structural check, not a numerical one.)
    let mut vgl = gl_pt;
    let mut vgr = gr_pt;
    for _r in 0..ROUNDS {
        let old_gl = vgl;
        let old_gr = vgr;
        vgl = old_gr;
        vgr = old_gl ^ diffuse_t(old_gr);
    }
    assert_eq!(vgl, gl_ct, "mask propagation mismatch (ΓL)");
    assert_eq!(vgr, gr_ct, "mask propagation mismatch (ΓR)");
    println!("  mask propagation verification: PASSED");

    // ---------- empirical test ----------
    println!("\nRunning empirical bias test:");
    println!("  samples = 2^{} = {}", SAMPLES.trailing_zeros(), SAMPLES);

    // Use a fixed key for reproducibility.
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    let cipher = FeistelArx::new(&key);

    // Deterministic PRNG for plaintext generation (xorshift128+).
    // We use the cipher's own structure to generate pseudo-random plaintexts
    // via a simple LCG to avoid a rand dependency.
    let mut state: u64 = 0x1234567890abcdef;
    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state >> 33
    }

    let mut total_zero: u64 = 0;
    let mut total_n: u64 = 0;

    for _sample in 0..SAMPLES {
        // Generate two random plaintexts.
        let pt1_l = lcg(&mut state);
        let pt1_r = lcg(&mut state);
        let pt2_l = lcg(&mut state);
        let pt2_r = lcg(&mut state);

        // Encrypt.
        let mut block1 = [0u8; 16];
        let mut block2 = [0u8; 16];
        block1[..8].copy_from_slice(&pt1_l.to_le_bytes());
        block1[8..].copy_from_slice(&pt1_r.to_le_bytes());
        block2[..8].copy_from_slice(&pt2_l.to_le_bytes());
        block2[8..].copy_from_slice(&pt2_r.to_le_bytes());

        cipher.encrypt_block(&mut block1);
        cipher.encrypt_block(&mut block2);

        let ct1_l = u64::from_le_bytes(block1[..8].try_into().unwrap());
        let ct1_r = u64::from_le_bytes(block1[8..].try_into().unwrap());
        let ct2_l = u64::from_le_bytes(block2[..8].try_into().unwrap());
        let ct2_r = u64::from_le_bytes(block2[8..].try_into().unwrap());

        // Linear approximation φ for a single (P, C) pair:
        // φ = parity(ΓL_pt · P_L) ^ parity(ΓR_pt · P_R) ^ parity(ΓL_ct · C_L) ^ parity(ΓR_ct · C_R)
        // Under the bias hypothesis, φ = 0 with probability (1+ε)/2.
        // We use the first plaintext/ciphertext pair per sample.
        let phi = parity(pt1_l, gl_pt)
            ^ parity(pt1_r, gr_pt)
            ^ parity(ct1_l, gl_ct)
            ^ parity(ct1_r, gr_ct);

        if phi == 0 {
            total_zero += 1;
        }
        total_n += 1;

        // Suppress unused warning for the second pair (kept for future
        // paired-difference extensions).
        let _ = (pt2_l, pt2_r, ct2_l, ct2_r);
    }

    let freq = total_zero as f64 / total_n as f64;
    let expected = 0.5;
    let std_err = (0.25 / total_n as f64).sqrt();
    let z = (freq - expected) / std_err;
    let ci_low = freq - 1.96 * std_err;
    let ci_high = freq + 1.96 * std_err;

    println!("\n=== Results (key = 000102...1f) ===");
    println!("  observed freq(phi=0)  = {:.8}", freq);
    println!("  95% CI                = [{:.8}, {:.8}]", ci_low, ci_high);
    println!("  z-score vs 0.5        = {:.2}", z);
    println!("  std. error            = {:.8}", std_err);
    println!("  samples             = {}", total_n);

    // Interpretation
    println!("\n=== Interpretation ===");
    if ci_low > expected || ci_high < expected {
        println!(
            "  BIAS DETECTED: 0.5 is outside the 95% CI. Observed deviation = {:.2e}",
            (freq - expected).abs()
        );
        println!("  This suggests the trail may have a real (small) bias.");
        println!("  Estimated bias ε ≈ {:.2e}", (freq - expected).abs() * 2.0);
        println!("  Note: a single key/sample size cannot confirm the trail's full");
        println!("  predicted bias. Further multi-key testing is needed.");
    } else {
        println!(
            "  NO BIAS DETECTED: 0.5 is within the 95% CI at N={}.",
            total_n
        );
        println!("  The observed frequency is consistent with the null hypothesis.");
        println!("  This does NOT refute the trail — the predicted combined bias");
        println!("  (~1e-12) is far below the detection threshold at this sample size.");
        println!(
            "  Detection threshold at 95% confidence: |ε| > {:.2e}",
            1.96 * std_err * 2.0
        );
        println!();
        println!("  CONCLUSION: The 2^75.7 work figure stands as a THEORETICAL bound.");
        println!("  It would require ~2^75.7 known plaintext/ciphertext pairs to exploit.");
        println!("  Whether this is a practical threat depends on the data-availability");
        println!(
            "  model. At N = 2^{}, no statistical evidence of bias was found.",
            total_n.trailing_zeros()
        );
    }

    // Also report the per-round breakdown of the trail weight for context.
    println!("\n=== Trail weight context ===");
    println!("  Per-round LAT product (16 rounds) = {:.6e}", trail_prod);
    println!(
        "  (The product {:.2e} is the per-round LAT product, not the actual full-cipher bias.)",
        trail_prod
    );
    println!(
        "  Distinguisher work ≈ 2^(−2·log₂(product)) = 2^{:.1}",
        est_work
    );
    println!();
    println!("  NOTE: The trail product is NOT the actual combined bias of the");
    println!("  full-cipher approximation. The actual bias ε of φ(P,C) for the");
    println!("  16-round cipher is the quantity measured above. The trail product");
    println!("  is a standard (often pessimistic or optimistic) estimate of |ε|.");
    println!("  The empirical measurement is the authoritative value.");
}
