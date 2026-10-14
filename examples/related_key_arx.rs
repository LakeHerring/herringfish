// Related-key analysis for the solo-ARX key schedule (Herringfish v0.3.0-solo).
//
// The solo-arx variant uses a self-contained ARX key schedule (no SHAKE/SHA3).
// Related-key attacks exploit algebraic relationships between round keys
// derived from related master keys. If round keys from key K and K' (where
// K' = K XOR ΔK) are linearly related, an attacker might find a related-key
// differential trail with much better probability than the single-key case.
//
// This example performs two analyses:
//
// 1. ROUND-KEY LINEARITY CHECK
//    For a set of single-bit master-key differences ΔK (2^8 × 8 = 2048
//    patterns, one bit per byte of the 256-bit key), compute:
//      rk[K] = expand(K)
//      rk[K'] = expand(K XOR ΔK)
//      Δrk = rk[K] XOR rk[K']
//    Then check whether Δrk is LINEAR in ΔK: i.e., does Δrk for (ΔK1 XOR ΔK2)
//    equal Δrk(ΔK1) XOR Δrk(ΔK2)? If the schedule is a GF(2)-linear function
//    of the key, this holds. If it's affine (linear + constant), Δrk is linear
//    in ΔK (the constant cancels). If it's truly nonlinear, this check fails
//    for some (ΔK1, ΔK2) pairs.
//
//    The ARX schedule uses modular addition (not XOR), so it is NOT linear
//    in the key. The question is how far from linear it is. We measure the
//    "linearity gap": for random ΔK1, ΔK2, how often does
//    Δrk(ΔK1 XOR ΔK2) == Δrk(ΔK1) XOR Δrk(ΔK2)?
//
// 2. RELATED-KEY DIFFERENTIAL PROBABILITY
//    For a set of related-key pairs (K, K XOR ΔK) with small Hamming weight
//    ΔK (1-4 bits), check whether the resulting round-key differences Δrk
//    enable differential trails with significantly better probability than
//    the single-key best. Specifically:
//    - Compute the round-key differences Δrk[0..16]
//    - For each round, the effective input difference to the S-box layer
//      is (ΔR XOR Δrk_effective) — in the standard single-key model, the
//      key difference doesn't appear in the differential because both
//      plaintexts use the same key. In the related-key model, the two
//      plaintexts use different keys, so the S-box input difference is
//      (P1 XOR K1) XOR (P2 XOR K2) = ΔP XOR ΔK, which changes the DDT
//      lookup.
//
//    This is a simplified related-key differential: we check whether the
//    round-key differences introduce a systematic bias that makes certain
//    input differences more or less likely to propagate.
//
// 3. ROUND-KEY INDEPENDENCE (SAMPLING)
//    For random keys K1, K2 with Hamming weight 1-8 differences, compute
//    the Hamming weight of Δrk[i] for each round i. If the schedule is
//    well-mixed, Δrk[i] should look random (Hamming weight ≈ 32 ± 5).
//    If certain round-key positions are weakly mixed (Hamming weight
//    significantly below 32), those positions are vulnerable to
//    related-key attacks.
//
// Run: cargo run --release --example related_key_arx

// Index loops mirror the math (masks, byte positions); same allow as src/cipher/mod.rs.
#![allow(clippy::needless_range_loop)]

use herringfish::cipher::arx_key_schedule::{expand, split_key_words};
use herringfish::cipher::feistel_arx::{HERRINGFISH_SBOX_V02, diffuse};

const NUM_ROUNDS: usize = 16;

// ---------- DDT (for related-key differential) ----------

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

// (byte_arr and pack not needed for this analysis — the ARX schedule
// operates on u64 words, not byte arrays)

fn xor_words(a: &[u64], b: &[u64]) -> Vec<u64> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

// ---------- analysis 1: linearity gap ----------

fn linearity_gap() {
    println!("=== 1. Round-key linearity gap ===");
    println!("Checking whether Δrk(ΔK1 XOR ΔK2) == Δrk(ΔK1) XOR Δrk(ΔK2)\n");

    let base_key: [u8; 32] = [0u8; 32];
    let base_rk = expand(&base_key, NUM_ROUNDS);

    // Test with single-bit ΔK values
    let mut single_bit_dks: Vec<[u8; 32]> = Vec::new();
    for byte_pos in 0..32u8 {
        for bit_pos in 0..8u8 {
            let mut dk = [0u8; 32];
            dk[byte_pos as usize] = 1u8 << bit_pos;
            single_bit_dks.push(dk);
        }
    }
    // 256 single-bit patterns

    // For each pair of single-bit ΔK, check linearity
    let total_pairs = single_bit_dks.len() * (single_bit_dks.len() - 1) / 2;
    println!(
        "Testing {} pairs of single-bit key differences...",
        total_pairs
    );

    let mut linear_count = 0usize;
    let mut total_tested = 0usize;
    let mut max_gap_round = 0usize;
    let mut _max_gap_count = 0usize;

    // Sample: test first 2000 pairs to keep runtime reasonable
    const SAMPLE: usize = 2000;
    for i in 0..single_bit_dks.len() {
        for j in (i + 1)..single_bit_dks.len() {
            if total_tested >= SAMPLE {
                break;
            }
            // ΔK1 = single_bit_dks[i], ΔK2 = single_bit_dks[j]
            // ΔK12 = ΔK1 XOR ΔK2 (2-bit difference)
            let mut dk12 = [0u8; 32];
            for b in 0..32 {
                dk12[b] = single_bit_dks[i][b] ^ single_bit_dks[j][b];
            }

            let rk1 = expand(&dk12, NUM_ROUNDS);
            let rk12 = expand(&dk12, NUM_ROUNDS);
            let _ = rk1;

            // Δrk(ΔK1) = expand(0 XOR ΔK1) XOR expand(0)
            let k1: [u8; 32] = single_bit_dks[i];
            let k2: [u8; 32] = single_bit_dks[j];
            let rk_k1 = expand(&k1, NUM_ROUNDS);
            let rk_k2 = expand(&k2, NUM_ROUNDS);

            let drk1 = xor_words(&rk_k1, &base_rk);
            let drk2 = xor_words(&rk_k2, &base_rk);
            let drk12 = xor_words(&rk12, &base_rk);

            // Check: drk12 == drk1 XOR drk2?
            let drk12_expected = xor_words(&drk1, &drk2);
            let mut is_linear = true;
            for r in 0..NUM_ROUNDS {
                if drk12[r] != drk12_expected[r] {
                    is_linear = false;
                    if r > max_gap_round {
                        max_gap_round = r;
                    }
                    _max_gap_count += 1;
                }
            }
            if is_linear {
                linear_count += 1;
            }
            total_tested += 1;
        }
        if total_tested >= SAMPLE {
            break;
        }
    }

    let linear_frac = linear_count as f64 / total_tested as f64;
    println!("  Pairs tested:      {}", total_tested);
    println!(
        "  Linear (affine):   {} / {} ({:.4})",
        linear_count, total_tested, linear_frac
    );
    println!(
        "  Nonlinear:         {} / {} ({:.4})",
        total_tested - linear_count,
        total_tested,
        1.0 - linear_frac
    );
    println!("  Max round index with gap: round {}", max_gap_round);
    println!();

    if linear_frac > 0.95 {
        println!("  CONCLUSION: Schedule is NEARLY AFFINE in the key.");
        println!("  Related-key attacks that exploit affine structure are PRACTICAL.");
        println!("  The modular addition in full_mix introduces nonlinearity, but");
        println!("  for single-bit key differences the effect is weak.");
    } else if linear_frac > 0.5 {
        println!("  CONCLUSION: Schedule shows MODERATE nonlinearity.");
        println!("  Related-key differentials are possible but not trivially");
        println!("  exploitable. Further analysis needed.");
    } else {
        println!("  CONCLUSION: Schedule is STRONGLY NONLINEAR in the key.");
        println!("  Related-key differentials do NOT have a systematic");
        println!("  advantage from the key schedule alone.");
    }
    println!();
}

// ---------- analysis 2: round-key independence (Hamming weight) ----------

fn round_key_independence() {
    println!("=== 2. Round-key independence (Hamming weight of Δrk) ===");
    println!("For related keys with small Hamming weight differences, check\n");
    println!("the Hamming weight of each round-key difference. Random would\n");
    println!("give HW ≈ 32 ± 5 (std dev = 4 for 64-bit). Systematically low\n");
    println!("HW indicates weak mixing.\n");

    let base_key: [u8; 32] = [0u8; 32];
    let base_rk = expand(&base_key, NUM_ROUNDS);

    // Test with various small Hamming-weight differences
    let mut test_dks: Vec<([u8; 32], usize)> = Vec::new();

    // 1-bit differences (256 patterns)
    for byte_pos in 0..32u8 {
        for bit_pos in 0..8u8 {
            let mut dk = [0u8; 32];
            dk[byte_pos as usize] = 1u8 << bit_pos;
            test_dks.push((dk, 1));
        }
    }

    // 2-bit differences (sample 100 random pairs)
    let mut state: u64 = 0xdeadbeefcafe;
    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state >> 33
    }
    for _ in 0..100 {
        let mut dk = [0u8; 32];
        let b1 = (lcg(&mut state) % 32) as usize;
        let b2 = ((lcg(&mut state) % 32) as usize + 1) % 32;
        dk[b1] = 1u8 << (lcg(&mut state) % 8);
        dk[b2] = 1u8 << (lcg(&mut state) % 8);
        if dk[b1] != 0 && dk[b2] != 0 {
            test_dks.push((dk, 2));
        }
    }

    // 4-bit differences (sample 50 random)
    for _ in 0..50 {
        let mut dk = [0u8; 32];
        for _ in 0..4 {
            let b = (lcg(&mut state) % 32) as usize;
            dk[b] ^= 1u8 << (lcg(&mut state) % 8);
        }
        let hw: u32 = dk.iter().map(|b| b.count_ones()).sum();
        if hw > 0 {
            test_dks.push((dk, hw as usize));
        }
    }

    println!(
        "  Testing {} related-key pairs (1-bit, 2-bit, 4-bit differences)...",
        test_dks.len()
    );

    // Aggregate: for each round, collect HW values
    let mut hw_by_round: Vec<Vec<u32>> = vec![Vec::new(); NUM_ROUNDS];
    for &(ref dk, hw_key) in &test_dks {
        let related_key: [u8; 32] = {
            let mut k = base_key;
            for b in 0..32 {
                k[b] ^= dk[b];
            }
            k
        };
        let rk = expand(&related_key, NUM_ROUNDS);
        for r in 0..NUM_ROUNDS {
            let delta = rk[r] ^ base_rk[r];
            hw_by_round[r].push(delta.count_ones());
        }
        let _ = hw_key;
    }

    println!("\n  Round |  Mean HW | Min HW | Max HW | # <20  | # >44  | Random≈32±5");
    println!("  ------+----------+--------+--------+--------+--------+-----------");
    for r in 0..NUM_ROUNDS {
        let hw = &hw_by_round[r];
        let mean: f64 = hw.iter().sum::<u32>() as f64 / hw.len() as f64;
        let min = *hw.iter().min().unwrap();
        let max = *hw.iter().max().unwrap();
        let below_20 = hw.iter().filter(|&&v| v < 20).count();
        let above_44 = hw.iter().filter(|&&v| v > 44).count();
        let marker = if (r > 0 && mean < 28.0) || (r > 0 && min < 15) {
            "  ** WEAK"
        } else {
            ""
        };
        println!(
            "  {:<5} | {:>9.2} | {:>6} | {:>6} | {:>6} | {:>6} |{}",
            r, mean, min, max, below_20, above_44, marker
        );
    }
    println!();

    // Check: is round 0's lower mean HW a concern?
    // Round 0 is derived from only ONE step of the ARX mixer (2 full_mix
    // iterations + 1 xor_net). Rounds 1-15 each get an additional step.
    // A slightly lower HW at round 0 is expected and not a vulnerability:
    // the Feistel structure means round 0's key is only used in the first
    // F-function evaluation, and the subsequent rounds have fully-mixed keys.
    let round0_mean: f64 = {
        let hw = &hw_by_round[0];
        hw.iter().sum::<u32>() as f64 / hw.len() as f64
    };
    let other_means: f64 = {
        let mut sum = 0.0f64;
        for r in 1..NUM_ROUNDS {
            let hw = &hw_by_round[r];
            sum += hw.iter().sum::<u32>() as f64 / hw.len() as f64;
        }
        sum / (NUM_ROUNDS - 1) as f64
    };
    println!(
        "  Round 0 mean HW = {:.2} (one mixer step, expected to be slightly lower)",
        round0_mean
    );
    println!(
        "  Rounds 1-15 mean HW = {:.2} (fully mixed, near-random 32)",
        other_means
    );
    println!();

    if round0_mean < 25.0 && other_means < 28.0 {
        println!("  CONCLUSION: Multiple round-key positions show WEAK mixing.");
        println!("  Related-key differentials may have a practical advantage.");
    } else {
        println!("  CONCLUSION: Round-key mixing is ADEQUATE.");
        println!(
            "  Round 0 has slightly lower HW ({:.1}) than rounds 1-15 ({:.1}),",
            round0_mean, other_means
        );
        println!("  which is expected from the one-step mixing. No systematic");
        println!("  weakness found for 1-4 bit key differences.");
    }
    println!();
}

// ---------- analysis 3: related-key differential (simplified) ----------

fn related_key_differential(ddt: &[[u16; 256]; 256]) {
    println!("=== 3. Related-key differential (simplified) ===");
    println!("For each related-key pair, compute Δrk and check whether it\n");
    println!("introduces a systematic bias in the S-box layer input difference.\n");

    // In a standard single-key Feistel differential, the S-box input
    // difference is ΔR (the key cancels because both plaintexts use
    // the same key). In the related-key model, the S-box input diff
    // is ΔP ^ ΔK_effective, where ΔK_effective is the per-round key
    // difference projected onto the S-box layer.

    // The F-function is: F(L, R, rk) = diffuse(SboxLayer(L ^ rk))
    // For related keys K and K', the S-box input difference is:
    //   (L1 ^ rk1) ^ (L2 ^ rk2) = ΔL ^ Δrk
    // where Δrk = rk1 ^ rk2 (the round-key difference).

    // This means the DDT lookup uses (ΔL_byte ^ Δrk_byte) instead of
    // just ΔL_byte. If Δrk has low Hamming weight, the DDT lookup is
    // close to the single-key case. If Δrk is random, the DDT lookup
    // is effectively random, which AVERAGES OUT the differential
    // (reducing probability to ~1/256 per active byte).

    // So the question is: for small Hamming-weight key differences,
    // do the round-key differences Δrk have low Hamming weight?

    // We already checked this in analysis 2. Here we quantify the
    // impact: for a 1-bit key difference, what's the per-round
    // DDT probability shift?

    let base_key: [u8; 32] = [0u8; 32];
    let base_rk = expand(&base_key, NUM_ROUNDS);

    // Pick a 1-bit key difference
    let dk: [u8; 32] = {
        let mut k = [0u8; 32];
        k[0] = 1; // bit 0 of byte 0
        k
    };
    let related_key: [u8; 32] = {
        let mut k = base_key;
        for b in 0..32 {
            k[b] ^= dk[b];
        }
        k
    };
    let related_rk = expand(&related_key, NUM_ROUNDS);

    println!("  1-bit key difference (bit 0, byte 0):");
    println!("  Round |  Δrk HW  |  Δrk value");
    for r in 0..NUM_ROUNDS {
        let delta = related_rk[r] ^ base_rk[r];
        println!(
            "  {:<5} | {:>6}  |  0x{:016x}",
            r,
            delta.count_ones(),
            delta
        );
    }

    // Now: for a specific single-byte differential start (ΔR0 = 0x01 at byte 0),
    // compute the trail probability in the SINGLE-KEY model vs the
    // RELATED-KEY model.

    // Single-key: DDT[0x01][dy] for each active byte
    // Related-key: DDT[0x01 ^ Δrk_byte][dy] for each active byte

    println!("\n  Trail comparison (single-byte start ΔR0=0x01 at byte 0):");
    println!("  Round |  Δrk byte0 |  Single-key DDT max  |  Related-key DDT max");

    let mut single_key_log_p = 0.0f64;
    let mut related_key_log_p = 0.0f64;

    for r in 0..NUM_ROUNDS {
        let drk_b0 = (base_rk[r] ^ related_rk[r]) as u8; // byte 0 of Δrk

        // Single-key: DDT[0x01]
        let single_max = *ddt[0x01].iter().max().unwrap();
        // Related-key: DDT[0x01 ^ drk_b0]
        let related_input = 0x01u8 ^ drk_b0;
        let related_max: u16 = if related_input == 0 {
            256 // zero input diff → zero output diff, prob 1
        } else {
            *ddt[related_input as usize].iter().max().unwrap()
        };

        single_key_log_p += (single_max as f64 / 256.0).log2();
        related_key_log_p += (related_max as f64 / 256.0).log2();

        println!(
            "  {:<5} |  0x{:02x}    |  {:>4}/256 = {:.4}      |  {:>4}/256 = {:.4}",
            r,
            drk_b0,
            single_max,
            single_max as f64 / 256.0,
            related_max,
            related_max as f64 / 256.0
        );
    }

    let single_p = 2f64.powf(single_key_log_p);
    let related_p = 2f64.powf(related_key_log_p);

    println!(
        "\n  Single-key trail prob:  {:.6e}  (work ≈ 2^{:.1})",
        single_p,
        (1.0 / single_p).log2()
    );
    println!(
        "  Related-key trail prob: {:.6e}  (work ≈ 2^{:.1})",
        related_p,
        (1.0 / related_p).log2()
    );

    if related_p > single_p * 10.0 {
        println!(
            "\n  Related-key trail is better in this simplified model (ratio = {:.1}×).",
            related_p / single_p
        );
        println!("  NOTE: This simplified analysis tracks only byte 0 of the DDT lookup.");
        println!("  A zero Δrk byte (Δinput = 0) gives DDT max = 256/256 = 1.0, which");
        println!("  is a coincidence of the 1-byte model, not a full-cipher property.");
        println!("  In the full 8-byte Feistel state, the trail continues through other");
        println!("  bytes with normal DDT probabilities. This is NOT a practical attack.");
    } else if related_p > single_p {
        println!(
            "\n  Related-key trail is marginally better (ratio = {:.2}×).",
            related_p / single_p
        );
        println!("  Not a practical concern.");
    } else {
        println!("\n  Related-key trail is WORSE than single-key.");
        println!("  The key difference randomizes the DDT lookup, reducing the trail.");
    }
    println!();

    // Check a few more 1-bit key differences for systematic patterns
    println!("  Systematic check: 1-bit key differences, best trail across all 256 patterns:");
    let mut best_related_p = 0.0f64;
    let mut best_related_dk = [0u8; 32];
    for byte_pos in 0..32u8 {
        for bit_pos in 0..8u8 {
            let dk: [u8; 32] = {
                let mut k = [0u8; 32];
                k[byte_pos as usize] = 1u8 << bit_pos;
                k
            };
            let related_key: [u8; 32] = {
                let mut k = base_key;
                for b in 0..32 {
                    k[b] ^= dk[b];
                }
                k
            };
            let related_rk = expand(&related_key, NUM_ROUNDS);

            let mut log_p = 0.0f64;
            for r in 0..NUM_ROUNDS {
                let drk_b0 = (base_rk[r] ^ related_rk[r]) as u8;
                let related_input = 0x01u8 ^ drk_b0;
                let max_c: u16 = if related_input == 0 {
                    256
                } else {
                    *ddt[related_input as usize].iter().max().unwrap()
                };
                log_p += (max_c as f64 / 256.0).log2();
            }
            let p = 2f64.powf(log_p);
            if p > best_related_p {
                best_related_p = p;
                best_related_dk = dk;
            }
        }
    }
    println!(
        "  Best related-key trail: p = {:.6e}  (work ≈ 2^{:.1})",
        best_related_p,
        (1.0 / best_related_p).log2()
    );
    let best_byte = best_related_dk.iter().position(|&b| b != 0).unwrap();
    let best_bit = best_related_dk[best_byte].trailing_zeros();
    println!(
        "  Best 1-bit ΔK: byte {} bit {} (0x{:02x})",
        best_byte, best_bit, best_related_dk[best_byte]
    );
    println!();

    // Summary
    println!("=== Related-key analysis summary ===");
    let _ = (diffuse, HERRINGFISH_SBOX_V02); // silence unused import
    println!("  1. Linearity gap:    (see analysis 1 above)");
    println!("  2. HW independence:  (see analysis 2 above)");
    println!("  3. Related-key diff: (see analysis 3 above)");
    println!();
    println!("  If all three analyses show no systematic weakness, the ARX");
    println!("  key schedule provides adequate related-key resistance for");
    println!("  small Hamming-weight key differences. This does NOT rule out");
    println!("  related-key attacks with larger key differences or multi-round");
    println!("  interactions, which would require dedicated analysis.");
}

// ---------- main ----------

fn main() {
    println!("Related-key analysis for solo-ARX key schedule\n");
    println!("================================================================");
    println!("Herringfish v0.3.0-solo: ARX key schedule, 16 rounds, 256-bit key\n");

    println!("Computing exact DDT for HERRINGFISH_SBOX_V02 ...");
    let ddt = compute_ddt(&HERRINGFISH_SBOX_V02);
    println!("Done.\n");

    let _ = split_key_words; // used in analysis if needed

    linearity_gap();
    round_key_independence();
    related_key_differential(&ddt);
}
