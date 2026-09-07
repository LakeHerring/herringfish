#![allow(
    clippy::all,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments
)]
use rand::{Rng, SeedableRng};
use std::collections::HashMap;

fn encrypt_rounds(key: &[u8; 32], pt: &[u8; 16], rounds: usize) -> [u8; 16] {
    // We need to expose internal encryption with reduced rounds. Since FeistelArx encrypts full 16 rounds,
    // we'll duplicate logic with reduced rounds using the same sbox and key schedule.
    // For simplicity, use the existing FeistelArx but with modified NUM_ROUNDS via a wrapper.
    // Use the canonical ARX key schedule and the frozen HERRINGFISH S-box
    // so this example matches the library cipher exactly.
    let round_keys =
        herringfish::cipher::arx_key_schedule::derive_round_keys(key, 16);
    let sbox = herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

    let mut left = u64::from_le_bytes(pt[0..8].try_into().unwrap());
    let mut right = u64::from_le_bytes(pt[8..16].try_into().unwrap());
    for i in 0..rounds {
        let k = round_keys[i];
        // F function with S-box + diffusion
        let mut t = 0u64;
        for j in 0..8 {
            let x_byte = ((right >> (8 * j)) & 0xff) as u8;
            let k_byte = ((k >> (8 * j)) & 0xff) as u8;
            let sb = sbox[(x_byte ^ k_byte) as usize];
            t |= (sb as u64) << (8 * j);
        }
        let mut bytes = [0u8; 8];
        for j in 0..8 {
            bytes[j] = ((t >> (8 * j)) & 0xff) as u8;
        }
        let mut out_bytes = [0u8; 8];
        for j in 0..8 {
            out_bytes[j] = bytes[j] ^ bytes[(j + 1) % 8] ^ bytes[(j + 3) % 8];
        }
        let mut f_out = 0u64;
        for j in 0..8 {
            f_out |= (out_bytes[j] as u64) << (8 * j);
        }
        let new_right = left ^ f_out;
        left = right;
        right = new_right;
    }
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&left.to_le_bytes());
    out[8..16].copy_from_slice(&right.to_le_bytes());
    out
}

fn estimate_max_prob(rounds: usize, samples: usize) -> (f64, f64) {
    let key = [0u8; 32];
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x12345678);
    let mut best = 0.0;
    for bit in 0..8 {
        let mut freq: HashMap<[u8; 16], usize> = HashMap::new();
        for _ in 0..samples {
            let mut p = [0u8; 16];
            rng.fill_bytes(&mut p);
            let mut p2 = p;
            p2[0] ^= 1 << bit;
            let o1 = encrypt_rounds(&key, &p, rounds);
            let o2 = encrypt_rounds(&key, &p2, rounds);
            let mut diff = [0u8; 16];
            for i in 0..16 {
                diff[i] = o1[i] ^ o2[i];
            }
            *freq.entry(diff).or_insert(0) += 1;
        }
        let max_count = freq.values().cloned().max().unwrap_or(0);
        let p = max_count as f64 / samples as f64;
        if p > best {
            best = p;
        }
    }
    let se = (best * (1.0 - best) / samples as f64).sqrt();
    let ci_low = (best - 1.96 * se).max(0.0);
    let ci_high = (best + 1.96 * se).min(1.0);
    (best, (ci_low + ci_high) / 2.0)
}

fn main() {
    let samples = 100000;
    println!(
        "Reduced-round differential max prob, samples per bit = {}",
        samples
    );
    for rounds in [4, 6, 8, 12] {
        let (p, _) = estimate_max_prob(rounds, samples);
        let se = (p * (1.0 - p) / samples as f64).sqrt();
        let ci_low = (p - 1.96 * se).max(0.0);
        let ci_high = (p + 1.96 * se).min(1.0);
        println!(
            "Rounds {}: max prob ≈ {:.6} 95% CI [{:.6}, {:.6}]",
            rounds, p, ci_low, ci_high
        );
    }
}
