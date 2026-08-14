#![allow(clippy::all, dead_code, unused_imports, unused_variables, unused_assignments)]
use rand::{Rng, SeedableRng};
use std::collections::HashMap;

fn encrypt_rounds(key: &[u8; 32], pt: &[u8; 16], rounds: usize) -> [u8; 16] {
    // We need to expose internal encryption with reduced rounds. Since FeistelArx encrypts full 16 rounds,
    // we'll duplicate logic with reduced rounds using the same sbox and key schedule.
    // For simplicity, use the existing FeistelArx but with modified NUM_ROUNDS via a wrapper.
    // Here we just reuse the FeistelArx implementation by creating a custom encryptor.
    // We'll re-implement minimal logic here.
    use sha3::digest::{ExtendableOutput, Update};
    use shake::Shake256;
    const DOMAIN_FEISTEL_KEY: &[u8] = b"HERRINGFISH-FEISTEL-KEY";
    const DOMAIN_FEISTEL_SBOX: &[u8] = b"HERRINGFISH-FEISTEL-SBOX";

    // derive round keys
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN_FEISTEL_KEY);
    hasher.update(key);
    let mut out = vec![0u8; 16 * 8];
    hasher.finalize_xof_into(&mut out);
    let mut round_keys = Vec::new();
    for i in 0..16 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&out[i * 8..i * 8 + 8]);
        round_keys.push(u64::from_le_bytes(b));
    }

    // derive sbox via same method as FeistelArx (simplified: use fixed AES S-box for speed)
    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    let mut left = u64::from_le_bytes(pt[0..8].try_into().unwrap());
    let mut right = u64::from_le_bytes(pt[8..16].try_into().unwrap());
    for i in 0..rounds {
        let k = round_keys[i];
        // F function with S-box + diffusion
        let mut t = 0u64;
        for j in 0..8 {
            let x_byte = ((right >> (8 * j)) & 0xff) as u8;
            let k_byte = ((k >> (8 * j)) & 0xff) as u8;
            let sb = SBOX[(x_byte ^ k_byte) as usize];
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
