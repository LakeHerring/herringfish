#![allow(
    clippy::all,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments
)]
use herringfish::cipher::Cipher;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;

fn spn_diff_max_rounds(_rounds: usize, samples: usize) -> f64 {
    // Simplified: use Cipher with NUM_ROUNDS = 14, we test reduced rounds by calling encrypt_block multiple times? For now approximate with full rounds.
    // Placeholder: return sampling floor
    let key = [0u8; 32];
    let cipher = Cipher::new(&key);
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x12345678);
    let mut best = 0.0;
    for bit in 0..8 {
        let mut freq: HashMap<[u8; 16], usize> = HashMap::new();
        for _ in 0..samples {
            let mut p = [0u8; 16];
            rng.fill_bytes(&mut p);
            let mut p2 = p;
            p2[0] ^= 1 << bit;
            let mut c1 = p;
            let mut c2 = p2;
            cipher.encrypt_block(&mut c1);
            cipher.encrypt_block(&mut c2);
            let mut d = [0u8; 16];
            for i in 0..16 {
                d[i] = c1[i] ^ c2[i];
            }
            *freq.entry(d).or_insert(0) += 1;
        }
        let max_count = freq.values().cloned().max().unwrap_or(0);
        let p = max_count as f64 / samples as f64;
        if p > best {
            best = p;
        }
    }
    best
}

fn main() {
    let samples = 100000;
    println!(
        "SPN vs Feistel comparative differential sampling, samples={}",
        samples
    );
    println!(
        "SPN placeholder max prob ≈ {:.6}",
        spn_diff_max_rounds(14, samples)
    );
    println!("Feistel results already in docs/specification/feistel_arx_v0.2.md");
}
