#![allow(clippy::all, dead_code, unused_imports, unused_variables, unused_assignments)]
use rand::{Rng, SeedableRng};
use sha3::digest::{ExtendableOutput, Update};
use shake::Shake256;

const ROUNDS: usize = 16;
const DOMAIN_KEY: &[u8] = b"HERRINGFISH-FEISTEL-KEY";

fn derive_round_keys(key: &[u8; 32]) -> Vec<u64> {
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN_KEY);
    hasher.update(key);
    let mut out = vec![0u8; ROUNDS * 8];
    hasher.finalize_xof_into(&mut out);
    (0..ROUNDS)
        .map(|i| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&out[i * 8..i * 8 + 8]);
            u64::from_le_bytes(b)
        })
        .collect()
}

fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

fn mean_hamming(keys: &[Vec<u64>]) -> f64 {
    let n = keys.len();
    let mut sum = 0u32;
    for i in 0..n {
        for j in i + 1..n {
            for r in 0..ROUNDS {
                sum += hamming_distance(keys[i][r], keys[j][r]);
            }
        }
    }
    sum as f64 / ((n * (n - 1) / 2) as f64 * ROUNDS as f64)
}

fn main() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xdeadbeef);
    let sample_count = 1000;
    let mut keys = Vec::new();
    for _ in 0..sample_count {
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        keys.push(derive_round_keys(&k));
    }
    let avg_dist = mean_hamming(&keys);
    println!(
        "Average pairwise round-key Hamming distance: {:.2} bits",
        avg_dist
    );

    // Related-key test for 1-bit key difference
    let mut diffs = Vec::new();
    for _ in 0..500 {
        let mut k1 = [0u8; 32];
        rng.fill_bytes(&mut k1);
        let mut k2 = k1;
        let byte = rng.next_u32() as usize % 32;
        let bit = rng.next_u32() as u8 % 8;
        k2[byte] ^= 1 << bit;
        let rk1 = derive_round_keys(&k1);
        let rk2 = derive_round_keys(&k2);
        let mut d = 0u32;
        for r in 0..ROUNDS {
            d += hamming_distance(rk1[r], rk2[r]);
        }
        diffs.push(d as f64 / ROUNDS as f64);
    }
    let mean = diffs.iter().sum::<f64>() / diffs.len() as f64;
    let var = diffs.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / diffs.len() as f64;
    println!(
        "Related-key 1-bit diff: mean round-key Hamming = {:.2} bits, std = {:.2}",
        mean,
        var.sqrt()
    );
    println!("Expected ~64 bits for independent 64-bit keys");
}
