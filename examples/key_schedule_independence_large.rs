#![allow(
    clippy::all,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments
)]
use herringfish::cipher::feistel_arx::FeistelArx;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn derive_round_keys(key: &[u8; 32]) -> Vec<u64> {
    let _cipher = FeistelArx::new(key);
    // Access private round keys via reflection? Can't.
    // We'll re-derive using same method as FeistelArx
    use sha3::digest::{ExtendableOutput, Update};
    use shake::Shake256;
    const DOMAIN: &[u8] = b"HERRINGFISH-FEISTEL-KEY";
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN);
    hasher.update(key);
    let mut out = vec![0u8; 16 * 8];
    hasher.finalize_xof_into(&mut out);
    (0..16)
        .map(|i| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&out[i * 8..i * 8 + 8]);
            u64::from_le_bytes(b)
        })
        .collect()
}

fn hamming_distance(a: &[u64], b: &[u64]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

fn main() {
    const SAMPLES: usize = 100_000;
    let mut rng = StdRng::seed_from_u64(0xdeadbeef);

    // Pairwise independence
    let mut pairwise_dist = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        rng.fill_bytes(&mut k1);
        rng.fill_bytes(&mut k2);
        let rk1 = derive_round_keys(&k1);
        let rk2 = derive_round_keys(&k2);
        pairwise_dist.push(hamming_distance(&rk1, &rk2));
    }
    let mean_pair: f64 = pairwise_dist.iter().sum::<usize>() as f64 / SAMPLES as f64;
    let var_pair = pairwise_dist
        .iter()
        .map(|d| (*d as f64 - mean_pair).powi(2))
        .sum::<f64>()
        / SAMPLES as f64;

    // Related-key
    let mut related_dist = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let mut k1 = [0u8; 32];
        rng.fill_bytes(&mut k1);
        let mut k2 = k1;
        // flip 1 bit
        let byte_idx = rng.next_u32() as usize % 32;
        let bit_idx = rng.next_u32() as usize % 8;
        k2[byte_idx] ^= 1u8 << bit_idx;
        let rk1 = derive_round_keys(&k1);
        let rk2 = derive_round_keys(&k2);
        related_dist.push(hamming_distance(&rk1, &rk2));
    }
    let mean_rel: f64 = related_dist.iter().sum::<usize>() as f64 / SAMPLES as f64;
    let var_rel = related_dist
        .iter()
        .map(|d| (*d as f64 - mean_rel).powi(2))
        .sum::<f64>()
        / SAMPLES as f64;

    println!("Key-schedule independence test");
    println!("Samples: {}", SAMPLES);
    println!("Pairwise round-key Hamming distance:");
    println!(
        "  mean = {:.2} bits, std = {:.2}",
        mean_pair,
        var_pair.sqrt()
    );
    println!("Related-key 1-bit diff:");
    println!("  mean = {:.2} bits, std = {:.2}", mean_rel, var_rel.sqrt());
    println!("Expected ~64 bits for independent 64-bit keys per round, total 1024 bits");
}
