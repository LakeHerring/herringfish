#![allow(
    clippy::all,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments
)]

use herringfish::cipher::feistel_arx::FeistelArx;
use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};

fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

fn main() {
    let key = [0u8; 32];
    let cipher = FeistelArx::new(&key);

    let samples = 100_000;
    let mut rng = StdRng::seed_from_u64(0xdeadbeef);

    // Avalanche test
    let mut avalanche_sum = 0usize;
    let mut bit_counts = [0usize; 128];

    for _ in 0..samples {
        let mut pt = [0u8; 16];
        rng.fill_bytes(&mut pt);
        let mut pt2 = pt;
        // flip one random bit
        let byte_idx = rng.random_range(0..16);
        let bit_idx = rng.random_range(0..8);
        pt2[byte_idx] ^= 1 << bit_idx;

        let mut ct1 = pt;
        let mut ct2 = pt2;
        cipher.encrypt_block(&mut ct1);
        cipher.encrypt_block(&mut ct2);

        let hd = hamming_distance(&ct1, &ct2);
        avalanche_sum += hd;

        // accumulate bit differences
        for i in 0..16 {
            let diff = ct1[i] ^ ct2[i];
            for b in 0..8 {
                if (diff >> b) & 1 == 1 {
                    bit_counts[i * 8 + b] += 1;
                }
            }
        }
    }

    let avg_hd = avalanche_sum as f64 / samples as f64;
    println!("Full-cipher avalanche analysis");
    println!("Samples: {}", samples);
    println!("Average Hamming distance: {:.2} bits (ideal 64)", avg_hd);

    let mut bit_avg = 0.0;
    for c in bit_counts.iter() {
        bit_avg += *c as f64 / samples as f64;
    }
    bit_avg /= 128.0;
    println!("Average bit flip probability: {:.4} (ideal 0.5)", bit_avg);

    // Strict avalanche criterion check
    let mut sac_deviation = 0.0;
    for i in 0..128 {
        let p = bit_counts[i] as f64 / samples as f64;
        sac_deviation += (p - 0.5).abs();
    }
    sac_deviation /= 128.0;
    println!("SAC mean absolute deviation: {:.4}", sac_deviation);

    println!("Full-cipher statistical analysis complete");
}
