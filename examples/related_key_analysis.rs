use herringfish::cipher::NUM_ROUNDS;
use herringfish::cipher::key_schedule::KeySchedule;
use rand::{Rng, SeedableRng};

fn hamming_distance_bytes(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

fn key_hamming(a: &[u8; 32], b: &[u8; 32]) -> usize {
    hamming_distance_bytes(a, b)
}

fn round_key_correlation(key0: &[u8; 32], key1: &[u8; 32]) -> Vec<f64> {
    let rk0 = KeySchedule::derive(key0);
    let rk1 = KeySchedule::derive(key1);
    let mut corrs = Vec::new();
    for i in 0..=NUM_ROUNDS {
        let d = hamming_distance_bytes(&rk0[i], &rk1[i]) as f64 / 128.0;
        corrs.push(d);
    }
    corrs
}

fn main() {
    // Hamming weight 1,2,4 analysis
    let base_key = [0u8; 32];
    for w in [1, 2, 4] {
        let mut total = 0.0;
        let mut trials = 0;
        // sample many key pairs with given Hamming weight difference
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xdeadbeef);
        for _ in 0..1000 {
            let mut key1 = [0u8; 32];
            // create key difference with weight w
            let mut diff = [0u8; 32];
            rng.fill_bytes(&mut diff);
            // force exactly w bits
            let mut bits_set = 0;
            for i in 0..32 {
                if bits_set >= w {
                    break;
                }
                // set random bits
                let byte_idx = rng.next_u32() as usize % 32;
                let bit = rng.next_u32() as usize % 8;
                if (diff[byte_idx] >> bit) & 1 == 0 {
                    diff[byte_idx] |= 1 << bit;
                    bits_set += 1;
                }
            }
            for i in 0..32 {
                key1[i] = base_key[i] ^ diff[i];
            }
            let corrs = round_key_correlation(&base_key, &key1);
            let avg = corrs.iter().sum::<f64>() / corrs.len() as f64;
            total += avg;
            trials += 1;
        }
        println!(
            "Hamming weight {} key diff -> avg round key Hamming distance {:.2}/128 bits",
            w,
            total / trials as f64
        );
    }

    // Distribution across many random key pairs
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xcafebabe);
    let mut sum = 0.0;
    for _ in 0..1000 {
        let mut k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        rng.fill_bytes(&mut k0);
        rng.fill_bytes(&mut k1);
        let corrs = round_key_correlation(&k0, &k1);
        let avg = corrs.iter().sum::<f64>() / corrs.len() as f64;
        sum += avg;
    }
    println!(
        "Random key pairs avg round key Hamming distance {:.2}/128 bits",
        sum / 1000.0
    );
}
