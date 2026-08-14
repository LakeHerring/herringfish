#![allow(clippy::all, dead_code, unused_imports, unused_variables, unused_assignments)]
use herringfish::cipher::key_schedule::KeySchedule;
use herringfish::cipher::NUM_ROUNDS;

fn hamming_distance_bytes(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

fn main() {
    let key0 = [0u8; 32];
    let mut key1 = [0u8; 32];
    key1[0] ^= 1;

    let rk0 = KeySchedule::derive(&key0);
    let rk1 = KeySchedule::derive(&key1);

    println!("Related-key Hamming distance of round keys");
    let mut total = 0usize;
    for i in 0..=NUM_ROUNDS {
        let d = hamming_distance_bytes(&rk0[i], &rk1[i]);
        total += d;
        println!("Round {}: {} bits differ / 128", i, d);
    }
    let avg = total as f64 / ((NUM_ROUNDS + 1) as f64);
    println!("Average Hamming distance per round key: {:.2} bits", avg);

    // Test for multiple key differences
    use rand::Rng;
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xdeadbeef);
    let mut sum_dist = 0.0;
    for _ in 0..100 {
        let mut k0 = [0u8; 32];
        let mut k1 = [0u8; 32];
        rng.fill_bytes(&mut k0);
        rng.fill_bytes(&mut k1);
        let rk0 = KeySchedule::derive(&k0);
        let rk1 = KeySchedule::derive(&k1);
        let mut d = 0;
        for i in 0..=NUM_ROUNDS {
            d += hamming_distance_bytes(&rk0[i], &rk1[i]);
        }
        sum_dist += d as f64 / ((NUM_ROUNDS + 1) as f64 * 128.0);
    }
    println!(
        "Average normalized Hamming distance for random keys: {:.3}",
        sum_dist / 100.0
    );
}
