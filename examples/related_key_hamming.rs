use herringfish::cipher::key_schedule::KeySchedule;
use rand::{Rng, RngExt, SeedableRng};

fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

fn main() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xdeadbeef);
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

    let ks0 = KeySchedule::derive(&key);
    let n_rounds = ks0.len();
    let mut sums = vec![0usize; n_rounds];
    let mut counts = vec![0usize; n_rounds];

    for _ in 0..1000 {
        let mut key2 = key;
        // flip 1 bit
        let bit = rng.random_range(0..256);
        key2[bit / 8] ^= 1 << (bit % 8);
        let ks1 = KeySchedule::derive(&key2);
        for r in 0..n_rounds {
            let d = hamming_distance(&ks0[r], &ks1[r]);
            sums[r] += d;
            counts[r] += 1;
        }
    }

    println!("Average Hamming distance per round for 1-bit key difference:");
    for r in 0..n_rounds {
        let avg = sums[r] as f64 / counts[r] as f64;
        println!("Round {}: {:.2} bits", r, avg);
    }
}
