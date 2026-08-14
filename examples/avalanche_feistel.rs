use herringfish::cipher::feistel_arx::{NUM_ROUNDS, FeistelArx};
use std::convert::TryInto;
use rand::{Rng, rand_core};

fn f_function(x: u64, k: u64) -> u64 {
    let mut t = x ^ k;
    t = t.wrapping_add(k.rotate_left(13));
    t = t.rotate_left(7);
    t ^= k.rotate_left(3);
    t = t.wrapping_add(x);
    t.rotate_left(11)
}

fn encrypt_trace(key: &[u8; 32], pt: &[u8; 16], round_keys: &[u64]) -> Vec<[u8; 16]> {
    let mut left = u64::from_le_bytes(pt[0..8].try_into().unwrap());
    let mut right = u64::from_le_bytes(pt[8..16].try_into().unwrap());
    let mut states = Vec::with_capacity(NUM_ROUNDS + 1);
    let mut block = [0u8; 16];
    block[0..8].copy_from_slice(&left.to_le_bytes());
    block[8..16].copy_from_slice(&right.to_le_bytes());
    states.push(block);
    for &k in round_keys {
        let f_out = f_function(right, k);
        let new_right = left ^ f_out;
        left = right;
        right = new_right;
        block[0..8].copy_from_slice(&left.to_le_bytes());
        block[8..16].copy_from_slice(&right.to_le_bytes());
        states.push(block);
    }
    states
}

fn derive_round_keys(key: &[u8; 32]) -> Vec<u64> {
    let mut keys = Vec::new();
    // replicate derivation from FeistelArx
    use shake::Shake256;
    use sha3::digest::{Update, ExtendableOutput};
    const DOMAIN_FEISTEL_KEY: &[u8] = b"HERRINGFISH-FEISTEL-KEY";
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN_FEISTEL_KEY);
    hasher.update(key);
    let mut out = vec![0u8; NUM_ROUNDS * 8];
    hasher.finalize_xof_into(&mut out);
    for i in 0..NUM_ROUNDS {
        let mut bytes = [0u8;8];
        bytes.copy_from_slice(&out[i*8..i*8+8]);
        keys.push(u64::from_le_bytes(bytes));
    }
    keys
}

fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).map(|(x,y)| (x ^ y).count_ones() as usize).sum()
}

fn main() {
    let key = [0u8; 32];
    let round_keys = derive_round_keys(&key);
    let base_pt = [0u8; 16];
    
    // average avalanche per round over 128 bit flips
    let mut sums = vec![0usize; NUM_ROUNDS + 1];
    for bit in 0..128 {
        let mut pt = base_pt;
        let byte_idx = bit / 8;
        let bit_idx = bit % 8;
        pt[byte_idx] ^= 1 << bit_idx;
        let trace = encrypt_trace(&key, &pt, &round_keys);
        for r in 0..=NUM_ROUNDS {
            sums[r] += hamming_distance(&base_pt, &trace[r]);
        }
    }
    println!("Feistel ARX avalanche average Hamming distance per round");
    for r in 0..=NUM_ROUNDS {
        let avg = sums[r] as f64 / 128.0;
        println!("Round {:2}: avg {} bits, ratio {:.3}", r, avg, avg / 128.0);
    }
    
    // differential characteristic search for 4,8,12 rounds - simple brute force for 1 active input bit
    for rounds in [4,8,12] {
        // brute force all input differences with Hamming weight 1
        let mut best_prob = 0.0;
        let mut best_diff = 0;
        // For demonstration, sample a subset due to combinatorial explosion
        // We'll enumerate all 128 single-bit differences and count output collisions for a fixed key
        // Actually differential probability estimation needs many pairs. We'll do a simple heuristic:
        // find most frequent output difference
        use std::collections::HashMap;
        let mut freq: HashMap<[u8;16], usize> = HashMap::new();
        let base_trace = encrypt_trace(&key, &base_pt, &round_keys[..rounds]);
        let base_out = base_trace[rounds];
        // sample 1024 random plaintexts
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xdeadbeef);
        for _ in 0..1024 {
            let mut pt = [0u8;16];
            rng.fill_bytes(&mut pt);
            let trace = encrypt_trace(&key, &pt, &round_keys[..rounds]);
            let out = trace[rounds];
            let diff = {
                let mut d = [0u8;16];
                for i in 0..16 { d[i] = out[i] ^ base_out[i]; }
                d
            };
            *freq.entry(diff).or_insert(0) += 1;
        }
        let total = 1024;
        let max_count = freq.values().cloned().max().unwrap_or(0);
        let prob = max_count as f64 / total as f64;
        println!("Rounds {}: sampled differential max freq {}/{} = {:.4}", rounds, max_count, total, prob);
    }
}
