use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

const ROUNDS: usize = 4;

fn f_function(x: u64, k: u64) -> u64 {
    let sbox = &HERRINGFISH_SBOX_V02;
    let mut out = 0u64;
    for i in 0..8 {
        let x_byte = ((x >> (8 * i)) & 0xff) as u8;
        let k_byte = ((k >> (8 * i)) & 0xff) as u8;
        let sb = sbox[(x_byte ^ k_byte) as usize];
        out |= (sb as u64) << (8 * i);
    }
    let mut bytes = [0u8; 8];
    for i in 0..8 {
        bytes[i] = ((out >> (8 * i)) & 0xff) as u8;
    }
    let mut out_bytes = [0u8; 8];
    for i in 0..8 {
        out_bytes[i] = bytes[i] ^ bytes[(i + 1) % 8] ^ bytes[(i + 3) % 8];
    }
    let mut out2 = 0u64;
    for i in 0..8 {
        out2 |= (out_bytes[i] as u64) << (8 * i);
    }
    out2
}

fn feistel_encrypt(pt: u128, keys: &[u64], rounds: usize) -> u128 {
    let mut left = (pt >> 64) as u64;
    let mut right = pt as u64;
    for i in 0..rounds {
        let f_out = f_function(right, keys[i]);
        let new_right = left ^ f_out;
        left = right;
        right = new_right;
    }
    ((left as u128) << 64) | (right as u128)
}

fn main() {
    // Use zero key for trail search – round keys are derived from master key, but for trail analysis we can assume fixed keys
    let keys = vec![0u64; ROUNDS];
    // Search for best differential characteristic for 1-bit input difference
    let mut best_prob = 0.0f64;
    let mut best_in = 0u128;
    let mut best_out = 0u128;
    // Brute force over small input differences
    for diff in 1u128..=(1u128 << 8) {
        let mut counts = std::collections::HashMap::new();
        // sample subset of plaintexts
        for pt in 0u128..1024 {
            let pt2 = pt ^ diff;
            let c1 = feistel_encrypt(pt, &keys, ROUNDS);
            let c2 = feistel_encrypt(pt2, &keys, ROUNDS);
            let dout = c1 ^ c2;
            *counts.entry(dout).or_insert(0usize) += 1;
        }
        if let Some(&cnt) = counts.values().max() {
            let prob = cnt as f64 / 1024.0;
            if prob > best_prob {
                best_prob = prob;
                best_in = diff;
                best_out = *counts.iter().max_by_key(|(_, c)| *c).unwrap().0;
            }
        }
    }
    println!("Best differential for {} rounds", ROUNDS);
    println!(
        "Δin = {:#018x}, Δout = {:#018x}, p̂ = {:.6}",
        best_in, best_out, best_prob
    );
    println!(
        "Note: heuristic search over 1024 plaintexts with zero keys. For rigorous analysis, use exact DDT and key-independent trails."
    );
}
