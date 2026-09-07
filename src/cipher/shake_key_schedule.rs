//! SHAKE-based key expansion with domain separation

use crate::cipher::{BLOCK_SIZE, KEY_SIZE, NUM_ROUNDS};
use sha3::digest::{ExtendableOutput, Update};
use shake::Shake256;

const DOMAIN_KEY: &[u8] = b"HERRINGFISH-KEY";
const DOMAIN_CONST: &[u8] = b"HERRINGFISH-CONST";

pub fn derive_round_keys_shake(key: &[u8; KEY_SIZE]) -> Vec<[u8; BLOCK_SIZE]> {
    let mut round_keys = Vec::with_capacity(NUM_ROUNDS + 1);

    // Derive round keys
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN_KEY);
    hasher.update(key);
    let mut out = Vec::new();
    hasher.finalize_xof_into(&mut out);

    // We need (NUM_ROUNDS+1)*BLOCK_SIZE bytes
    let needed = (NUM_ROUNDS + 1) * BLOCK_SIZE;
    while out.len() < needed {
        // Extend output by re-seeding with counter
        // Simple approach: use countered XOF
        let counter = (out.len() / 128) as u64;
        let mut h = Shake256::default();
        h.update(DOMAIN_KEY);
        h.update(key);
        h.update(&counter.to_le_bytes());
        let mut tmp = vec![0u8; 128];
        h.finalize_xof_into(&mut tmp);
        out.extend(tmp);
    }

    for i in 0..=NUM_ROUNDS {
        let start = i * BLOCK_SIZE;
        let mut rk = [0u8; BLOCK_SIZE];
        rk.copy_from_slice(&out[start..start + BLOCK_SIZE]);
        round_keys.push(rk);
    }

    round_keys
}

pub fn derive_round_constants_shake(num: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN_CONST);
    hasher.update(&num.to_le_bytes());
    let mut out = vec![0u8; num];
    hasher.finalize_xof_into(&mut out);
    out
}
