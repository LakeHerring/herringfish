//! Key schedule for prototype SPN
//!
//! 256-bit master key -> 15 round keys of 128 bits each.
//! SHAKE256-based expansion with domain separation.

use crate::cipher::{BLOCK_SIZE, KEY_SIZE, NUM_ROUNDS};
use sha3::digest::{ExtendableOutput, Update};
use shake::Shake256;

pub struct KeySchedule;

const DOMAIN_SPN_KEY: &[u8] = b"HERRINGFISH-SPN-KEY";

impl KeySchedule {
    /// Derive round keys from master key using SHAKE256
    pub fn derive(key: &[u8; KEY_SIZE]) -> Vec<[u8; BLOCK_SIZE]> {
        let mut hasher = Shake256::default();
        hasher.update(DOMAIN_SPN_KEY);
        hasher.update(key);
        let needed = (NUM_ROUNDS + 1) * BLOCK_SIZE;
        let mut out = vec![0u8; needed];
        hasher.finalize_xof_into(&mut out);
        let mut round_keys = Vec::with_capacity(NUM_ROUNDS + 1);
        for i in 0..=NUM_ROUNDS {
            let mut rk = [0u8; BLOCK_SIZE];
            let start = i * BLOCK_SIZE;
            rk.copy_from_slice(&out[start..start + BLOCK_SIZE]);
            round_keys.push(rk);
        }
        round_keys
    }
}
