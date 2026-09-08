//! Key schedule for Herringfish Feistel ARX v0.2 (solo-arx branch).
//!
//! 256-bit master key -> 15 round keys of 128 bits each, expanded via
//! the self-contained ARX key schedule. No SHAKE/SHA-3 is used.

use crate::cipher::{arx_key_schedule, BLOCK_SIZE, KEY_SIZE, NUM_ROUNDS};

pub struct KeySchedule;

impl KeySchedule {
    /// Derive round keys from the master key using the ARX schedule.
    ///
    /// Each 128-bit round key consumes two consecutive 64-bit words
    /// from the ARX expansion (little-endian halves).
    pub fn derive(key: &[u8; KEY_SIZE]) -> Vec<[u8; BLOCK_SIZE]> {
        let words = arx_key_schedule::expand(key, 2 * (NUM_ROUNDS + 1));

        let mut round_keys = Vec::with_capacity(NUM_ROUNDS + 1);
        for i in 0..=NUM_ROUNDS {
            let mut rk = [0u8; BLOCK_SIZE];
            let lo = u64::to_le_bytes(words[2 * i]);
            let hi = u64::to_le_bytes(words[2 * i + 1]);
            rk[..8].copy_from_slice(&lo);
            rk[8..].copy_from_slice(&hi);
            round_keys.push(rk);
        }
        round_keys
    }
}
