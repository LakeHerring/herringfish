//! Cipher core types and API

pub mod key_schedule;
pub mod round;
pub mod shake_key_schedule;
pub mod feistel_arx;

use crate::cipher::key_schedule::KeySchedule;
use crate::cipher::round::{encrypt_round, decrypt_round};

pub const BLOCK_SIZE: usize = 16; // 128 bits
pub const KEY_SIZE: usize = 32;   // 256 bits
pub const NUM_ROUNDS: usize = 14;

/// Key type for Herringfish prototype
pub type Key = [u8; KEY_SIZE];

/// Cipher state
pub struct Cipher {
    round_keys: Vec<[u8; BLOCK_SIZE]>,
}

impl Cipher {
    /// Create a new cipher instance from a 256-bit key
    pub fn new(key: &Key) -> Self {
        let ks = KeySchedule::derive(key);
        Self { round_keys: ks }
    }

    /// Encrypt a 128-bit block in place
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // Initial AddRoundKey
        for i in 0..BLOCK_SIZE {
            block[i] ^= self.round_keys[0][i];
        }
        for r in 1..NUM_ROUNDS {
            encrypt_round(block, &self.round_keys[r]);
        }
        // Final AddRoundKey
        for i in 0..BLOCK_SIZE {
            block[i] ^= self.round_keys[NUM_ROUNDS][i];
        }
    }

    /// Decrypt a 128-bit block in place
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        // Initial AddRoundKey
        for i in 0..BLOCK_SIZE {
            block[i] ^= self.round_keys[NUM_ROUNDS][i];
        }
        for r in (1..NUM_ROUNDS).rev() {
            decrypt_round(block, &self.round_keys[r]);
        }
        // Final AddRoundKey
        for i in 0..BLOCK_SIZE {
            block[i] ^= self.round_keys[0][i];
        }
    }
}
