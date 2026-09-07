//! Integration tests for the self-contained ARX key schedule (solo branch).
//!
//! Replaces tests/shake_schedule.rs. No SHAKE/SHA-3 is involved.

use herringfish::cipher::{arx_key_schedule, feistel_arx, BLOCK_SIZE, KEY_SIZE};

/// Round count of the solo-branch Feistel ARX cipher (16), as opposed
/// to the SPN cipher's `cipher::NUM_ROUNDS` (14).
const FEISTEL_ROUNDS: usize = feistel_arx::NUM_ROUNDS;

#[test]
fn arx_key_schedule_deterministic() {
    let key = [0x5Au8; KEY_SIZE];
    let rk1 = arx_key_schedule::derive_round_keys(&key, FEISTEL_ROUNDS);
    let rk2 = arx_key_schedule::derive_round_keys(&key, FEISTEL_ROUNDS);
    assert_eq!(rk1, rk2);
    assert_eq!(rk1.len(), FEISTEL_ROUNDS);
}

#[test]
fn arx_key_schedule_differs() {
    let key1 = [0u8; KEY_SIZE];
    let mut key2 = [0u8; KEY_SIZE];
    key2[31] = 1;
    let rk1 = arx_key_schedule::derive_round_keys(&key1, FEISTEL_ROUNDS);
    let rk2 = arx_key_schedule::derive_round_keys(&key2, FEISTEL_ROUNDS);
    assert_ne!(rk1, rk2);
}

#[test]
fn arx_key_schedule_prefix_property() {
    let key = [0xC3u8; KEY_SIZE];
    let short = arx_key_schedule::derive_round_keys(&key, 8);
    let long = arx_key_schedule::derive_round_keys(&key, 32);
    assert_eq!(&short[..], &long[..8]);
}

#[test]
fn arx_key_schedule_no_zero_stream() {
    // The zero master key must not produce an all-zero round-key stream.
    let key = [0u8; KEY_SIZE];
    let rk = arx_key_schedule::derive_round_keys(&key, FEISTEL_ROUNDS);
    assert!(rk.iter().any(|&k| k != 0));
}

#[test]
fn block_and_key_sizes_unchanged() {
    assert_eq!(BLOCK_SIZE, 16);
    assert_eq!(KEY_SIZE, 32);
    assert_eq!(FEISTEL_ROUNDS, 16);
}
