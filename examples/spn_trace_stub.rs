#![allow(clippy::all, dead_code, unused_imports, unused_variables, unused_assignments)]
use herringfish::cipher::key_schedule::KeySchedule;
use herringfish::cipher::round::{add_round_key, mix_columns, shift_rows, sub_bytes};
use herringfish::cipher::{BLOCK_SIZE, NUM_ROUNDS};

fn spn_encrypt_trace(key: &[u8; 32], pt: &[u8; 16]) -> Vec<[u8; 16]> {
    let round_keys = KeySchedule::derive(key);
    let mut state = *pt;
    let mut states = Vec::with_capacity(NUM_ROUNDS + 1);
    // Initial AddRoundKey
    for i in 0..BLOCK_SIZE {
        state[i] ^= round_keys[0][i];
    }
    states.push(state);
    for r in 1..NUM_ROUNDS {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &round_keys[r]);
        states.push(state);
    }
    // Final round without MixColumns
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[NUM_ROUNDS]);
    states.push(state);
    states
}

// Re-export round functions for SPN trace
// We need to make round functions public. Let's assume they are public via mod.
// For now we will duplicate minimal implementations.

fn main() {
    println!("SPN per-round trace instrumentation ready");
    println!("Differential estimation for 1-bit input differences will be implemented next");
}
