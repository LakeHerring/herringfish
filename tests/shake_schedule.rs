use herringfish::cipher::{shake_key_schedule::derive_round_keys_shake, BLOCK_SIZE, NUM_ROUNDS};

#[test]
fn shake_key_schedule_deterministic() {
    let key = [0u8; 32];
    let rk1 = derive_round_keys_shake(&key);
    let rk2 = derive_round_keys_shake(&key);
    assert_eq!(rk1, rk2);
    assert_eq!(rk1.len(), NUM_ROUNDS + 1);
    for rk in &rk1 {
        assert_eq!(rk.len(), BLOCK_SIZE);
    }
}

#[test]
fn shake_key_schedule_differs() {
    let key1 = [0u8; 32];
    let mut key2 = [0u8; 32];
    key2[0] = 1;
    let rk1 = derive_round_keys_shake(&key1);
    let rk2 = derive_round_keys_shake(&key2);
    assert_ne!(rk1, rk2);
}
