#![allow(
    clippy::all,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments
)]
use herringfish::cipher::feistel_arx::FeistelArx;

fn main() {
    let key = [0u8; 32];
    let mut pt = [0u8; 16];
    let cipher = FeistelArx::new(&key);
    cipher.encrypt_block(&mut pt);
    println!("Key: {}", hex(&key));
    println!("Plaintext: {}", hex(&[0u8; 16]));
    println!("Ciphertext: {}", hex(&pt));
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{:02x}", x))
        .collect::<Vec<_>>()
        .join("")
}
