use herringfish::cipher::feistel_arx::FeistelArx;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() {
    let mut keys = Vec::new();
    for i in 0..10 {
        let mut k = [0u8;32];
        for j in 0..32 { k[j] = ((i*32 + j) % 256) as u8; }
        keys.push(k);
    }
    let mut plaintexts = Vec::new();
    for i in 0..10 {
        let mut p = [0u8;16];
        for j in 0..16 { p[j] = ((i*16 + j) % 256) as u8; }
        plaintexts.push(p);
    }
    println!("# Herringfish Feistel ARX v0.2 Expanded KAT");
    println!("S-box: HERRINGFISH_SBOX_V02, rounds=16");
    for k in &keys {
        let cipher = FeistelArx::new(k);
        for p in &plaintexts {
            let mut ct = *p;
            cipher.encrypt_block(&mut ct);
            println!("Key: {}", to_hex(k));
            println!("Plaintext: {}", to_hex(p));
            println!("Ciphertext: {}", to_hex(&ct));
            println!();
        }
    }
}
