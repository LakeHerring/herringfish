use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

fn f_function(x: u64, k: u64) -> u64 {
    let sbox = &HERRINGFISH_SBOX_V02;
    let mut out = 0u64;
    for i in 0..8 {
        let x_byte = ((x >> (8*i)) & 0xff) as u8;
        let k_byte = ((k >> (8*i)) & 0xff) as u8;
        let sb = sbox[(x_byte ^ k_byte) as usize];
        out |= (sb as u64) << (8*i);
    }
    let mut bytes = [0u8;8];
    for i in 0..8 { bytes[i] = ((out >> (8*i)) & 0xff) as u8; }
    let mut out_bytes = [0u8;8];
    for i in 0..8 {
        out_bytes[i] = bytes[i] ^ bytes[(i+1)%8] ^ bytes[(i+3)%8];
    }
    let mut out2 = 0u64;
    for i in 0..8 { out2 |= (out_bytes[i] as u64) << (8*i); }
    out2
}

fn derive_round_keys(key: &[u8;32]) -> Vec<u64> {
    use shake::Shake256;
    use sha3::digest::Update;
    use shake::ExtendableOutput;
    const DOMAIN: &[u8] = b"HERRINGFISH-FEISTEL-KEY";
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN);
    hasher.update(key);
    let mut out = vec![0u8; 16*8];
    hasher.finalize_xof_into(&mut out);
    (0..16).map(|i| {
        let mut b = [0u8;8];
        b.copy_from_slice(&out[i*8..i*8+8]);
        u64::from_le_bytes(b)
    }).collect()
}

fn encrypt_block(key: &[u8;32], pt: &[u8;16], rounds: usize) -> [u8;16] {
    let keys = derive_round_keys(key);
    let mut left = u64::from_le_bytes(pt[0..8].try_into().unwrap());
    let mut right = u64::from_le_bytes(pt[8..16].try_into().unwrap());
    for i in 0..rounds {
        let f_out = f_function(right, keys[i]);
        let new_right = left ^ f_out;
        left = right;
        right = new_right;
    }
    let mut out = [0u8;16];
    out[0..8].copy_from_slice(&left.to_le_bytes());
    out[8..16].copy_from_slice(&right.to_le_bytes());
    out
}

fn to_hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

fn main() {
    let keys = [
        [0u8;32],
        [0xff;32],
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f],
    ];
    let plaintexts = [
        [0u8;16],
        [0xff;16],
        [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff],
    ];
    for rounds in [4usize,6,8] {
        println!("# Herringfish Feistel ARX v0.2 {} rounds KAT", rounds);
        for k in &keys {
            for p in &plaintexts {
                let ct = encrypt_block(k, p, rounds);
                println!("Key: {}", to_hex(k));
                println!("Plaintext: {}", to_hex(p));
                println!("Ciphertext: {}", to_hex(&ct));
                println!();
            }
        }
        println!("---");
    }
}
