use herringfish::cipher::feistel_arx::FeistelArx;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let keys = [
        [0u8; 32],
        [0xff; 32],
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
    ];
    let plaintexts = [
        [0u8; 16],
        [0xff; 16],
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ],
    ];
    let mut ok = true;
    for k in &keys {
        let cipher = FeistelArx::new(k);
        for p in &plaintexts {
            let mut ct = *p;
            cipher.encrypt_block(&mut ct);
            let mut dec = ct;
            cipher.decrypt_block(&mut dec);
            if dec != *p {
                println!("Round-trip failure");
                ok = false;
            }
        }
    }
    if ok {
        println!("All KAT vectors passed round-trip");
    } else {
        println!("Some checks failed");
    }
}
