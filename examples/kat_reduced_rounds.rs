#![allow(clippy::all, dead_code, unused_imports, unused_variables, unused_assignments)]
use herringfish::cipher::feistel_arx::FeistelArx;
use std::fs::File;
use std::io::Write;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let key = [0u8; 32];
    let plaintexts = vec![
        [0u8; 16],
        [0xFF; 16],
        [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10],
    ];
    
    let rounds_list = [4usize, 6usize, 8usize];
    
    let mut f = File::create("docs/tables/kat_reduced_rounds_v02.txt").unwrap();
    writeln!(f, "# Herringfish Feistel ARX v0.2 reduced-round KATs").unwrap();
    writeln!(f, "# Generated: 2026-08-15").unwrap();
    writeln!(f, "# S-box: HERRINGFISH_SBOX_V02, a=0x11, b=0x71").unwrap();
    
    for rounds in rounds_list {
        writeln!(f, "\n[rounds={}]", rounds).unwrap();
        let cipher = FeistelArx::new_with_rounds(&key, rounds);
        for pt in &plaintexts {
            let mut buf = *pt;
            cipher.encrypt_block(&mut buf);
            writeln!(f, "key=0000000000000000000000000000000000000000000000000000000000000000").unwrap();
            writeln!(f, "plaintext={}", hex_encode(pt)).unwrap();
            writeln!(f, "ciphertext={}", hex_encode(&buf)).unwrap();
        }
    }
    println!("Reduced-round KATs written to docs/tables/kat_reduced_rounds_v02.txt");
}
