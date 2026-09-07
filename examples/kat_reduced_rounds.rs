#![allow(
    clippy::all,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments
)]
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
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ],
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
            writeln!(
                f,
                "key=0000000000000000000000000000000000000000000000000000000000000000"
            )
            .unwrap();
            writeln!(f, "plaintext={}", hex_encode(pt)).unwrap();
            writeln!(f, "ciphertext={}", hex_encode(&buf)).unwrap();
        }
    }
    drop(f);
    println!("Reduced-round KATs written to docs/tables/kat_reduced_rounds_v02.txt");

    // Also regenerate docs/tables/kat_reduced_all.txt: three sections
    // (4, 6, 8 rounds), each with the standard 3x3 key/plaintext grid,
    // separated by `---` lines. The grid uses the 00112233... plaintext
    // to match the original table.
    let all_plaintexts = [
        [0u8; 16],
        [0xFF; 16],
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ],
    ];
    let all_keys = [
        [0u8; 32],
        [0xFFu8; 32],
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
    ];

    let mut f = File::create("docs/tables/kat_reduced_all.txt").unwrap();
    for (si, &rounds) in rounds_list.iter().enumerate() {
        if si > 0 {
            writeln!(f, "---").unwrap();
        }
        writeln!(f, "# Herringfish Feistel ARX v0.2 {} rounds KAT", rounds).unwrap();
        for (ki, k) in all_keys.iter().enumerate() {
            let c = FeistelArx::new_with_rounds(k, rounds);
            for (pi, pt) in all_plaintexts.iter().enumerate() {
                let mut buf = *pt;
                c.encrypt_block(&mut buf);
                if ki > 0 || pi > 0 {
                    writeln!(f).unwrap();
                }
                writeln!(f, "Key: {}", hex_encode(k)).unwrap();
                writeln!(f, "Plaintext: {}", hex_encode(pt)).unwrap();
                writeln!(f, "Ciphertext: {}", hex_encode(&buf)).unwrap();
            }
        }
    }
    println!("Reduced-round KATs written to docs/tables/kat_reduced_all.txt");
}
