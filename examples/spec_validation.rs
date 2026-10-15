//! Validate that the implementation matches the numbers the v0.2 / solo-arx
//! specification states. Every check is an assertion: any mismatch aborts with a
//! non-zero exit status, so the CI step cannot pass while a parameter is wrong.
//!
//! Previously this example printed fixed text for every section except the S-box
//! and ended with "All checked parameters match" unconditionally; it could not
//! fail. Observed, not assumed: each line below is computed from the code.

// Index loops mirror the math (masks, byte positions); same allow as src/cipher/mod.rs.
#![allow(clippy::needless_range_loop)]

use herringfish::cipher::arx_key_schedule::{ROUND_CONSTANTS, derive_round_keys};
use herringfish::cipher::feistel_arx::{
    BLOCK_SIZE, FeistelArx, HERRINGFISH_SBOX_V02, KEY_SIZE, NUM_ROUNDS, diffuse,
};

const GOLDEN64: u64 = 0x9E37_79B9_7F4A_7C15;

/// Spec §6, written out independently of `diffuse()`: d_i = y_i ^ y_{i+1} ^ y_{i+3} (mod 8).
fn diffuse_spec(y: u64) -> u64 {
    let b = y.to_le_bytes();
    let mut d = [0u8; 8];
    for i in 0..8 {
        d[i] = b[i] ^ b[(i + 1) % 8] ^ b[(i + 3) % 8];
    }
    u64::from_le_bytes(d)
}

fn main() {
    println!("Herringfish Feistel ARX v0.2 (solo-arx) specification validation");

    // 1. S-box (spec §8-§9)
    println!("\n1. S-box properties");
    let mut seen = [false; 256];
    for &v in HERRINGFISH_SBOX_V02.iter() {
        assert!(!seen[v as usize], "duplicate S-box value {v:#04x}");
        seen[v as usize] = true;
    }
    println!("  bijective: true");

    let mut ddt_max = 0u16;
    for dx in 1..=255usize {
        let mut counts = [0u16; 256];
        for x in 0..256usize {
            counts[(HERRINGFISH_SBOX_V02[x ^ dx] ^ HERRINGFISH_SBOX_V02[x]) as usize] += 1;
        }
        ddt_max = ddt_max.max(*counts.iter().max().unwrap());
    }
    assert_eq!(ddt_max, 4, "DDT max must be 4 (spec §9.2)");
    println!(
        "  DDT max count: {ddt_max} (probability {})",
        ddt_max as f64 / 256.0
    );

    let mut lat_max = 0i32;
    for a in 1..=255usize {
        for b in 1..=255usize {
            let mut sum = 0i32;
            for x in 0..256usize {
                let parity = ((x & a).count_ones()
                    ^ (HERRINGFISH_SBOX_V02[x] as usize & b).count_ones())
                    & 1;
                sum += if parity == 0 { 1 } else { -1 };
            }
            lat_max = lat_max.max(sum.abs());
        }
    }
    assert_eq!(lat_max, 32, "LAT max must be 32 (spec §9.3)");
    println!(
        "  LAT max |bias count|: {lat_max} (correlation {})",
        lat_max as f64 / 256.0
    );

    // 2. Global parameters (spec §3)
    println!("\n2. Global parameters");
    assert_eq!(BLOCK_SIZE, 16, "block size 128 bits");
    assert_eq!(KEY_SIZE, 32, "master key 256 bits");
    assert_eq!(NUM_ROUNDS, 16, "16 rounds");
    let key = [0u8; KEY_SIZE];
    let cipher = FeistelArx::new(&key);
    assert_eq!(cipher.rounds(), 16);
    assert_eq!(
        cipher.round_keys().len(),
        16,
        "one 64-bit round key per round"
    );
    println!(
        "  block {} bits, key {} bits, rounds {}, round keys {} x 64 bits",
        BLOCK_SIZE * 8,
        KEY_SIZE * 8,
        cipher.rounds(),
        cipher.round_keys().len()
    );

    // 3. Diffusion layer (spec §6): implementation equals the spec formula
    println!("\n3. Diffusion layer");
    let mut s: u64 = 0x2F6E_2B1D_9A37_C415;
    for _ in 0..10_000 {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        assert_eq!(
            diffuse(s),
            diffuse_spec(s),
            "diffuse() differs from spec §6 for {s:#018x}"
        );
    }
    println!("  diffuse() == spec formula on 10000 pseudo-random inputs");

    // 4. Key schedule (spec §12-S)
    println!("\n4. Solo-ARX key schedule");
    for (i, &c) in ROUND_CONSTANTS.iter().enumerate() {
        assert_eq!(
            c,
            GOLDEN64.wrapping_mul(2 * i as u64 + 1),
            "constant C[{i}]"
        );
    }
    println!("  16 constants equal GOLDEN64 * (2i+1) mod 2^64");
    let long = derive_round_keys(&key, 16);
    assert_eq!(derive_round_keys(&key, 5), long[..5], "prefix property");
    assert_eq!(
        cipher.round_keys(),
        long.as_slice(),
        "cipher uses the schedule"
    );
    println!("  prefix property holds; cipher uses derive_round_keys()");

    // 5. Known answer (spec §12-S KAT set; docs/tables/kat_vectors_v02.txt, first vector)
    println!("\n5. Known-answer check");
    let mut block = [0u8; BLOCK_SIZE];
    cipher.encrypt_block(&mut block);
    let hex: String = block.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex, "dd67189a17bbeabeb8c5a682b203a9a1",
        "zero key / zero plaintext"
    );
    cipher.decrypt_block(&mut block);
    assert_eq!(block, [0u8; BLOCK_SIZE], "decrypt inverts encrypt");
    println!("  zero key / zero plaintext -> dd67189a17bbeabeb8c5a682b203a9a1; round trip ok");
    println!(
        "  (all 145 vectors: `cargo test --test kat`, `kat_verify`, scripts/herringfish_ref.py)"
    );

    println!("\nValidation complete: every check above passed.");
}
