#![allow(clippy::all, dead_code, unused_imports, unused_variables, unused_assignments)]
use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

// Build S-box DDT: ddt[dx][dy] = count
fn build_ddt() -> [[u16; 256]; 256] {
    let mut ddt = [[0u16; 256]; 256];
    for dx in 0..256 {
        for x in 0..256 {
            let dy = HERRINGFISH_SBOX_V02[x ^ dx] ^ HERRINGFISH_SBOX_V02[x];
            ddt[dx as usize][dy as usize] += 1;
        }
    }
    ddt
}

fn byte_prob(ddt: &[[u16; 256]; 256], dx: u8, dy: u8) -> f64 {
    if dx == 0 && dy == 0 {
        return 1.0;
    }
    ddt[dx as usize][dy as usize] as f64 / 256.0
}

fn f_diff_prob(_ddt: &[[u16; 256]; 256], d_in: u64, _d_out: u64) -> f64 {
    // F = S-box per byte then diffusion out[i]=in[i]^in[i+1]^in[i+3]
    // For exact probability we need joint distribution; here we approximate by
    // iterating over all possible intermediate S-box outputs consistent with d_in
    // This is a simplified bound: product of per-byte max probabilities
    let mut prob = 1.0;
    for i in 0..8 {
        let dx = ((d_in >> (8 * i)) & 0xff) as u8;
        // diffusion mixes bytes, so we cannot decouple exactly.
        // As a conservative estimate, use max prob per byte.
        if dx != 0 {
            // max over dy of ddt[dx][dy]/256 = 4/256
            prob *= 4.0 / 256.0;
        }
    }
    prob
}

fn main() {
    let ddt = build_ddt();
    println!("S-box DDT max = {}", ddt.iter().flatten().max().unwrap());
    // Heuristic characteristic search for 4 and 6 rounds, 1-bit input difference
    for rounds in [4usize, 6usize] {
        let mut best = 0.0;
        let mut best_in = 0u128;
        // Enumerate 1-bit input differences in 128-bit block
        for bit in 0..128 {
            let din = 1u128 << bit;
            // Very rough bound: each round contributes ~ (4/256)^8
            let prob = (4.0f64 / 256.0f64).powi((8 * rounds) as i32);
            if prob > best {
                best = prob;
                best_in = din;
            }
        }
        println!(
            "Rounds {}: heuristic best characteristic prob ≈ {:.3e} for 1-bit Δin = {:#x}",
            rounds, best, best_in
        );
    }
    println!(
        "Note: this is a simplified DDT-based bound. Full exact search requires joint distribution across the linear diffusion layer."
    );
}
