#![allow(
    clippy::all,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments
)]
use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

/// GF(2) dot product (parity of the bitwise AND)
fn parity(x: u8) -> bool {
    x.count_ones() % 2 == 1
}

/// Build S-box LAT: lat[a][b] = sum_x (-1)^(a·x ^ b·S(x))
/// Note: the mask predicate is the GF(2) dot product (parity), not
/// `(x & a) != 0` (nonzero test, which is nonlinear and inflates the
/// apparent bias).
fn build_lat() -> [[i32; 256]; 256] {
    let mut lat = [[0i32; 256]; 256];
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            let mut sum = 0i32;
            for x in 0..=255u8 {
                let y = HERRINGFISH_SBOX_V02[x as usize];
                let bit_x = parity(x & a);
                let bit_y = parity(y & b);
                sum += if bit_x == bit_y { 1 } else { -1 };
            }
            lat[a as usize][b as usize] = sum;
        }
    }
    lat
}

fn max_abs_lat(lat: &[[i32; 256]; 256]) -> i32 {
    let mut max = 0;
    for a in 1usize..256 {
        for b in 1usize..256 {
            let v = lat[a][b].abs();
            if v > max {
                max = v;
            }
        }
    }
    max
}

fn main() {
    let lat = build_lat();
    let max_bias = max_abs_lat(&lat);
    println!("S-box LAT max bias count: {}", max_bias);
    println!("S-box LAT max correlation: {:.4}", max_bias as f64 / 256.0);

    for rounds in [4usize, 6usize] {
        // Heuristic linear trail bound: bias per S-box ~ max_bias/256
        let per_sbox_bias = max_bias as f64 / 256.0;
        // 8 S-boxes per round, Feistel structure
        let per_round_bias = per_sbox_bias.powi(8);
        let trail_bias = per_round_bias.powi(rounds as i32);
        println!(
            "Rounds {}: heuristic max linear trail bias ≈ {:.3e}",
            rounds, trail_bias
        );
    }
    println!(
        "Note: full mask enumeration for Feistel network requires joint distribution across rounds and linear diffusion."
    );
}
