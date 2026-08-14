use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

/// Build S-box LAT
fn build_lat() -> [[i32; 256]; 256] {
    let mut lat = [[0i32; 256]; 256];
    for a in 0usize..256 {
        for b in 0usize..256 {
            let mut sum = 0i32;
            for x in 0..256 {
                let y = HERRINGFISH_SBOX_V02[x];
                let bit_x = (x & a) != 0;
                let bit_y = (y as usize & b) != 0;
                sum += if bit_x == bit_y { 1 } else { -1 };
            }
            lat[a][b] = sum;
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
