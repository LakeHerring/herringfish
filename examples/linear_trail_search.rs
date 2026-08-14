use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

fn build_lat() -> [[i32;256];256] {
    let mut lat = [[0i32;256];256];
    for a in 0..256 {
        for b in 0..256 {
            let mut sum = 0i32;
            for x in 0..256 {
                let ax = ((x as u8) & a as u8).count_ones() & 1;
                let bx = (HERRINGFISH_SBOX_V02[x] & b as u8).count_ones() & 1;
                if ax == bx { sum += 1; } else { sum -= 1; }
            }
            lat[a][b] = sum;
        }
    }
    lat
}

fn main() {
    let lat = build_lat();
    let mut max_bias = 0i32;
    for a in 1..256 {
        for b in 1..256 {
            let v = lat[a][b].abs();
            if v > max_bias { max_bias = v; }
        }
    }
    println!("S-box LAT max bias = {}", max_bias);
    println!("Linear trail heuristic for 4 rounds: correlation ≈ (max_bias/256)^(8*4)");
    let corr = (max_bias as f64 / 256.0).powi(32);
    println!("Heuristic correlation ≈ {:.3e}", corr);
    println!("This is a starting point for full linear trail/hull analysis.");
}
