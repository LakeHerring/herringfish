/// DDT for Keccak χ and SHA-2 Boolean functions
/// χ is a 5-bit permutation per row

pub fn chi5(x: u8) -> u8 {
    let mut y = 0u8;
    for i in 0..5 {
        let a = (x >> i) & 1;
        let b = (x >> ((i + 1) % 5)) & 1;
        let c = (x >> ((i + 2) % 5)) & 1;
        let out = a ^ ((1 - b) & c);
        y |= out << i;
    }
    y
}

pub fn build_chi_ddt() -> [[u16; 32]; 32] {
    let mut table = [[0u16; 32]; 32];
    for in_mask in 0..32 {
        for x in 0..32 {
            let y = x ^ in_mask;
            let out = chi5(x as u8) ^ chi5(y as u8);
            table[in_mask][out as usize] += 1;
        }
    }
    table
}

pub fn chi_differential_uniformity() -> usize {
    let table = build_chi_ddt();
    let mut max = 0usize;
    for i in 1..32 {
        for j in 0..32 {
            let v = table[i][j] as usize;
            if v > max {
                max = v;
            }
        }
    }
    max
}

// SHA-256 Ch and Maj DDTs
#[inline]
fn ch3(a: u8, b: u8, c: u8) -> u8 {
    (a & b) ^ ((!a) & c)
}

#[inline]
fn maj3(a: u8, b: u8, c: u8) -> u8 {
    (a & b) ^ (a & c) ^ (b & c)
}

pub fn build_ch_ddt() -> [[u16; 2]; 2] {
    // 1-bit DDT for Ch
    let mut table = [[0u16; 2]; 2];
    for dx in 0..2 {
        for dy in 0..2 {
            for dz in 0..2 {
                let mut cnt = 0;
                for a in 0..2 {
                    for b in 0..2 {
                        for c in 0..2 {
                            let a2 = a ^ dx;
                            let b2 = b ^ dy;
                            let c2 = c ^ dz;
                            let out1 = ch3(a as u8, b as u8, c as u8);
                            let out2 = ch3(a2 as u8, b2 as u8, c2 as u8);
                            let dout = out1 ^ out2;
                            table[dx | dy << 1 | dz << 2][dout as usize] += 1;
                        }
                    }
                }
            }
        }
    }
    table
}
