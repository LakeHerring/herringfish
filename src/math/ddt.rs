/// Differential Distribution Table for n-bit S-boxes
/// Based on survey of DDT implementations for differential cryptanalysis
/// Probability p = count / 2^n where count is number of input pairs with given difference

pub struct DDT {
    pub n: usize,
    pub table: Vec<Vec<usize>>, // table[delta_in][delta_out]
}

impl DDT {
    pub fn new(sbox: &[u8]) -> Self {
        let n = (sbox.len() as f64).log2() as usize;
        let size = 1 << n;
        let mut table = vec![vec![0usize; size]; size];
        for x in 0..size {
            for y in 0..size {
                let delta_in = x ^ y;
                let delta_out = (sbox[x] ^ sbox[y]) as usize;
                table[delta_in][delta_out] += 1;
            }
        }
        Self { n, table }
    }

    pub fn probability(&self, delta_in: usize, delta_out: usize) -> f64 {
        let count = self.table[delta_in][delta_out];
        let total = 1 << self.n;
        count as f64 / total as f64
    }

    pub fn max_probability(&self) -> f64 {
        let size = 1 << self.n;
        let mut max_count = 0usize;
        for i in 1..size {
            for j in 0..size {
                if self.table[i][j] > max_count {
                    max_count = self.table[i][j];
                }
            }
        }
        max_count as f64 / (1 << self.n) as f64
    }

    pub fn differential_uniformity(&self) -> usize {
        let size = 1 << self.n;
        let mut max = 0usize;
        for i in 1..size {
            for j in 0..size {
                if self.table[i][j] > max {
                    max = self.table[i][j];
                }
            }
        }
        max
    }
}

// Example 4-bit S-box from PRESENT
pub const PRESENT_SBOX: [u8; 16] = [
    0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd,
    0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2,
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn present_ddt() {
        let ddt = DDT::new(&PRESENT_SBOX);
        assert_eq!(ddt.differential_uniformity(), 4);
    }
}
