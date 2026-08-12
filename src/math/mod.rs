pub mod linear_algebra;
pub mod probability;
pub mod combinatorics;
pub mod ddt;
pub mod keccak_chi_ddt;

pub fn bit_diff(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}
