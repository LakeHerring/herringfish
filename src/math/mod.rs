pub mod bigint;
pub mod finite_field;
pub mod polynomial;
pub mod matrix;
pub mod lattice;
pub mod ntt;
pub mod probability;

pub fn bit_diff(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}
