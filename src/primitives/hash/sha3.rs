use super::HashFamily;

pub struct Sha3Family;

impl HashFamily for Sha3Family {
    fn name(&self) -> &'static str { "SHA-3" }
    fn state_size_bits(&self) -> usize { 1600 }
    fn digest_size_bits(&self) -> usize { 384 } // example
}

// Keccak-f[1600] mathematical analysis
pub mod analysis {
    pub struct KeccakAnalysis;

    impl KeccakAnalysis {
        pub fn theta(&self) -> &'static str { "parity-based linear layer" }
        pub fn rho(&self) -> &'static str { "bitwise rotation" }
        pub fn pi(&self) -> &'static str { "permutation" }
        pub fn chi(&self) -> &'static str { "non-linear S-box" }
        pub fn iota(&self) -> &'static str { "round constant injection" }
    }
}
