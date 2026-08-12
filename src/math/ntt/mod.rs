// Number theoretic transform placeholder
pub struct Ntt {
    modulus: u64,
}

impl Ntt {
    pub fn new(modulus: u64) -> Self { Self { modulus } }
}
