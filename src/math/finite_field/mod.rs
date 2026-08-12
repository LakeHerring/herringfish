// Finite field arithmetic placeholder
pub trait Field {
    fn zero() -> Self;
    fn one() -> Self;
    fn add(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
}

pub struct PrimeField<const MOD: u64>;

impl<const MOD: u64> Field for PrimeField<MOD> {
    fn zero() -> Self { Self }
    fn one() -> Self { Self }
    fn add(&self, _other: &Self) -> Self { Self }
    fn mul(&self, _other: &Self) -> Self { Self }
}
