// Finite field arithmetic
pub trait Field {
    type Elem;
    fn zero() -> Self::Elem;
    fn one() -> Self::Elem;
    fn add(a: &Self::Elem, b: &Self::Elem) -> Self::Elem;
    fn mul(a: &Self::Elem, b: &Self::Elem) -> Self::Elem;
    fn neg(a: &Self::Elem) -> Self::Elem;
    fn inv(a: &Self::Elem) -> Option<Self::Elem>;
}

pub mod ddt;
pub mod keccak_chi_ddt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrimeField<const MOD: u64> {
    value: u64,
}

impl<const MOD: u64> PrimeField<MOD> {
    pub fn new(value: u64) -> Self {
        Self { value: value % MOD }
    }
    pub fn value(&self) -> u64 { self.value }
}

impl<const MOD: u64> std::ops::Add for PrimeField<MOD> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self { value: (self.value + rhs.value) % MOD }
    }
}

impl<const MOD: u64> std::ops::Mul for PrimeField<MOD> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self { value: ((self.value as u128 * rhs.value as u128) % MOD as u128) as u64 }
    }
}

impl<const MOD: u64> Field for PrimeField<MOD> {
    type Elem = Self;
    fn zero() -> Self::Elem { Self { value: 0 } }
    fn one() -> Self::Elem { Self { value: 1 % MOD } }
    fn add(a: &Self::Elem, b: &Self::Elem) -> Self::Elem { *a + *b }
    fn mul(a: &Self::Elem, b: &Self::Elem) -> Self::Elem { *a * *b }
    fn neg(a: &Self::Elem) -> Self::Elem {
        Self { value: if a.value == 0 {0} else { MOD - a.value } }
    }
    fn inv(a: &Self::Elem) -> Option<Self::Elem> {
        if a.value == 0 { return None; }
        // Extended Euclidean for u64
        let (g, x, _) = egcd(a.value as i128, MOD as i128);
        if g != 1 { return None; }
        let inv = ((x % MOD as i128 + MOD as i128) % MOD as i128) as u64;
        Some(Self { value: inv })
    }
}

fn egcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 { (a, 1, 0) } else {
        let (g, x1, y1) = egcd(b, a % b);
        (g, y1, x1 - (a / b) * y1)
    }
}
