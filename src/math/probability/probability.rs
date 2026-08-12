pub fn differential_probability(weight: u32) -> f64 {
    2.0_f64.powi(-(weight as i32))
}

pub fn linear_bias(correlation: f64) -> f64 {
    correlation.abs()
}
