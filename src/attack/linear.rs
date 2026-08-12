use super::Attack;

pub struct LinearAttack {
    pub family: String,
}

impl LinearAttack {
    pub fn new(family: &str) -> Self {
        Self { family: family.to_string() }
    }
}

impl Attack for LinearAttack {
    fn name(&self) -> &'static str { "Linear Cryptanalysis" }
    fn target_family(&self) -> &str { &self.family }
    fn describe(&self) -> String {
        format!("Linear approximations on {} permutation/compression", self.family)
    }
}
