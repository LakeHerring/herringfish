use super::HashFamily;

pub struct ShakeFamily;

impl HashFamily for ShakeFamily {
    fn name(&self) -> &'static str { "SHAKE" }
    fn state_size_bits(&self) -> usize { 1600 }
    fn digest_size_bits(&self) -> usize { 256 } // variable
}

// Sponge construction analysis
pub mod analysis {
    pub struct SpongeAnalysis;

    impl SpongeAnalysis {
        pub fn absorb_phase(&self) -> &'static str { "input mixed into state" }
        pub fn squeeze_phase(&self) -> &'static str { "output extracted from state" }
        pub fn capacity(&self, rate: usize) -> usize {
            1600 - rate
        }
    }
}
