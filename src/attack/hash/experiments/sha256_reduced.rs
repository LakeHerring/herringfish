use crate::primitives::hash::sha256::Sha256Compressor;

/// Simple reduced-round differential experiment for SHA-256
pub struct Sha256ReducedExperiment {
    rounds: usize,
}

impl Sha256ReducedExperiment {
    pub fn new(rounds: usize) -> Self { Self { rounds } }

    pub fn find_best_difference(&self) -> (usize, usize, usize) {
        let comp = Sha256Compressor;
        let mut best_state = 0usize;
        let mut best_msg = 0usize;
        let mut best_active = usize::MAX;
        for s in 0..8 {
            for m in 0..16 {
                let mut delta_state = [0u32; 8];
                delta_state[s] = 1;
                let mut delta_msg = [0u32; 16];
                delta_msg[m] = 1;
                let out = comp.diff_propagation(delta_state, delta_msg, self.rounds);
                let active = Sha256Compressor::active_words(&out);
                if active < best_active {
                    best_active = active;
                    best_state = s;
                    best_msg = m;
                }
            }
        }
        (best_state, best_msg, best_active)
    }
}
