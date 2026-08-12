use crate::primitives::hash::keccak::KeccakF;

/// Reduced-round Keccak differential experiment
pub struct KeccakReducedExperiment {
    rounds: usize,
}

impl KeccakReducedExperiment {
    pub fn new(rounds: usize) -> Self { Self { rounds } }

    pub fn best_weight1_trail(&self) -> usize {
        // Placeholder: count active bits for weight-1 differences
        let keccak = KeccakF;
        let mut best_active = usize::MAX;
        for lane in 0..25 {
            for bit in 0..64 {
                let mut delta = [[0u64;5];5];
                delta[lane/5][lane%5] = 1u64 << bit;
                let mut cur = delta;
                for _ in 0..self.rounds {
                    cur = keccak.diff_propagation(cur, 1);
                }
                let active = cur.iter().flatten().map(|v| v.count_ones() as usize).sum::<usize>();
                if active < best_active {
                    best_active = active;
                }
            }
        }
        best_active
    }
}
