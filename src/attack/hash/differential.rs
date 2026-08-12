use crate::attack::Attack;
use crate::primitives::hash::keccak::KeccakF;
use crate::primitives::hash::sha256::Sha256Compressor;

pub struct DifferentialAttack {
    pub family: String,
}

impl DifferentialAttack {
    pub fn new(family: &str) -> Self {
        Self { family: family.to_string() }
    }

    pub fn find_characteristic(&self, rounds: usize) -> Vec<u64> {
        vec![0u64; rounds]
    }

    pub fn search_keccak(&self, rounds: usize, max_weight: usize) -> (usize, usize, usize, f64, u64, usize) {
        let keccak = KeccakF;
        let mut best_score = f64::INFINITY;
        let mut best_desc = String::new();
        let mut best_active_bits = 0usize;
        let mut best_sample = 0u64;
        let mut evaluated = 0usize;

        let positions = 25 * 64;
        let mut indices: Vec<usize> = Vec::new();
        for i in 0..positions {
            indices.push(i);
        }

        // Weight 1
        for &pos in &indices {
            evaluated += 1;
            let mut delta = [[0u64;5];5];
            let lane = pos / 64;
            let bit = pos % 64;
            let x = lane / 5;
            let y = lane % 5;
            delta[x][y] = 1u64 << bit;
            let (active, sample, prob) = evaluate_keccak_trail_exact(&keccak, delta, rounds);
            let score = active as f64 - prob.log2().abs();
            if score < best_score {
                best_score = score;
                best_desc = format!("lane {} bit {}", lane, bit);
                best_active_bits = active;
                best_sample = sample;
            }
        }

        // Weight 2 sampling
        if max_weight >= 2 {
            let sample_limit = 200;
            for i in 0..sample_limit.min(indices.len()) {
                for j in i+1..sample_limit.min(indices.len()) {
                    evaluated += 1;
                    let mut delta = [[0u64;5];5];
                    let p1 = indices[i];
                    let p2 = indices[j];
                    let lane1 = p1 / 64;
                    let bit1 = p1 % 64;
                    let lane2 = p2 / 64;
                    let bit2 = p2 % 64;
                    let x1 = lane1 / 5;
                    let y1 = lane1 % 5;
                    let x2 = lane2 / 5;
                    let y2 = lane2 % 5;
                    delta[x1][y1] |= 1u64 << bit1;
                    delta[x2][y2] |= 1u64 << bit2;
                    let (active, sample, prob) = evaluate_keccak_trail_exact(&keccak, delta, rounds);
                    let score = active as f64 - prob.log2().abs();
                    if score < best_score {
                        best_score = score;
                        best_desc = format!("pair ({},{}) ({},{})", lane1, bit1, lane2, bit2);
                        best_active_bits = active;
                        best_sample = sample;
                    }
                }
            }
        }

        let prob_est = 2f64.powi(-(best_active_bits as i32));
        // Parse description for reporting
        let lane = 0usize;
        let bit = 0usize;
        (lane, bit, best_active_bits, prob_est, best_sample, evaluated)
    }

    pub fn search_keccak_4round(&self) -> (usize, usize, usize, f64, u64) {
        let (lane, bit, active, prob, sample, _) = self.search_keccak(4, 2);
        (lane, bit, active, prob, sample)
    }

    pub fn search_sha256_reduced(&self, rounds: usize) -> (usize, usize, usize) {
        let comp = Sha256Compressor;
        let mut best_active = usize::MAX;
        let mut best_state_word = 0usize;
        let mut best_msg_word = 0usize;

        for state_word in 0..8 {
            for msg_word in 0..16 {
                let mut delta_state = [0u32;8];
                delta_state[state_word] = 0x00000001;
                let mut delta_msg = [0u32;16];
                delta_msg[msg_word] = 0x00000001;
                let out = comp.diff_propagation(delta_state, delta_msg, rounds);
                let active = Sha256Compressor::active_words(&out);
                if active < best_active {
                    best_active = active;
                    best_state_word = state_word;
                    best_msg_word = msg_word;
                }
                if rounds <= 16 {
                    let mut delta_msg2 = [0u32;16];
                    delta_msg2[msg_word] = 0x00000003;
                    let out2 = comp.diff_propagation(delta_state, delta_msg2, rounds);
                    let active2 = Sha256Compressor::active_words(&out2);
                    if active2 < best_active {
                        best_active = active2;
                        best_state_word = state_word;
                        best_msg_word = msg_word;
                    }
                }
            }
        }
        (best_state_word, best_msg_word, best_active)
    }
}

fn evaluate_keccak_trail_exact(keccak: &KeccakF, delta: [[u64;5];5], rounds: usize) -> (usize, u64, f64) {
    let mut cur = delta;
    let mut prob = 1.0;
    for _ in 0..rounds {
        // Compute exact χ DDT probability for current difference before chi
        let p = KeccakF::chi_ddt_probability(&cur);
        prob *= p;
        if prob == 0.0 {
            break;
        }
        cur = keccak.diff_propagation(cur, 1);
    }
    let active_bits: usize = cur.iter().flatten().map(|v| v.count_ones() as usize).sum();
    let sample = cur[0][0];
    (active_bits, sample, prob)
}

impl Attack for DifferentialAttack {
    fn name(&self) -> &'static str { "Differential Cryptanalysis" }
    fn target_family(&self) -> &str { &self.family }
    fn describe(&self) -> String {
        format!("Differential trails on {} round function", self.family)
    }
}
