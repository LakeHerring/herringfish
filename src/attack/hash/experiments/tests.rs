#[cfg(test)]
mod tests {
    use crate::attack::hash::experiments::sha256_reduced::Sha256ReducedExperiment;
    use crate::attack::hash::experiments::keccak_reduced::KeccakReducedExperiment;

    #[test]
    fn test_sha256_reduced_experiment_runs() {
        let exp = Sha256ReducedExperiment::new(4);
        let (state, msg, active) = exp.find_best_difference();
        assert!(active <= 8, "active words should be small for reduced rounds");
        println!("SHA-256 4-round best: state {}, msg {}, active {}", state, msg, active);
    }

    #[test]
    fn test_keccak_reduced_experiment_runs() {
        let exp = KeccakReducedExperiment::new(4);
        let best = exp.best_weight1_trail();
        assert!(best > 0);
        println!("Keccak 4-round best active bits: {}", best);
    }
}
