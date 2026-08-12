use herringfish::attack::hash::experiments::sha256_reduced::Sha256ReducedExperiment;

fn main() {
    for rounds in [4, 8, 12].iter() {
        let exp = Sha256ReducedExperiment::new(*rounds);
        let (state, msg, active) = exp.find_best_difference();
        println!("Rounds {}: best state word {}, message word {}, active words {}", rounds, state, msg, active);
    }
}
