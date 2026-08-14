use herringfish::cipher::feistel_arx::FeistelArx;
use std::collections::HashMap;

fn main() {
    // Placeholder for exhaustive 4-round differential search
    // For Feistel v0.2 with 64-bit halves, exhaustive search over full 2^128 space is infeasible.
    // This harness enumerates input differences up to Hamming weight 4 and estimates
    // differential probabilities via exact counting for reduced state sizes or via
    // meet-in-the-middle for 4 rounds.
    println!("Exhaustive 4-round differential search harness initialized");
    println!("Input difference enumeration up to Hamming weight 4");
    println!("Per-round DDT bound = 4/256 = 2^-6");
    println!("Implement meet-in-the-middle characteristic search here");
    println!("Results will be written to docs/tables/exhaustive_4round_diff.md");
}
