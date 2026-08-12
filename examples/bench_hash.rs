use herringfish::primitives::hash::sha256::Sha256Compressor;
use std::time::Instant;

fn main() {
    let comp = Sha256Compressor;
    let state = [0u32; 8];
    let block = [0u32; 16];
    
    let iterations = 1_000_000;
    
    // Warm up
    for _ in 0..10_000 {
        let _ = comp.compress_n_rounds(state, block, 64);
    }
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = comp.compress_n_rounds(state, block, 64);
    }
    let elapsed = start.elapsed();
    
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    println!("SHA-256 compressor benchmark");
    println!("Iterations: {}", iterations);
    println!("Time: {:?}", elapsed);
    println!("Ops/sec: {:.2e}", ops_per_sec);
    
    // Estimate preimage time
    let n = 256f64;
    let ops = 2f64.powi(n as i32);
    let seconds = ops / ops_per_sec;
    println!("\nGeneric preimage estimate for 256-bit hash at this rate:");
    println!("Operations needed ≈ 2^{:.0}", n);
    println!("Estimated time ≈ {:.2e} seconds", seconds);
    println!("≈ {:.2e} years", seconds / 3600.0 / 24.0 / 365.0);
    
    // Different round counts
    println!("\nRound scaling:");
    for rounds in [16, 32, 48, 64] {
        let start_r = Instant::now();
        for _ in 0..100_000 {
            let _ = comp.compress_n_rounds(state, block, rounds);
        }
        let elapsed_r = start_r.elapsed();
        let ops_r = 100_000f64 / elapsed_r.as_secs_f64();
        println!("  {} rounds: {:.2e} ops/sec", rounds, ops_r);
    }
}
