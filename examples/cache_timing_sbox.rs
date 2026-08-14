use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;
use std::time::Instant;

/// Synthetic cache-timing measurement for S-box table lookup.
/// This is a heuristic demonstration, not a rigorous side-channel measurement.
/// Real cache-timing requires controlled hardware, warm-up, and statistical analysis.
fn main() {
    const ITER: usize = 10_000_000;
    const WARMUP: usize = 1_000_000;
    
    // Warm up cache
    for _ in 0..WARMUP {
        let _ = HERRINGFISH_SBOX_V02[0];
    }
    
    // Measure access time for sequential indices
    let start = Instant::now();
    let mut acc = 0usize;
    for i in 0..ITER {
        let idx = (i & 0xff) as usize;
        acc = acc.wrapping_add(HERRINGFISH_SBOX_V02[idx] as usize);
    }
    let dur_seq = start.elapsed();
    
    // Measure access time for random indices
    // Use a simple LCG for pseudo-random
    let start = Instant::now();
    let mut seed = 0x12345678u64;
    let mut acc2 = 0usize;
    for _ in 0..ITER {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let idx = ((seed >> 32) & 0xff) as usize;
        acc2 = acc2.wrapping_add(HERRINGFISH_SBOX_V02[idx] as usize);
    }
    let dur_rand = start.elapsed();
    
    println!("Cache-timing synthetic benchmark");
    println!("Iterations: {}", ITER);
    println!("Sequential access: {:?}  checksum {}", dur_seq, acc);
    println!("Random access:     {:?}  checksum {}", dur_rand, acc2);
    println!("\nNote: This is a coarse timing measurement. Real cache-timing attacks require:");
    println!("  - Controlled hardware with known cache hierarchy");
    println!("  - High-resolution timers, e.g., RDTSC");
    println!("  - Statistical analysis across many trials");
    println!("  - Isolation from OS jitter");
    println!("\nTable lookup is secret-dependent and thus vulnerable to cache-timing in the reference implementation.");
    println!("Use encrypt_block_ct for constant-time evaluation.");
}
