use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;
use std::hint::black_box;
use std::time::Instant;

/// Statistical cache-timing measurement for S-box table lookup.
/// Measures access time distribution for sequential vs random indices.
fn main() {
    const ITER_PER_TRIAL: usize = 1_000_000;
    const TRIALS: usize = 50;
    
    // Warm up
    for i in 0..256 {
        black_box(HERRINGFISH_SBOX_V02[i]);
    }
    
    let mut seq_times = Vec::with_capacity(TRIALS);
    let mut rand_times = Vec::with_capacity(TRIALS);
    
    for trial in 0..TRIALS {
        // Sequential
        let start = Instant::now();
        let mut acc = 0usize;
        for i in 0..ITER_PER_TRIAL {
            let idx = (i & 0xff) as usize;
            acc = acc.wrapping_add(HERRINGFISH_SBOX_V02[idx] as usize);
        }
        let dur = start.elapsed();
        seq_times.push(dur.as_nanos() as f64);
        black_box(acc);
        
        // Random
        let start = Instant::now();
        let mut seed = (trial as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15);
        let mut acc2 = 0usize;
        for _ in 0..ITER_PER_TRIAL {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let idx = ((seed >> 32) & 0xff) as usize;
            acc2 = acc2.wrapping_add(HERRINGFISH_SBOX_V02[idx] as usize);
        }
        let dur = start.elapsed();
        rand_times.push(dur.as_nanos() as f64);
        black_box(acc2);
    }
    
    let mean_seq = seq_times.iter().sum::<f64>() / TRIALS as f64;
    let mean_rand = rand_times.iter().sum::<f64>() / TRIALS as f64;
    let var_seq = seq_times.iter().map(|x| (x - mean_seq).powi(2)).sum::<f64>() / TRIALS as f64;
    let var_rand = rand_times.iter().map(|x| (x - mean_rand).powi(2)).sum::<f64>() / TRIALS as f64;
    let std_seq = var_seq.sqrt();
    let std_rand = var_rand.sqrt();
    
    println!("Cache-timing statistical analysis");
    println!("Trials: {}, Iterations per trial: {}", TRIALS, ITER_PER_TRIAL);
    println!("Sequential access: mean = {:.1} ns, std = {:.1} ns", mean_seq / ITER_PER_TRIAL as f64, std_seq / ITER_PER_TRIAL as f64);
    println!("Random access:     mean = {:.1} ns, std = {:.1} ns", mean_rand / ITER_PER_TRIAL as f64, std_rand / ITER_PER_TRIAL as f64);
    println!("Ratio random/sequential: {:.2}x", mean_rand / mean_seq);
    println!("\nNote: This is a coarse measurement using std::time::Instant.");
    println!("Real cache-timing attacks require:");
    println!("  - CPU cycle counters, e.g., RDTSC/QueryPerformanceCounter");
    println!("  - Core pinning and OS jitter mitigation");
    println!("  - Statistical tests e.g., Welch's t-test");
    println!("\nTable lookup is secret-dependent. Use encrypt_block_ct for constant-time evaluation.");
}
