#![allow(clippy::all, dead_code, unused_imports, unused_variables, unused_assignments)]
use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;
use std::hint::black_box;
use std::time::Instant;

/// Statistical cache-timing measurement with Welch's t-test
fn welch_t_test(a: &[f64], b: &[f64]) -> (f64, f64) {
    let n1 = a.len() as f64;
    let n2 = b.len() as f64;
    let mean1 = a.iter().sum::<f64>() / n1;
    let mean2 = b.iter().sum::<f64>() / n2;
    let var1 = a.iter().map(|x| (x - mean1).powi(2)).sum::<f64>() / (n1 - 1.0);
    let var2 = b.iter().map(|x| (x - mean2).powi(2)).sum::<f64>() / (n2 - 1.0);
    let se = (var1 / n1 + var2 / n2).sqrt();
    let t = (mean1 - mean2) / se;
    // degrees of freedom approximation
    let df_num = (var1 / n1 + var2 / n2).powi(2);
    let df_den = (var1 * var1) / (n1 * n1 * (n1 - 1.0)) + (var2 * var2) / (n2 * n2 * (n2 - 1.0));
    let df = df_num / df_den;
    (t, df)
}

fn main() {
    const ITER_PER_TRIAL: usize = 1_000_000;
    const TRIALS: usize = 100;

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
    let var_seq = seq_times
        .iter()
        .map(|x| (x - mean_seq).powi(2))
        .sum::<f64>()
        / (TRIALS - 1) as f64;
    let var_rand = rand_times
        .iter()
        .map(|x| (x - mean_rand).powi(2))
        .sum::<f64>()
        / (TRIALS - 1) as f64;
    let std_seq = var_seq.sqrt();
    let std_rand = var_rand.sqrt();

    let (t_stat, df) = welch_t_test(&seq_times, &rand_times);

    println!("Cache-timing statistical analysis");
    println!(
        "Trials: {}, Iterations per trial: {}",
        TRIALS, ITER_PER_TRIAL
    );
    println!(
        "Sequential: mean = {:.1} ns, std = {:.1} ns",
        mean_seq / ITER_PER_TRIAL as f64,
        std_seq / ITER_PER_TRIAL as f64
    );
    println!(
        "Random:     mean = {:.1} ns, std = {:.1} ns",
        mean_rand / ITER_PER_TRIAL as f64,
        std_rand / ITER_PER_TRIAL as f64
    );
    println!("Ratio random/sequential: {:.2}x", mean_rand / mean_seq);
    println!("Welch's t-test: t = {:.3}, df ≈ {:.1}", t_stat, df);
    println!(
        "\nNote: High-resolution timing requires QueryPerformanceCounter/RDTSC for cycle accuracy."
    );
    println!("Current measurement uses std::time::Instant and is affected by OS jitter.");
    println!(
        "Table lookup is secret-dependent. Use encrypt_block_ct for constant-time evaluation."
    );
}
