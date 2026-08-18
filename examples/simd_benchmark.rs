use herringfish::cipher::feistel_arx::{BLOCK_SIZE, FeistelArx};
use herringfish::simd::avx2;
use std::time::Instant;

fn main() {
    let key = [0u8; 32];
    let cipher = FeistelArx::new(&key);
    let mut block = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        block[i] = i as u8;
    }

    println!("Starting SIMD vs Scalar Benchmark...");

    // --- Scalar Benchmark ---
    let iterations = 1_000_000;
    let start = Instant::now();
    for _ in 0..iterations {
        cipher.encrypt_block(&mut block);
    }
    let duration = start.elapsed();
    println!(
        "Scalar: {:?} for {} iterations ({} MB/s)",
        duration,
        iterations,
        (iterations as f64 * BLOCK_SIZE as f64) / 1024.0 / 1024.0 / duration.as_secs_f64()
    );

    // --- SIMD Benchmark (AVX2 Diffusion only for comparison) ---
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::*;
        let mut data = [0u8; 32]; // Two blocks
        for i in 0..16 {
            data[i] = block[i];
            data[i + 16] = block[i];
        }

        let start_simd = Instant::now();
        for _ in 0..iterations {
            unsafe {
                let block_vec = _mm256_loadu_si256(data.as_ptr() as *const __m256i);
                let diffused = avx2::diffusion_avx2(block_vec);
                _mm256_storeu_si256(data.as_mut_ptr() as *mut __m256i, diffused);
            }
        }
        let duration_simd = start_simd.elapsed();
        println!(
            "AVX2 Diffusion: {:?} for {} iterations ({} MB/s)",
            duration_simd,
            iterations,
            (iterations as f64 * 32.0) / 1024.0 / 1024.0 / duration_simd.as_secs_f64()
        );
    }

    println!("Benchmark complete.");
}
