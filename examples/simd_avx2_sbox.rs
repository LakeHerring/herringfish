#![allow(clippy::all, dead_code, unused_imports, unused_variables, unused_assignments)]
use std::arch::x86_64::*;
use std::time::Instant;

#[target_feature(enable = "avx2")]
unsafe fn diffusion_avx2(block: __m256i) -> __m256i {
    // Diffusion: out[i] = in[i] ^ in[i+1] ^ in[i+3]
    let a = block;
    let b = _mm256_alignr_epi8(a, a, 1);
    let c = _mm256_alignr_epi8(a, a, 3);
    _mm256_xor_si256(_mm256_xor_si256(a, b), c)
}

fn main() {
    if !is_x86_feature_detected!("avx2") {
        println!("AVX2 not supported");
        return;
    }
    
    const ITER: usize = 10_000_000;
    const BLOCKS: usize = ITER / 32;
    
    // Prepare input buffer
    let mut data = vec![0u8; ITER];
    for i in 0..ITER { data[i] = (i & 0xff) as u8; }
    
    // Scalar baseline
    let start = Instant::now();
    let mut acc = 0usize;
    for chunk in data.chunks(32) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            let b0 = chunk[i];
            let b1 = chunk[(i+1)%32];
            let b3 = chunk[(i+3)%32];
            out[i] = b0 ^ b1 ^ b3;
        }
        acc = acc.wrapping_add(out.iter().map(|&x| x as usize).sum::<usize>());
    }
    let dur_scalar = start.elapsed();
    
    // AVX2
    let start = Instant::now();
    let mut acc_avx = 0u64;
    unsafe {
        for chunk in data.chunks_exact(32) {
            let in_vec = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            let out_vec = diffusion_avx2(in_vec);
            let mut tmp = [0u8; 32];
            _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, out_vec);
            for b in tmp { acc_avx = acc_avx.wrapping_add(b as u64); }
        }
    }
    let dur_avx = start.elapsed();
    
    println!("AVX2 diffusion benchmark");
    println!("Blocks: {}", BLOCKS);
    println!("Scalar: {:?}  ({:.0} ops/s)", dur_scalar, BLOCKS as f64 / dur_scalar.as_secs_f64());
    println!("AVX2:   {:?}  ({:.0} ops/s)", dur_avx, BLOCKS as f64 / dur_avx.as_secs_f64());
    println!("Speedup: {:.2}x", dur_scalar.as_secs_f64() / dur_avx.as_secs_f64());
    println!("Checksum scalar: {}, avx: {}", acc, acc_avx);
}
