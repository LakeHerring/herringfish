use criterion::{Criterion, black_box, criterion_group, criterion_main};
use herringfish::cipher::feistel_arx::FeistelArx;
use std::arch::x86_64::*;

#[cfg(target_arch = "x86_64")]
unsafe fn avx2_diffusion_helper(data: &mut [u8]) {
    let mut i = 0;
    while i + 32 <= data.len() {
        let in_vec = unsafe { _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i) };
        let out_vec = herringfish::simd::avx2::diffusion_avx2(in_vec);
        unsafe {
            _mm256_storeu_si256(data.as_mut_ptr().add(i) as *mut __m256i, out_vec);
        }
        i += 32;
    }
}

fn bench_scalar_cipher(c: &mut Criterion) {
    let key = [0u8; 32];
    let cipher = FeistelArx::new(&key);
    let mut blocks: Vec<[u8; 16]> = Vec::with_capacity(1024);
    for i in 0..1024 {
        let mut b = [0u8; 16];
        for j in 0..16 {
            b[j] = ((i + j) & 0xff) as u8;
        }
        blocks.push(b);
    }
    c.bench_function("scalar_feistel_encrypt", |b| {
        b.iter(|| {
            let mut data = black_box(blocks.clone());
            for blk in &mut data {
                cipher.encrypt_block(blk);
            }
            black_box(data)
        })
    });
}

#[cfg(target_arch = "x86_64")]
fn bench_avx2_diffusion(c: &mut Criterion) {
    let mut data = vec![0u8; 1024 * 32];
    for i in 0..data.len() {
        data[i] = (i & 0xff) as u8;
    }
    c.bench_function("avx2_diffusion", |b| {
        b.iter(|| {
            let mut buf = black_box(data.clone());
            unsafe {
                avx2_diffusion_helper(&mut buf);
            }
            black_box(buf)
        })
    });
}

#[cfg(not(target_arch = "x86_64"))]
fn bench_avx2_diffusion(_c: &mut Criterion) {}

criterion_group!(benches, bench_scalar_cipher, bench_avx2_diffusion);
criterion_main!(benches);
