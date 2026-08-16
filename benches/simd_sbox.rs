use criterion::{Criterion, black_box, criterion_group, criterion_main};
use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

fn bench_scalar_sbox(c: &mut Criterion) {
    let table = HERRINGFISH_SBOX_V02;
    let data: Vec<u8> = (0..1024).map(|i| (i & 0xff) as u8).collect();
    c.bench_function("scalar_sbox", |b| {
        b.iter(|| {
            let mut out = [0u8; 1024];
            for i in 0..1024 {
                out[i] = table[data[i] as usize];
            }
            black_box(out);
        })
    });
}

#[cfg(target_arch = "x86_64")]
unsafe fn avx2_sbox_gather(data: &[u8], table: &[u8; 256], out: &mut [u8]) {
    unsafe {
        let mut i = 0;
        while i + 32 <= data.len() {
            let input_vec = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
            // Prototype gather using src/simd/avx2
            let gathered = herringfish::simd::avx2::sbox_gather_avx2(input_vec, table);
            _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, gathered);
            i += 32;
        }
        for j in i..data.len() {
            out[j] = table[data[j] as usize];
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn bench_avx2_sbox(c: &mut Criterion) {
    let table = HERRINGFISH_SBOX_V02;
    let data: Vec<u8> = (0..1024).map(|i| (i & 0xff) as u8).collect();
    let mut out = vec![0u8; 1024];
    c.bench_function("avx2_sbox_gather", |b| {
        b.iter(|| {
            unsafe {
                avx2_sbox_gather(&data, &table, &mut out);
            }
            black_box(&out);
        })
    });
}

#[cfg(not(target_arch = "x86_64"))]
fn bench_avx2_sbox(_c: &mut Criterion) {}

criterion_group!(benches, bench_scalar_sbox, bench_avx2_sbox);
criterion_main!(benches);
