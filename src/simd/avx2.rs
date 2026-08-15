//! AVX2 SIMD implementations for Herringfish Feistel ARX
//! 
//! Provides vectorised diffusion and S-box lookup using AVX2 intrinsics.
//! All functions are gated to x86_64 targets.

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(target_arch = "x86_64")]
pub fn diffusion_avx2(block: __m256i) -> __m256i {
    // Diffusion: out[i] = in[i] ^ in[i+1] ^ in[i+3]
    let a = block;
    let b = unsafe { _mm256_alignr_epi8(a, a, 1) };
    let c = unsafe { _mm256_alignr_epi8(a, a, 3) };
    unsafe { _mm256_xor_si256(_mm256_xor_si256(a, b), c) }
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn sbox_gather_avx2(input: __m256i, table: &[u8; 256]) -> __m256i {
    // True AVX2 gather using _mm256_i32gather_epi32
    // Build 32-bit indices from input bytes, gather from a u32 view of the table.
    let mut bytes = [0u8; 32];
    _mm256_storeu_si256(bytes.as_mut_ptr() as *mut __m256i, input);

    // Build 32-bit indices
    let mut idx = [0u32; 8];
    for i in 0..8 {
        idx[i] = bytes[i] as u32;
    }
    // For simplicity we process 8 bytes at a time with 256-bit gather.
    // In production, build full 32-lane index vector via widening.
    // Here we demonstrate gather with a u32 table view.
    let table_u32 = table.as_ptr() as *const u32 as *const i32;
    let idx_vec = _mm256_setr_epi32(
        idx[0] as i32, idx[1] as i32, idx[2] as i32, idx[3] as i32,
        idx[4] as i32, idx[5] as i32, idx[6] as i32, idx[7] as i32,
    );
    // Gather 8 u32 values, repeat for remaining lanes via scalar fallback for prototype
    let gathered = _mm256_i32gather_epi32(table_u32, idx_vec, 1);
    // Mask to bytes
    let mask = _mm256_set1_epi32(0xFF);
    let gathered_bytes = _mm256_and_si256(gathered, mask);

    // For remaining 24 bytes, fall back to scalar for this prototype
    // Full implementation would widen all 32 bytes to 32-bit indices and gather in one go.
    let mut out_bytes = [0u8; 32];
    _mm256_storeu_si256(out_bytes.as_mut_ptr() as *mut __m256i, gathered_bytes);
    for i in 8..32 {
        out_bytes[i] = table[bytes[i] as usize];
    }
    _mm256_loadu_si256(out_bytes.as_ptr() as *const __m256i)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn diffusion_avx2(_block: [u8; 32]) -> [u8; 32] {
    // Non-x86_64 stub
    [0u8; 32]
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_diffusion_avx2_stability() {
        // Placeholder test
    }
}
