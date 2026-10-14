//! AVX2 SIMD batch encryption for Herringfish Feistel ARX
//!
//! Processes 4 blocks (4 × 128-bit) in parallel using 256-bit lanes.
//! Each lane holds one 64-bit half of a block; a 256-bit register
//! holds two halves of two blocks.
//!
//! The S-box is applied via a gather from a 256-entry table.
//! Diffusion is a series of XOR + alignr operations.
//!
//! WARNING: Experimental. Not for production use. Must be verified
//! against the scalar reference implementation.

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(target_arch = "x86_64")]
use crate::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

/// Encrypt `n` blocks in parallel using AVX2.
///
/// `blocks` contains `n` 16-byte blocks in a flat buffer.
/// Must be called on a CPU with AVX2 support.
///
/// # Safety
/// Caller must ensure AVX2 is available and `blocks` is properly aligned
/// (or use the safe wrapper).
#[cfg(target_arch = "x86_64")]
pub unsafe fn encrypt_blocks_avx2_unchecked(blocks: &mut [[u8; 16]], round_keys: &[u64]) {
    unsafe {
        let n = blocks.len();

        // Process 4 blocks per iteration
        for chunk_start in (0..n).step_by(4) {
            let chunk_end = (chunk_start + 4).min(n);
            let chunk = &mut blocks[chunk_start..chunk_end];
            let count = chunk.len();

            // Load blocks into lanes.
            // Each block is (L, R) where L = bytes[0..8], R = bytes[8..16].
            // We pack: lane_low  = L of block 0 | L of block 1 (two u64s)
            //          lane_high = R of block 0 | R of block 1 (two u64s)
            //
            // Actually, for 4 blocks we use two 256-bit registers per half:
            //   reg_L01 = [L0, L1] (two u64 in 128-bit lane 0)
            //   reg_R01 = [R0, R1]
            //   reg_L23 = [L2, L3]
            //   reg_R23 = [R2, R3]
            //
            // But AVX2 256-bit = 4 × u64. So:
            //   L_reg = [L0, L1, L2, L3]
            //   R_reg = [R0, R1, R2, R3]

            let mut l = [0u64; 4];
            let mut r = [0u64; 4];

            for (i, block) in chunk.iter().enumerate().take(count) {
                l[i] = u64::from_le_bytes(block[..8].try_into().unwrap());
                r[i] = u64::from_le_bytes(block[8..16].try_into().unwrap());
            }

            let mut l_vec = _mm256_setr_epi64x(l[0] as i64, l[1] as i64, l[2] as i64, l[3] as i64);
            let mut r_vec = _mm256_setr_epi64x(r[0] as i64, r[1] as i64, r[2] as i64, r[3] as i64);

            // Apply Feistel rounds
            for &rk in round_keys {
                let rk_vec = _mm256_set1_epi64x(rk as i64);

                // F(R) = diffuse(sbox_layer(R ^ rk))
                let r_xor_k = _mm256_xor_si256(r_vec, rk_vec);
                let sbox_out = sbox_layer_avx2(r_xor_k);
                let diffused = diffuse_avx2(sbox_out);

                // L' = R, R' = L ^ F(R)
                let new_l = r_vec;
                let new_r = _mm256_xor_si256(l_vec, diffused);

                l_vec = new_l;
                r_vec = new_r;
            }

            // Store back — extract two 128-bit halves from each 256-bit register
            let mut l0: [i64; 2] = std::mem::zeroed();
            let mut l1: [i64; 2] = std::mem::zeroed();
            let mut r0: [i64; 2] = std::mem::zeroed();
            let mut r1: [i64; 2] = std::mem::zeroed();

            _mm_store_si128(
                l0.as_mut_ptr() as *mut __m128i,
                _mm256_castsi256_si128(l_vec),
            );
            _mm_store_si128(
                l1.as_mut_ptr() as *mut __m128i,
                _mm256_castsi256_si128(_mm256_permute2x128_si256(l_vec, l_vec, 1)),
            );
            _mm_store_si128(
                r0.as_mut_ptr() as *mut __m128i,
                _mm256_castsi256_si128(r_vec),
            );
            _mm_store_si128(
                r1.as_mut_ptr() as *mut __m128i,
                _mm256_castsi256_si128(_mm256_permute2x128_si256(r_vec, r_vec, 1)),
            );

            let l_vals = [l0[0] as u64, l0[1] as u64, l1[0] as u64, l1[1] as u64];
            let r_vals = [r0[0] as u64, r0[1] as u64, r1[0] as u64, r1[1] as u64];
            for (i, out_block) in chunk.iter_mut().enumerate() {
                out_block[..8].copy_from_slice(&l_vals[i].to_le_bytes());
                out_block[8..16].copy_from_slice(&r_vals[i].to_le_bytes());
            }
        }
    }
}

/// S-box layer on a 256-bit register: each 8-bit lane is looked up
/// in the S-box table via gather.
///
/// # Safety
/// Caller must ensure the CPU supports AVX2 (see [`avx2_available`]).
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn sbox_layer_avx2(input: __m256i) -> __m256i {
    // Store to temp, gather byte-by-byte from S-box table
    let mut in_bytes = [0u8; 32];
    unsafe {
        _mm256_storeu_si256(in_bytes.as_mut_ptr() as *mut __m256i, input);
    }

    let mut out_bytes = [0u8; 32];
    for i in 0..32 {
        out_bytes[i] = HERRINGFISH_SBOX_V02[in_bytes[i] as usize];
    }

    unsafe { _mm256_loadu_si256(out_bytes.as_ptr() as *const __m256i) }
}

/// Diffusion: out[i] = in[i] ^ in[(i+1)%8] ^ in[(i+3)%8]
/// Applied independently to each 64-bit lane (8 bytes).
///
/// The S-box layer is already scalar (store→loop→load), so diffusion
/// follows the same pattern. The SIMD benefit is in the parallel XOR
/// operations in the Feistel round loop.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn diffuse_avx2(block: __m256i) -> __m256i {
    unsafe {
        let mut tmp = [0u8; 32];
        _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, block);
        for lane in 0..4 {
            let base = lane * 8;
            let b0 = tmp[base];
            let b1 = tmp[base + 1];
            let b2 = tmp[base + 2];
            let b3 = tmp[base + 3];
            let b4 = tmp[base + 4];
            let b5 = tmp[base + 5];
            let b6 = tmp[base + 6];
            let b7 = tmp[base + 7];
            tmp[base] = b0 ^ b1 ^ b3;
            tmp[base + 1] = b1 ^ b2 ^ b4;
            tmp[base + 2] = b2 ^ b3 ^ b5;
            tmp[base + 3] = b3 ^ b4 ^ b6;
            tmp[base + 4] = b4 ^ b5 ^ b7;
            tmp[base + 5] = b5 ^ b6 ^ b0;
            tmp[base + 6] = b6 ^ b7 ^ b1;
            tmp[base + 7] = b7 ^ b0 ^ b2;
        }
        _mm256_loadu_si256(tmp.as_ptr() as *const __m256i)
    }
}

/// Check if the current CPU supports AVX2.
#[cfg(target_arch = "x86_64")]
pub fn avx2_available() -> bool {
    is_x86_feature_detected!("avx2")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn avx2_available() -> bool {
    false
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use super::*;
    use crate::cipher::feistel_arx::FeistelArx;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_matches_scalar() {
        // Test that AVX2 batch encrypt matches scalar encrypt
        let key = [0x42u8; 32];
        let cipher = FeistelArx::new(&key);
        let round_keys: Vec<u64> = cipher.round_keys().to_vec();

        // Test with 4 blocks
        let mut blocks = [[0u8; 16]; 4];
        for (i, block) in blocks.iter_mut().enumerate() {
            for (j, byte) in block.iter_mut().enumerate() {
                *byte = (i * 16 + j) as u8;
            }
        }

        // Scalar reference
        let mut scalar_blocks = blocks;
        for block in &mut scalar_blocks {
            cipher.encrypt_block(block);
        }

        // AVX2
        let mut avx2_blocks = blocks;
        unsafe { encrypt_blocks_avx2_unchecked(&mut avx2_blocks, &round_keys) };

        assert_eq!(
            scalar_blocks, avx2_blocks,
            "AVX2 batch encrypt does not match scalar"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_diffusion_matches_scalar() {
        use crate::cipher::feistel_arx::diffuse;

        // Test diffusion on a known value
        let test_val = 0xDEADBEEFCAFEBABE_u64;
        let scalar_result = diffuse(test_val);

        let mut bytes = [0u8; 32];
        let val_bytes = test_val.to_le_bytes();
        bytes[..8].copy_from_slice(&val_bytes);
        bytes[8..16].copy_from_slice(&val_bytes);

        let input = unsafe { _mm256_loadu_si256(bytes.as_ptr() as *const __m256i) };
        let output = diffuse_avx2(input);

        let mut out_bytes = [0u8; 32];
        unsafe { _mm256_storeu_si256(out_bytes.as_mut_ptr() as *mut __m256i, output) };

        let result_lo = u64::from_le_bytes(out_bytes[..8].try_into().unwrap());
        assert_eq!(result_lo, scalar_result, "AVX2 diffusion mismatch");
    }

    #[test]
    fn non_x86_stub() {
        // On non-x86_64, just verify the module compiles
    }
}
