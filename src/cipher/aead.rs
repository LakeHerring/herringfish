//! AEAD mode for Herringfish Feistel ARX
//!
//! Provides authenticated encryption using CTR mode for confidentiality
//! and GHASH for integrity/authenticity, following the NIST SP 800-38D
//! structure.
//!
//! Parameters:
//!   - Block size: 128 bits
//!   - Key: 256 bits
//!   - Nonce: 96 bits (12 bytes)
//!   - Tag: 128 bits (16 bytes)
//!   - AAD: arbitrary length
//!
//! WARNING: Experimental. Not for production use. No independent
//! verification of the GHASH implementation has been performed.

use crate::cipher::feistel_arx::FeistelArx;

/// Tag size in bytes (128 bits).
pub const TAG_SIZE: usize = 16;
/// Nonce size in bytes (96 bits).
pub const NONCE_SIZE: usize = 12;

/// AEAD mode built on Herringfish Feistel ARX.
///
/// Uses CTR mode for encryption and GHASH for authentication.
/// The GHASH hash subkey H is E_K(0^128) (the cipher applied to a
/// zero block).
pub struct HerringfishAead {
    cipher: FeistelArx,
    h: [u8; 16], // GHASH hash subkey
}

impl HerringfishAead {
    /// Create a new AEAD instance from a 256-bit key.
    ///
    /// The cipher is set up with the full 16-round configuration.
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = FeistelArx::new(key);
        // H = E_K(0^128)
        let zero = [0u8; 16];
        let mut h = zero;
        cipher.encrypt_block(&mut h);
        Self { cipher, h }
    }

    /// Create an AEAD instance with a custom round count (for research).
    pub fn new_with_rounds(key: &[u8; 32], rounds: usize) -> Self {
        let cipher = FeistelArx::new_with_rounds(key, rounds);
        let zero = [0u8; 16];
        let mut h = zero;
        cipher.encrypt_block(&mut h);
        Self { cipher, h }
    }

    /// Encrypt plaintext with associated data.
    ///
    /// Returns (ciphertext, tag). Ciphertext is same length as plaintext.
    /// Tag is 16 bytes.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; TAG_SIZE]) {
        // 1. CTR encryption
        let ciphertext = self.ctr_encrypt(nonce, plaintext);

        // 2. GHASH over AAD || ciphertext
        let tag = self.ghash(nonce, aad, &ciphertext);

        (ciphertext, tag)
    }

    /// Decrypt ciphertext with associated data and verify the tag.
    ///
    /// Returns the plaintext if the tag is valid, or an error if
    /// authentication fails.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<Vec<u8>, AeadError> {
        // 1. Verify tag (constant-time comparison)
        let expected = self.ghash(nonce, aad, ciphertext);
        if !constant_time_eq(tag, &expected) {
            return Err(AeadError::TagMismatch);
        }

        // 2. CTR decryption (same as encryption for CTR)
        Ok(self.ctr_encrypt(nonce, ciphertext))
    }

    // ----------------------------------------------------------
    // CTR mode
    // ----------------------------------------------------------

    /// Generate CTR keystream and XOR with input.
    fn ctr_encrypt(&self, nonce: &[u8; NONCE_SIZE], data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        for (i, chunk) in data.chunks(16).enumerate() {
            let mut cb = [0u8; 16];
            // Counter block: nonce (12 bytes) || counter (4 bytes, big-endian)
            cb[..12].copy_from_slice(nonce);
            cb[12..16].copy_from_slice(&(i as u32 + 1).to_be_bytes());

            let mut keystream = cb;
            self.cipher.encrypt_block(&mut keystream);

            for (j, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ keystream[j]);
            }
        }

        output
    }

    /// Build the J0 block: nonce || 0x00000001
    fn build_counter_block(&self, nonce: &[u8; NONCE_SIZE], _data: &[u8]) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;
        j0
    }

    // ----------------------------------------------------------
    // GHASH
    // ----------------------------------------------------------

    /// Compute the GHASH tag:
    ///   S_0 = 0
    ///   S_i = (S_{i-1} XOR X_i) * H   (in GF(2^128))
    ///   tag = S_N XOR E_K(J0)
    ///
    /// where X_1 = AAD || pad0, X_2 = ciphertext || pad0,
    /// X_3 = 64-bit length(AAD) || 64-bit length(ciphertext)
    /// (all lengths in bits, big-endian)
    fn ghash(&self, nonce: &[u8; NONCE_SIZE], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_SIZE] {
        let mut s = [0u8; 16];

        // Process AAD
        s = self.ghash_blocks(&mut s, aad);

        // Process ciphertext
        s = self.ghash_blocks(&mut s, ciphertext);

        // Length block: 64-bit len(AAD) || 64-bit len(ct) (in bits, big-endian)
        let aad_bits = (aad.len() as u64) * 8;
        let ct_bits = (ciphertext.len() as u64) * 8;
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
        len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());
        s = self.ghash_block(&s, &len_block);

        // tag = S_N XOR E_K(J0)
        let j0 = self.build_counter_block(nonce, &[]);
        let mut ej0 = j0;
        self.cipher.encrypt_block(&mut ej0);

        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s[i] ^ ej0[i];
        }
        tag
    }

    /// Process full 16-byte blocks + final partial block.
    fn ghash_blocks(&self, s: &mut [u8; 16], data: &[u8]) -> [u8; 16] {
        let mut s_local = *s;
        let full_blocks = data.len() / 16;
        let remainder = data.len() % 16;

        for i in 0..full_blocks {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[i * 16..(i + 1) * 16]);
            s_local = self.ghash_block(&s_local, &block);
        }

        if remainder > 0 {
            let mut padded = [0u8; 16];
            padded[..remainder].copy_from_slice(&data[full_blocks * 16..]);
            s_local = self.ghash_block(&s_local, &padded);
        }

        s_local
    }

    /// Single GHASH block: S = (S XOR X) * H
    fn ghash_block(&self, s: &[u8; 16], x: &[u8; 16]) -> [u8; 16] {
        // S XOR X
        let mut acc = [0u8; 16];
        for i in 0..16 {
            acc[i] = s[i] ^ x[i];
        }
        // Multiply by H in GF(2^128)
        gf2_128_multiply(&acc, &self.h)
    }
}

// ============================================================
// GF(2^128) multiplication (NIST SP 800-38D §5.2)
// ============================================================
//
// The reduction polynomial is x^128 + x^7 + x^2 + x + 1.
// The bit ordering is as specified in NIST SP 800-38D:
//   x^i is bit 127-i (big-endian bit order, MSB first).
//
// The right-shift with conditional XOR (R = 11100000...0 = 0xE0)
// implements multiplication by x^128 mod P.

/// Multiply two 128-bit values in GF(2^128).
///
/// Uses the classic xtime algorithm with the reduction polynomial
/// x^128 + x^7 + x^2 + x + 1 (NIST SP 800-38D).
///
/// Bit representation: byte[0] is the most significant byte,
/// bit 7 of byte[0] is x^0 (the least significant bit of the
/// polynomial representation).
///
/// Algorithm:
///   z = 0
///   for each byte i of a (LSB byte first, i.e. a[15] down to a[0]):
///     for each bit b of that byte (0..7):
///       if bit is set: z ^= v
///       v = xtime(v)
fn gf2_128_multiply(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *b;

    for i in (0..16).rev() {
        for bit in 0..8u8 {
            if (a[i] >> bit) & 1 == 1 {
                for j in 0..16 {
                    z[j] ^= v[j];
                }
            }
            v = xtime(&v);
        }
    }

    z
}

/// Multiply by x in GF(2^128): left-shift by 1, conditionally XOR 0x87.
///
/// xtime(v) = (v << 1) XOR (0x87 if LSB was set)
/// where the shift is left (toward higher polynomial degrees) and
/// 0x87 represents the reduction polynomial x^7 + x^2 + x + 1.
#[inline]
fn xtime(v: &[u8; 16]) -> [u8; 16] {
    let lsb = v[15] & 1;
    let mut result = [0u8; 16];
    for i in 0..15 {
        result[i] = (v[i] << 1) | (v[i + 1] >> 7);
    }
    result[15] = v[15] << 1;
    if lsb != 0 {
        result[0] ^= 0x87;
    }
    result
}

// ============================================================
// Constant-time comparison
// ============================================================

/// Constant-time byte array comparison (returns true if equal).
fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ============================================================
// Error type
// ============================================================

/// Error returned when AEAD decryption fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// The authentication tag does not match (tampering detected).
    TagMismatch,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AeadError::TagMismatch => write!(f, "authentication tag mismatch"),
        }
    }
}

impl std::error::Error for AeadError {}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf2_128_multiply_zero() {
        let zero = [0u8; 16];
        let a = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22,
            0x33, 0x44,
        ];
        assert_eq!(gf2_128_multiply(&a, &zero), zero);
    }

    #[test]
    fn gf2_128_multiply_deterministic() {
        let a = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22,
            0x33, 0x44,
        ];
        let b = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let r1 = gf2_128_multiply(&a, &b);
        let r2 = gf2_128_multiply(&a, &b);
        assert_eq!(r1, r2);
    }

    #[test]
    fn gf2_128_multiply_nonzero() {
        // Non-zero * non-zero should be non-zero.
        // In our bit model, 0x01 in byte[15] = x^127 (highest degree).
        let mut a = [0u8; 16];
        a[15] = 1; // x^127
        let mut b = [0u8; 16];
        b[15] = 1; // x^127
        let result = gf2_128_multiply(&a, &b);
        // x^127 * x^127 = x^254 mod P, which is non-zero
        assert_ne!(result, [0u8; 16]);
    }

    #[test]
    fn gf2_128_multiply_commutative() {
        let a = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let b = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        assert_eq!(gf2_128_multiply(&a, &b), gf2_128_multiply(&b, &a));
    }

    #[test]
    fn aead_roundtrip_empty() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let aead = HerringfishAead::new(&key);

        let (ct, tag) = aead.encrypt(&nonce, b"", b"");
        assert_eq!(ct.len(), 0);

        let pt = aead.decrypt(&nonce, b"", &ct, &tag).unwrap();
        assert_eq!(pt, b"");
    }

    #[test]
    fn aead_roundtrip_short() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let aead = HerringfishAead::new(&key);

        let pt = b"Hello, Herringfish!";
        let aad = b"header";
        let (ct, tag) = aead.encrypt(&nonce, aad, pt);

        assert_eq!(ct.len(), pt.len());
        // Ciphertext should differ from plaintext
        assert_ne!(&ct[..4], &pt[..4]);

        let decrypted = aead.decrypt(&nonce, aad, &ct, &tag).unwrap();
        assert_eq!(&decrypted, pt);
    }

    #[test]
    fn aead_roundtrip_long() {
        let key = [3u8; 32];
        let nonce = [4u8; 12];
        let aead = HerringfishAead::new(&key);

        let pt: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        let aad: Vec<u8> = (0..100u32).map(|i| (i % 13) as u8).collect();
        let (ct, tag) = aead.encrypt(&nonce, &aad, &pt);

        assert_eq!(ct.len(), pt.len());
        let decrypted = aead.decrypt(&nonce, &aad, &ct, &tag).unwrap();
        assert_eq!(&decrypted, &pt);
    }

    #[test]
    fn aead_tamper_detection_ct() {
        let key = [5u8; 32];
        let nonce = [6u8; 12];
        let aead = HerringfishAead::new(&key);

        let pt = b"secret message";
        let (mut ct, tag) = aead.encrypt(&nonce, b"", pt);
        ct[0] ^= 0xFF; // tamper with ciphertext

        assert!(aead.decrypt(&nonce, b"", &ct, &tag).is_err());
    }

    #[test]
    fn aead_tamper_detection_aad() {
        let key = [7u8; 32];
        let nonce = [8u8; 12];
        let aead = HerringfishAead::new(&key);

        let pt = b"message";
        let (ct, tag) = aead.encrypt(&nonce, b"original-aad", pt);

        // Tamper with AAD
        assert!(aead.decrypt(&nonce, b"tampered-aad", &ct, &tag).is_err());
    }

    #[test]
    fn aead_tamper_detection_tag() {
        let key = [9u8; 32];
        let nonce = [10u8; 12];
        let aead = HerringfishAead::new(&key);

        let pt = b"message";
        let (ct, mut tag) = aead.encrypt(&nonce, b"", pt);
        tag[0] ^= 0x01; // tamper with tag

        assert!(aead.decrypt(&nonce, b"", &ct, &tag).is_err());
    }

    #[test]
    fn aead_different_nonce_different_ct() {
        let key = [11u8; 32];
        let aead = HerringfishAead::new(&key);
        let pt = b"same plaintext";

        let (ct1, _) = aead.encrypt(&[0u8; 12], b"", pt);
        let (ct2, _) = aead.encrypt(&[1u8; 12], b"", pt);

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn aead_partial_block() {
        // Test with ciphertext not a multiple of 16
        let key = [13u8; 32];
        let nonce = [14u8; 12];
        let aead = HerringfishAead::new(&key);

        for len in 1..40 {
            let pt = vec![len as u8; len];
            let (ct, tag) = aead.encrypt(&nonce, b"", &pt);
            assert_eq!(ct.len(), len);
            let decrypted = aead.decrypt(&nonce, b"", &ct, &tag).unwrap();
            assert_eq!(&decrypted, &pt, "failed at len={}", len);
        }
    }

    #[test]
    fn aead_deterministic() {
        let key = [15u8; 32];
        let nonce = [16u8; 12];
        let aead = HerringfishAead::new(&key);

        let (ct1, tag1) = aead.encrypt(&nonce, b"aad", b"data");
        let (ct2, tag2) = aead.encrypt(&nonce, b"aad", b"data");
        assert_eq!(ct1, ct2);
        assert_eq!(tag1, tag2);
    }
}
