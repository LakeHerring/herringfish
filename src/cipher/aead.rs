//! AEAD mode for Herringfish Feistel ARX (solo-arx)
//!
//! CTR-mode encryption plus GHASH authentication, following the structure
//! of NIST SP 800-38D (GCM) with the Herringfish block cipher in place of
//! AES. The normative definition is
//! `docs/specification/solo_arx_aead_v0.1.md`.
//!
//! Parameters:
//!   - Block size: 128 bits
//!   - Key: 256 bits
//!   - Nonce: 96 bits (12 bytes)
//!   - Tag: 128 bits (16 bytes)
//!   - AAD: arbitrary length below 2^61 bytes
//!   - Plaintext: at most 2^32 - 2 blocks
//!
//! WARNING: Experimental. Not for production use. The GHASH component is
//! tested against independent vectors; the security of the mode as a whole
//! has not been analysed.

use crate::cipher::feistel_arx::FeistelArx;

/// Tag size in bytes (128 bits).
pub const TAG_SIZE: usize = 16;
/// Nonce size in bytes (96 bits).
pub const NONCE_SIZE: usize = 12;

/// Maximum data blocks per message: counters 2 ..= 2^32 - 1 (spec §5).
const MAX_DATA_BLOCKS: u64 = (1 << 32) - 2;
/// AAD must be strictly shorter than this many bytes (spec §5).
const MAX_AAD_BYTES: u64 = 1 << 61;

/// Whether the lengths are within the limits of spec §5.
fn lengths_ok(aad_len: u64, data_len: u64) -> bool {
    aad_len < MAX_AAD_BYTES && data_len.div_ceil(16) <= MAX_DATA_BLOCKS
}

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
        Self::from_cipher(FeistelArx::new(key))
    }

    /// Create an AEAD instance with a custom round count (for research).
    pub fn new_with_rounds(key: &[u8; 32], rounds: usize) -> Self {
        Self::from_cipher(FeistelArx::new_with_rounds(key, rounds))
    }

    fn from_cipher(cipher: FeistelArx) -> Self {
        // H = E_K(0^128)
        let mut h = [0u8; 16];
        cipher.encrypt_block(&mut h);
        Self { cipher, h }
    }

    /// Encrypt plaintext with associated data.
    ///
    /// Returns (ciphertext, tag). Ciphertext is same length as plaintext.
    /// Tag is 16 bytes.
    ///
    /// # Panics
    ///
    /// Panics if `plaintext` is longer than 16 * (2^32 - 2) bytes or `aad`
    /// is 2^61 bytes or longer (spec §5); the CTR counter would otherwise
    /// wrap.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; TAG_SIZE]) {
        assert!(
            lengths_ok(aad.len() as u64, plaintext.len() as u64),
            "AEAD input exceeds mode limits (spec §5)"
        );

        // 1. CTR encryption
        let ciphertext = self.ctr_encrypt(nonce, plaintext);

        // 2. T = GHASH_H(A, C) XOR E_K(J0)
        let tag = self.compute_tag(nonce, aad, &ciphertext);

        (ciphertext, tag)
    }

    /// Decrypt ciphertext with associated data and verify the tag.
    ///
    /// Returns the plaintext if the tag is valid, or an error if
    /// authentication fails or the input exceeds the mode limits.
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_SIZE],
    ) -> Result<Vec<u8>, AeadError> {
        if !lengths_ok(aad.len() as u64, ciphertext.len() as u64) {
            return Err(AeadError::InputTooLong);
        }

        // 1. Verify tag (constant-time comparison)
        let expected = self.compute_tag(nonce, aad, ciphertext);
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
    ///
    /// Data block `i` uses counter block `nonce || [i + 2]_32`, so the
    /// counters start at inc32(J0) and never equal J0's counter (1).
    /// Callers must have checked `lengths_ok`, which keeps `i + 2` within
    /// `u32`.
    fn ctr_encrypt(&self, nonce: &[u8; NONCE_SIZE], data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        for (i, chunk) in data.chunks(16).enumerate() {
            let mut keystream = counter_block(nonce, i as u32 + 2);
            self.cipher.encrypt_block(&mut keystream);

            for (j, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ keystream[j]);
            }
        }

        output
    }

    /// T = GHASH_H(A, C) XOR E_K(J0)
    fn compute_tag(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> [u8; TAG_SIZE] {
        let s = ghash(&self.h, aad, ciphertext);

        let mut ej0 = j0(nonce);
        self.cipher.encrypt_block(&mut ej0);

        let mut tag = [0u8; TAG_SIZE];
        for i in 0..16 {
            tag[i] = s[i] ^ ej0[i];
        }
        tag
    }
}

/// Counter block: nonce (12 bytes) || counter (4 bytes, big-endian).
fn counter_block(nonce: &[u8; NONCE_SIZE], counter: u32) -> [u8; 16] {
    let mut cb = [0u8; 16];
    cb[..12].copy_from_slice(nonce);
    cb[12..].copy_from_slice(&counter.to_be_bytes());
    cb
}

/// J0 = nonce || 0x00000001 (96-bit nonce case of NIST SP 800-38D §7.1).
fn j0(nonce: &[u8; NONCE_SIZE]) -> [u8; 16] {
    counter_block(nonce, 1)
}

// ============================================================
// GHASH (NIST SP 800-38D §6.4)
// ============================================================

/// GHASH_H(A, C): the hash of spec §4, a pure function of (H, A, C).
///
///   Y_0 = 0
///   Y_i = (Y_{i-1} XOR X_i) * H
///
/// over A || pad0 || C || pad0 || [8*len(A)]_64 || [8*len(C)]_64.
fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    for data in [aad, ciphertext] {
        for chunk in data.chunks(16) {
            let mut x = [0u8; 16]; // zero-padded final block
            x[..chunk.len()].copy_from_slice(chunk);
            y = ghash_step(&y, &x, h);
        }
    }

    // Length block: bit lengths, big-endian (lengths are < 2^61 bytes).
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    ghash_step(&y, &len_block, h)
}

/// One GHASH step: (Y XOR X) * H.
fn ghash_step(y: &[u8; 16], x: &[u8; 16], h: &[u8; 16]) -> [u8; 16] {
    let mut acc = [0u8; 16];
    for i in 0..16 {
        acc[i] = y[i] ^ x[i];
    }
    gf2_128_multiply(&acc, h)
}

// ============================================================
// GF(2^128) multiplication (NIST SP 800-38D §6.3, Algorithm 1)
// ============================================================

/// R = 0xE1 || 0^120, the reduction constant of Algorithm 1.
const R: u128 = 0xE1 << 120;

/// Multiply two elements of GF(2^128) = GF(2)[x] / (x^128 + x^7 + x^2 + x + 1).
///
/// Bit order is NIST's: the coefficient of x^i is bit x_i, where x_0 is
/// the most significant bit of byte 0 and x_127 the least significant bit
/// of byte 15. As a big-endian integer, x_i is integer bit 127 - i.
///
/// Branch-free: both conditionals of Algorithm 1 are done with masks, so
/// neither operand influences control flow.
fn gf2_128_multiply(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let x = u128::from_be_bytes(*x);
    let mut v = u128::from_be_bytes(*y);
    let mut z = 0u128;

    for i in 0..128 {
        // if x_i == 1 { z ^= v }
        let xi = (x >> (127 - i)) & 1;
        z ^= v & xi.wrapping_neg();

        // v = (v >> 1) ^ (R if LSB(v) == 1)
        let lsb = v & 1;
        v = (v >> 1) ^ (R & lsb.wrapping_neg());
    }

    z.to_be_bytes()
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
    /// Input exceeds the mode limits (spec §5).
    InputTooLong,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AeadError::TagMismatch => write!(f, "authentication tag mismatch"),
            AeadError::InputTooLong => write!(f, "input exceeds AEAD mode limits"),
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
        // In NIST bit order, 0x01 in byte[15] = x^127 (highest degree).
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

    /// x^127 * x^1 = x^128 = x^7 + x^2 + x + 1, which in NIST bit order is
    /// 0xE1 || 0^120 (the constant R of Algorithm 1).
    #[test]
    fn gf2_128_reduction_constant() {
        let mut x127 = [0u8; 16];
        x127[15] = 0x01;
        let mut x1 = [0u8; 16];
        x1[0] = 0x40;
        let mut want = [0u8; 16];
        want[0] = 0xE1;
        assert_eq!(gf2_128_multiply(&x127, &x1), want);
    }

    /// Field axioms on deterministic pseudo-random elements (fixed LCG
    /// seed): identity is 0x80 || 0^120 (the polynomial 1), and the product
    /// is associative and distributes over XOR. The pre-solo-arx-AEAD
    /// multiply failed associativity in about half of random triples.
    #[test]
    fn gf2_128_field_axioms() {
        let mut one = [0u8; 16];
        one[0] = 0x80;

        let mut s: u64 = 0x2F6E_2B1D_9A37_C415;
        let mut next = || {
            let mut b = [0u8; 16];
            for byte in b.iter_mut() {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = (s >> 33) as u8;
            }
            b
        };
        let xor = |a: &[u8; 16], b: &[u8; 16]| {
            let mut o = [0u8; 16];
            for i in 0..16 {
                o[i] = a[i] ^ b[i];
            }
            o
        };

        for _ in 0..200 {
            let (a, b, c) = (next(), next(), next());
            assert_eq!(gf2_128_multiply(&one, &a), a);
            let ab = gf2_128_multiply(&a, &b);
            assert_eq!(
                gf2_128_multiply(&ab, &c),
                gf2_128_multiply(&a, &gf2_128_multiply(&b, &c))
            );
            assert_eq!(
                gf2_128_multiply(&a, &xor(&b, &c)),
                xor(&gf2_128_multiply(&a, &b), &gf2_128_multiply(&a, &c))
            );
        }
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

    // ============================================================
    // Counter layout regression (spec §5)
    // ============================================================

    /// Regression: bca2397 (and the following working-tree variant) used
    /// the same counter block for keystream block 0 and the tag mask
    /// E_K(J0). Data counters must start at 2 and never reach J0's 1.
    #[test]
    fn ctr_never_uses_j0_counter() {
        let aead = HerringfishAead::new(&[0x5Au8; 32]);
        let nonce = [0xA5u8; 12];

        let mut ej0 = j0(&nonce);
        aead.cipher.encrypt_block(&mut ej0);
        assert_eq!(&j0(&nonce)[12..], &[0, 0, 0, 1]);

        // Encrypting zeros exposes the keystream directly.
        let blocks = 64;
        let (ks, _) = aead.encrypt(&nonce, b"", &vec![0u8; 16 * blocks]);

        for (i, chunk) in ks.chunks(16).enumerate() {
            assert_ne!(chunk, &ej0[..], "keystream block {i} equals E_K(J0)");

            // Block i is exactly E_K(nonce || [i + 2]_32).
            let mut want = counter_block(&nonce, i as u32 + 2);
            aead.cipher.encrypt_block(&mut want);
            assert_eq!(chunk, &want[..], "keystream block {i} counter layout");
        }
    }

    /// Spec §5 limits: 2^32 - 2 data blocks, AAD below 2^61 bytes. The
    /// boundary is tested arithmetically; a 64 GiB message is not built.
    #[test]
    fn length_limits() {
        let max_bytes = 16 * MAX_DATA_BLOCKS;

        assert!(lengths_ok(0, 0));
        assert!(lengths_ok(0, max_bytes));
        assert!(lengths_ok(0, max_bytes - 15)); // partial last block still fits
        assert!(!lengths_ok(0, max_bytes + 1)); // one byte opens block 2^32 - 1
        assert!(lengths_ok(MAX_AAD_BYTES - 1, 0));
        assert!(!lengths_ok(MAX_AAD_BYTES, 0));

        // The last allowed block (index MAX - 1) gets counter u32::MAX.
        assert_eq!(MAX_DATA_BLOCKS - 1 + 2, u64::from(u32::MAX));
    }

    // ============================================================
    // GHASH known-answer tests (cipher-independent: H is an input)
    // ============================================================

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn hex16(s: &str) -> [u8; 16] {
        hex(s).try_into().unwrap()
    }

    /// McGrew & Viega, "The Galois/Counter Mode of Operation", Test Case 2:
    /// K = 0^128, so H = AES_K(0) = 66e94bd4ef8a2c3b884cfa59ca342b2e;
    /// A empty, C = 0388dace60b6a392f328c2b971b2fe78.
    /// GHASH = tag ^ AES_K(Y0)
    ///       = ab6e47d42cec13bdf53a67b21257bddf ^ 58e2fccefa7e3061367f1d57a4e7455a.
    #[test]
    fn ghash_mcgrew_viega_tc2() {
        let h = hex16("66e94bd4ef8a2c3b884cfa59ca342b2e");
        let c = hex("0388dace60b6a392f328c2b971b2fe78");
        assert_eq!(
            ghash(&h, b"", &c),
            hex16("f38cbb1ad69223dcc3457ae5b6b0f885")
        );
    }

    /// GHASH values derived from NIST ACVP-AES-GCM-1.0, testGroup tgId 1,
    /// tcId 1..15 (15-byte AAD, empty payload). Each row is
    /// (H = AES-128_K(0), AAD, GHASH_H(AAD, empty) = tag ^ AES-128_K(J0)).
    /// Generated and cross-checked against the NIST tags by
    /// `python -I scripts/gen_ghash_kat.py` (OpenSSL 3.5.7 for AES-128).
    /// The AES-GCM tags themselves are not reproducible here because they
    /// contain AES_K(J0); only the GHASH component is validated.
    #[test]
    fn ghash_acvp_derived_kats() {
        #[rustfmt::skip] // one vector per line, matches scripts/gen_ghash_kat.py output
        let rows: [(&str, &str, &str); 15] = [
            ("bd8ec183d9b88b91634a63794a186ffd", "4607f76f4fda85dafdc8ce085e0ce5", "da4e6c832c6a9eb1c70fc79be66b6698"), // tcId 1
            ("d65554485c297ef725ca0dda839e3dc2", "65fc70a3cc2e0f14b3c56216881f8c", "4154a8b02095b1a46b960ebe8ad67529"), // tcId 2
            ("f0dc80bb80c3b3fa112236287d7108b2", "edde20197c7ded0b293b061f349840", "e79a52de6f8724c3921262a854d1769a"), // tcId 3
            ("c65363d1c7ad44c1d010c844a3e0959d", "6a4687585852ae3438d97cc703ee17", "ab91468a216693f205bd9c9975e62c2b"), // tcId 4
            ("ab5bb0e89ba17700ad315f8412342a17", "2bc528ceb661427363c3d7c41a474b", "4e2afb0b17ca15f76c667fad32e77d4c"), // tcId 5
            ("82361fdb4f6cd0103255cda8cf6b5c0a", "9d43a96f28e0753def6e6e07fd8442", "3e00b0eb8bb05efc99293fab6a35a6aa"), // tcId 6
            ("9996da23aaaeb43e228b848ccf83c84a", "8f8edfa6e95b755976955ed3483cd2", "3bc4179044e31bc338b5ee659e2ebf13"), // tcId 7
            ("5f89399d43e317d861119726960d8031", "900865d0db20458368f9a191775a58", "f6b5671963dd38c3fe463dcb1d10e689"), // tcId 8
            ("bc3356c76a0d40c5365bda5e40126e7d", "bf4d54fb100225db37d80aa5883b92", "03f6ff5285f22c16e2f649d5edadbdbc"), // tcId 9
            ("3a571c8660a1ad16d420923f4768d118", "ee74a91456154ea7df2702e8069099", "20a45a12de1b398db1c46cfd7fb41328"), // tcId 10
            ("3beabe0484fbdaeddf140b153b9b0d00", "0ee044d4503197d12d2773bad595dd", "f91f7b4fab87dfb8bdf517b1507b1e30"), // tcId 11
            ("5cba1b66a4dde03a9f646219532bf0a2", "cab5e1f3a6e9f334a1e3a0a480e430", "91d26a5cdebb3bd6c3f715e5aa315243"), // tcId 12
            ("14ae6fe5925cf39ed088fed5890251c2", "81febc3a769a3ec54cc2b2af464eb5", "dbca95e315ecdd41b29a326d98deab02"), // tcId 13
            ("a46c0b9d791bd09ca29068dda93ef623", "37e2149b37a2199f6def54b283a4c8", "e4bdcb95e01246e320af7484d4e2acb6"), // tcId 14
            ("066272cdb5faa3111f7537bc1efd33e3", "ab966dc5a64f1fa1588acc1cf4062c", "7bedbc8cc852a879139d961f945ca27c"), // tcId 15
        ];

        for (n, (h, aad, want)) in rows.iter().enumerate() {
            let got = ghash(&hex16(h), &hex(aad), b"");
            assert_eq!(
                got,
                hex16(want),
                "ACVP tgId 1 tcId {}: GHASH mismatch",
                n + 1
            );
        }
    }
}
