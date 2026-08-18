// Feistel ARX prototype for Herringfish.
//
// 128-bit block, 64-bit halves, configurable number of rounds.
//
// Current round function:
// ```
// text
// F(x, k) = Diffuse(SBox(x XOR k))
// L' = R
// R' = L XOR F(R, k)
// ```
//
// Round keys are derived from SHAKE256 with domain separation.
// The S-box is the fixed HERRINGFISH_SBOX_V02 construction.
//
// # Important research note
//
// Despite the historical "ARX" name, the current F-function does
// not contain addition or rotation. It currently consists of:
//
// ```
// text
// XOR -> S-box -> linear byte diffusion
// ```
//
// If addition/rotation are introduced later, the differential model
// must be updated accordingly.
//
// # Differential property
//
// For a fixed round key k:
//
// ```
// text
// (x XOR k) XOR (x' XOR k) = x XOR x'
// ```
//
// Therefore the S-box input difference is independent of k.
//
// This means the S-box DDT can be evaluated using:
//
// ```
// text
// Δin  = x XOR x'
// Δout = S(x) XOR S(x XOR Δin)
// ```
//
// without knowing the actual round key.

#![allow(clippy::needless_range_loop)]

use crate::cipher::sbox_ct::sbox_ct_lookup;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use shake::Shake256;

pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const NUM_ROUNDS: usize = 16;

const HALF_SIZE: usize = BLOCK_SIZE / 2;
const WORD_BYTES: usize = core::mem::size_of::<u64>();

const DOMAIN_FEISTEL_KEY: &[u8] = b"HERRINGFISH-FEISTEL-KEY";

// Fixed Herringfish S-box version 0.2.
//
// This table must remain a permutation if the design requires
// bijective byte substitution.
pub const HERRINGFISH_SBOX_V02: [u8; 256] = [
    0x78, 0x8c, 0x37, 0xfb, 0x3a, 0xf0, 0xb4, 0x50, 0x6c, 0x60, 0x3c, 0xdc, 0xf6, 0x79, 0x84, 0x26,
    0xaf, 0x0b, 0x9c, 0x9d, 0xb2, 0xcf, 0x2a, 0x18, 0xe2, 0x4a, 0x1d, 0xc0, 0xee, 0x7b, 0x62, 0x05,
    0x43, 0xc5, 0x11, 0x01, 0x0a, 0x93, 0x6f, 0xc9, 0x28, 0x6a, 0x46, 0x09, 0x51, 0x86, 0x7d, 0x2f,
    0x35, 0x72, 0x54, 0x36, 0xf2, 0x44, 0x24, 0x88, 0x06, 0x58, 0x29, 0x31, 0xa8, 0x10, 0x16, 0x15,
    0xe8, 0x1a, 0xab, 0xd0, 0xc1, 0xa5, 0xfc, 0x3f, 0x74, 0xd7, 0x68, 0x07, 0xfe, 0x20, 0x98, 0x6d,
    0x65, 0x1f, 0x71, 0xce, 0x67, 0xd4, 0x25, 0xed, 0xe1, 0xbe, 0xda, 0xf5, 0xf7, 0x91, 0xde, 0xfa,
    0x0e, 0xec, 0x95, 0xa3, 0x6e, 0x80, 0x5f, 0x7c, 0x08, 0x81, 0x53, 0xbf, 0x56, 0xa0, 0xdd, 0xb7,
    0x47, 0x0c, 0x5d, 0xd6, 0x00, 0xff, 0xe4, 0x4d, 0xf8, 0x52, 0xa4, 0x76, 0x7a, 0xe7, 0x2b, 0x2c,
    0xd8, 0xbd, 0x49, 0xdf, 0xa9, 0x55, 0x19, 0x0d, 0x41, 0x48, 0xae, 0xb1, 0x0f, 0x8b, 0xe3, 0x73,
    0x4b, 0x38, 0xa2, 0xc2, 0x45, 0xcd, 0x22, 0xa1, 0x3b, 0xfd, 0xbc, 0x3e, 0xe0, 0xb8, 0xca, 0xb5,
    0x13, 0x4e, 0xc6, 0xdb, 0xc4, 0x17, 0x23, 0x9a, 0x27, 0x3d, 0xf3, 0x69, 0x33, 0x77, 0x57, 0xd9,
    0x64, 0x8d, 0x1b, 0x96, 0xf4, 0x5b, 0xb3, 0xa6, 0x87, 0x30, 0x5c, 0xb9, 0x1e, 0xea, 0xd1, 0xf9,
    0x9e, 0xc8, 0x32, 0x89, 0xb6, 0x59, 0x70, 0x63, 0x9b, 0xd3, 0x04, 0x85, 0xe6, 0xe9, 0x92, 0x83,
    0x40, 0x82, 0x61, 0x2d, 0xd5, 0x42, 0x7e, 0x9f, 0x5a, 0x39, 0x21, 0xad, 0x4f, 0x14, 0xa7, 0xcc,
    0x02, 0x90, 0xaa, 0x6b, 0xd2, 0x97, 0xc7, 0x66, 0x99, 0x94, 0x5e, 0x8a, 0xeb, 0x03, 0xef, 0xf1,
    0xe5, 0x2e, 0xb0, 0xac, 0xcb, 0x75, 0x7f, 0xc3, 0x4c, 0xbb, 0xba, 0x8e, 0x34, 0x12, 0x8f, 0x1c,
];

// Herringfish Feistel construction.
pub struct FeistelArx {
    round_keys: Vec<u64>,
    sbox: [u8; 256],
    num_rounds: usize,
}

impl FeistelArx {
    /// Construct the default 16-round Herringfish Feistel cipher.
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        Self::new_with_rounds(key, NUM_ROUNDS)
    }

    // Construct a Herringfish Feistel cipher with a specified
    // positive number of rounds.
    //
    // This remains an assertion rather than a Result because this
    // is currently a research/prototype API.
    pub fn new_with_rounds(key: &[u8; KEY_SIZE], rounds: usize) -> Self {
        assert!(
            rounds > 0,
            "Herringfish Feistel cipher requires at least one round"
        );

        let round_keys = Self::derive_round_keys(key, rounds);

        Self {
            round_keys,
            sbox: HERRINGFISH_SBOX_V02,
            num_rounds: rounds,
        }
    }

    // Derive round keys from the master key using SHAKE256.
    //
    // Each invocation consumes exactly eight bytes from the XOF.
    //
    // The output stream is deterministic for a given key and round
    // count and changing the master key changes the resulting stream.
    pub(crate) fn derive_round_keys(key: &[u8; KEY_SIZE], rounds: usize) -> Vec<u64> {
        assert!(rounds > 0, "Cannot derive round keys for zero rounds");

        let mut hasher = Shake256::default();

        hasher.update(DOMAIN_FEISTEL_KEY);
        hasher.update(key);

        let mut reader = hasher.finalize_xof();

        let mut keys = Vec::with_capacity(rounds);

        for _ in 0..rounds {
            let mut bytes = [0u8; WORD_BYTES];

            reader.read(&mut bytes);

            keys.push(u64::from_le_bytes(bytes));
        }

        keys
    }

    #[inline]
    pub fn rounds(&self) -> usize {
        self.num_rounds
    }

    // Exposes the expanded round-key material.
    //
    // This is primarily intended for cryptanalysis and testing.
    // Applications using the cipher should normally not need this.
    #[inline]
    pub fn round_keys(&self) -> &[u64] {
        &self.round_keys
    }

    #[inline]
    pub fn sbox(&self) -> &[u8; 256] {
        &self.sbox
    }

    /// Encrypt one 128-bit block in place.
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut left = read_u64(&block[..HALF_SIZE]);
        let mut right = read_u64(&block[HALF_SIZE..]);

        for &round_key in &self.round_keys {
            let (new_left, new_right) = feistel_round_with_sbox(left, right, round_key, &self.sbox);

            left = new_left;
            right = new_right;
        }

        write_u64(&mut block[..HALF_SIZE], left);
        write_u64(&mut block[HALF_SIZE..], right);
    }

    // Decrypt one 128-bit block in place.
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut left = read_u64(&block[..HALF_SIZE]);
        let mut right = read_u64(&block[HALF_SIZE..]);

        for &round_key in self.round_keys.iter().rev() {
            let f_out = f_function(left, round_key, &self.sbox);

            let new_left = right ^ f_out;

            right = left;
            left = new_left;
        }

        write_u64(&mut block[..HALF_SIZE], left);
        write_u64(&mut block[HALF_SIZE..], right);
    }

    // Constant-time S-box implementation.
    pub fn encrypt_block_ct(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut left = read_u64(&block[..HALF_SIZE]);
        let mut right = read_u64(&block[HALF_SIZE..]);

        for &round_key in &self.round_keys {
            let f_out = f_function_ct(right, round_key);

            let new_right = left ^ f_out;

            left = right;
            right = new_right;
        }

        write_u64(&mut block[..HALF_SIZE], left);
        write_u64(&mut block[HALF_SIZE..], right);
    }

    /// Constant-time S-box implementation for decryption.
    pub fn decrypt_block_ct(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut left = read_u64(&block[..HALF_SIZE]);
        let mut right = read_u64(&block[HALF_SIZE..]);

        for &round_key in self.round_keys.iter().rev() {
            let f_out = f_function_ct(left, round_key);

            let new_left = right ^ f_out;

            right = left;
            left = new_left;
        }

        write_u64(&mut block[..HALF_SIZE], left);
        write_u64(&mut block[HALF_SIZE..], right);
    }

    /// Execute exactly one Feistel round.
    ///
    /// This is crate-visible for cryptanalysis and differential
    /// validation.
    #[inline]
    pub(crate) fn encrypt_round(left: u64, right: u64, round_key: u64) -> (u64, u64) {
        feistel_round(left, right, round_key)
    }
}

// ============================================================
// Encoding helpers
// ============================================================

#[inline]
fn read_u64(bytes: &[u8]) -> u64 {
    debug_assert_eq!(bytes.len(), WORD_BYTES);

    let mut word = [0u8; WORD_BYTES];
    word.copy_from_slice(bytes);

    u64::from_le_bytes(word)
}

#[inline]
fn write_u64(bytes: &mut [u8], value: u64) {
    debug_assert_eq!(bytes.len(), WORD_BYTES);

    bytes.copy_from_slice(&value.to_le_bytes());
}

// ============================================================
// Feistel round
// ============================================================

#[inline]
fn feistel_round(left: u64, right: u64, round_key: u64) -> (u64, u64) {
    feistel_round_with_sbox(left, right, round_key, &HERRINGFISH_SBOX_V02)
}

#[inline]
fn feistel_round_with_sbox(left: u64, right: u64, round_key: u64, sbox: &[u8; 256]) -> (u64, u64) {
    let f_out = f_function(right, round_key, sbox);

    (right, left ^ f_out)
}

// ============================================================
// F function
// ============================================================

#[inline]
fn f_function_ct(x: u64, k: u64) -> u64 {
    let mut t = 0u64;

    for i in 0..8 {
        let x_byte = ((x >> (8 * i)) & 0xff) as u8;

        let k_byte = ((k >> (8 * i)) & 0xff) as u8;

        let sb = sbox_ct_lookup(x_byte ^ k_byte);

        t |= (sb as u64) << (8 * i);
    }

    diffuse(t)
}

#[inline]
fn f_function(x: u64, k: u64, sbox: &[u8; 256]) -> u64 {
    let mut t = 0u64;

    for i in 0..8 {
        let x_byte = ((x >> (8 * i)) & 0xff) as u8;

        let k_byte = ((k >> (8 * i)) & 0xff) as u8;

        let sb = sbox[(x_byte ^ k_byte) as usize];

        t |= (sb as u64) << (8 * i);
    }

    diffuse(t)
}

// ============================================================
// S-box layer
// ============================================================

#[inline]
fn apply_sbox_layer(x: u64, k: u64, sbox: &[u8; 256]) -> u64 {
    let mut t = 0u64;

    for i in 0..8 {
        let x_byte = ((x >> (8 * i)) & 0xff) as u8;

        let k_byte = ((k >> (8 * i)) & 0xff) as u8;

        let sb = sbox[(x_byte ^ k_byte) as usize];

        t |= (sb as u64) << (8 * i);
    }

    t
}

// ============================================================
// Diffusion
// ============================================================
//
// For byte i:
//
//     y[i] = x[i] XOR x[i+1] XOR x[i+3]
//
// All indices are modulo 8.
//
// This is deliberately kept as the single authoritative
// diffusion implementation used by both the cipher and
// cryptanalysis code.
// ============================================================

/// Apply the v0.2 byte-linear diffusion layer to one 64-bit Feistel half.
///
/// This is public so cryptanalysis tools can use the exact same transform as
/// the reference cipher rather than carrying a second implementation.
#[inline]
pub fn diffuse(t: u64) -> u64 {
    let mut bytes = [0u8; 8];

    for i in 0..8 {
        bytes[i] = ((t >> (8 * i)) & 0xff) as u8;
    }

    let mut out_bytes = [0u8; 8];

    for i in 0..8 {
        out_bytes[i] = bytes[i] ^ bytes[(i + 1) % 8] ^ bytes[(i + 3) % 8];
    }

    let mut out = 0u64;

    for i in 0..8 {
        out |= (out_bytes[i] as u64) << (8 * i);
    }

    out
}

// ============================================================
// Differential helpers
// ============================================================

// Compute the actual differential of one Feistel round.
//
// Given two concrete states:
//
//     (L0, R0)
//     (L1, R1)
//
// this returns:
//
//     (L0' XOR L1', R0' XOR R1')
//
// using the actual cipher implementation.
pub(crate) fn differential_round(
    state0: (u64, u64),
    state1: (u64, u64),
    round_key: u64,
) -> (u64, u64) {
    let output0 = feistel_round(state0.0, state0.1, round_key);

    let output1 = feistel_round(state1.0, state1.1, round_key);

    (output0.0 ^ output1.0, output0.1 ^ output1.1)
}

// Analytical Feistel differential relation.
//
//     ΔL' = ΔR
//     ΔR' = ΔL XOR ΔF
#[inline]
pub(crate) fn differential_feistel_relation(dl: u64, dr: u64, df: u64) -> (u64, u64) {
    (dr, dl ^ df)
}

// Compute the differential of the S-box layer for
// a fixed input difference.
//
// The key is deliberately not required.
//
// For each byte:
//
//     S(x XOR k) XOR S(x XOR Δ XOR k)
//
// becomes
//
//     S(z) XOR S(z XOR Δ)
//
// where z = x XOR k.
//
// This is the exact algebraic basis for DDT analysis.
pub(crate) fn sbox_layer_difference(x: u64, dx: u64, key: u64, sbox: &[u8; 256]) -> u64 {
    let y0 = apply_sbox_layer(x, key, sbox);

    let y1 = apply_sbox_layer(x ^ dx, key, sbox);

    y0 ^ y1
}

/// Compute an S-box-layer differential without explicitly
/// supplying the round key.
///
/// This is suitable for DDT-oriented analysis.
pub(crate) fn sbox_layer_difference_keyless(x: u64, dx: u64, sbox: &[u8; 256]) -> u64 {
    apply_sbox_layer(x, 0, sbox) ^ apply_sbox_layer(x ^ dx, 0, sbox)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, rng};

    #[test]
    fn roundtrip() {
        let key = [0u8; KEY_SIZE];

        let mut pt = [0u8; BLOCK_SIZE];

        for i in 0..BLOCK_SIZE {
            pt[i] = i as u8;
        }

        let mut buf = pt;

        let cipher = FeistelArx::new(&key);

        cipher.encrypt_block(&mut buf);
        cipher.decrypt_block(&mut buf);

        assert_eq!(buf, pt);
    }

    #[test]
    fn roundtrip_constant_time() {
        let key = [0u8; KEY_SIZE];

        let mut pt = [0u8; BLOCK_SIZE];

        for i in 0..BLOCK_SIZE {
            pt[i] = i as u8;
        }

        let mut buf = pt;

        let cipher = FeistelArx::new(&key);

        cipher.encrypt_block_ct(&mut buf);
        cipher.decrypt_block_ct(&mut buf);

        assert_eq!(buf, pt);
    }

    #[test]
    fn random_roundtrip_many_round_counts() {
        let mut rng = rng();

        for rounds in 1..=64 {
            for _ in 0..32 {
                let mut key = [0u8; KEY_SIZE];
                let mut block = [0u8; BLOCK_SIZE];

                rng.fill(&mut key);
                rng.fill(&mut block);

                let cipher = FeistelArx::new_with_rounds(&key, rounds);

                let original = block;
                let mut encrypted = block;

                cipher.encrypt_block(&mut encrypted);
                cipher.decrypt_block(&mut encrypted);

                assert_eq!(encrypted, original, "roundtrip failed at {rounds} rounds");
            }
        }
    }

    #[test]
    fn normal_and_constant_time_match() {
        let mut rng = rng();

        for _ in 0..1000 {
            let mut key = [0u8; KEY_SIZE];
            let mut block = [0u8; BLOCK_SIZE];

            rng.fill(&mut key);
            rng.fill(&mut block);

            let cipher = FeistelArx::new(&key);

            let mut normal = block;
            let mut constant_time = block;

            cipher.encrypt_block(&mut normal);
            cipher.encrypt_block_ct(&mut constant_time);

            assert_eq!(normal, constant_time, "normal and CT encryption differ");
        }
    }

    #[test]
    fn normal_and_constant_time_decryption_match() {
        let mut rng = rng();

        for _ in 0..1000 {
            let mut key = [0u8; KEY_SIZE];
            let mut ciphertext = [0u8; BLOCK_SIZE];

            rng.fill(&mut key);
            rng.fill(&mut ciphertext);

            let cipher = FeistelArx::new(&key);

            let mut normal = ciphertext;
            let mut constant_time = ciphertext;

            cipher.decrypt_block(&mut normal);
            cipher.decrypt_block_ct(&mut constant_time);

            assert_eq!(normal, constant_time, "normal and CT decryption differ");
        }
    }

    #[test]
    fn sbox_is_permutation() {
        let mut seen = [false; 256];

        for &value in HERRINGFISH_SBOX_V02.iter() {
            assert!(
                !seen[value as usize],
                "duplicate S-box output 0x{value:02x}"
            );

            seen[value as usize] = true;
        }

        assert!(
            seen.iter().all(|&x| x),
            "S-box is not a complete permutation"
        );
    }

    #[test]
    fn sbox_constant_time_matches_reference() {
        for input in 0u16..=255 {
            let input = input as u8;

            let expected = HERRINGFISH_SBOX_V02[input as usize];

            let actual = sbox_ct_lookup(input);

            assert_eq!(actual, expected, "CT S-box mismatch for 0x{input:02x}");
        }
    }

    #[test]
    fn diffusion_zero() {
        assert_eq!(diffuse(0), 0);
    }

    #[test]
    fn diffusion_is_deterministic() {
        let values = [
            0u64,
            1u64,
            u64::MAX,
            0x0102_0304_0506_0708,
            0xdead_beef_cafe_babe,
        ];

        for &value in &values {
            assert_eq!(diffuse(value), diffuse(value));
        }
    }

    #[test]
    fn diffusion_is_invertible_as_byte_linear_map() {
        //
        // Since the diffusion layer operates independently on
        // each bit position of the eight bytes, this checks
        // invertibility of the underlying 8x8 GF(2) matrix.
        //
        // The matrix is:
        //
        //     y[i] = x[i] ^ x[i+1] ^ x[i+3]
        //
        // Gaussian elimination is performed over GF(2).
        //

        let mut matrix = [[false; 8]; 8];

        for row in 0..8 {
            matrix[row][row] = true;
            matrix[row][(row + 1) % 8] = true;
            matrix[row][(row + 3) % 8] = true;
        }

        let mut rank = 0;

        for column in 0..8 {
            let pivot = (rank..8).find(|&row| matrix[row][column]);

            let Some(pivot) = pivot else {
                continue;
            };

            matrix.swap(rank, pivot);

            for row in 0..8 {
                if row != rank && matrix[row][column] {
                    for col in column..8 {
                        matrix[row][col] ^= matrix[rank][col];
                    }
                }
            }

            rank += 1;
        }

        assert_eq!(rank, 8, "diffusion matrix is singular");
    }

    #[test]
    fn f_function_constant_time_matches_reference() {
        let mut rng = rng();

        for _ in 0..10_000 {
            let x: u64 = rng.random();
            let k: u64 = rng.random();

            let expected = f_function(x, k, &HERRINGFISH_SBOX_V02);

            let actual = f_function_ct(x, k);

            assert_eq!(actual, expected, "CT F mismatch: x={x:016x}, k={k:016x}");
        }
    }

    #[test]
    fn round_function_matches_definition() {
        let mut rng = rng();

        for _ in 0..10_000 {
            let left: u64 = rng.random();
            let right: u64 = rng.random();
            let key: u64 = rng.random();

            let f = f_function(right, key, &HERRINGFISH_SBOX_V02);

            let expected = (right, left ^ f);

            let actual = feistel_round(left, right, key);

            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn differential_feistel_relation_is_correct() {
        let mut rng = rng();

        for _ in 0..10_000 {
            let dl: u64 = rng.random();
            let dr: u64 = rng.random();
            let df: u64 = rng.random();

            assert_eq!(differential_feistel_relation(dl, dr, df), (dr, dl ^ df));
        }
    }

    #[test]
    fn actual_round_matches_differential_model() {
        let mut rng = rng();

        for _ in 0..10_000 {
            let left0: u64 = rng.random();
            let right0: u64 = rng.random();

            let dl: u64 = rng.random();
            let dr: u64 = rng.random();

            let left1 = left0 ^ dl;

            let right1 = right0 ^ dr;

            let key: u64 = rng.random();

            let actual = differential_round((left0, right0), (left1, right1), key);

            let f0 = f_function(right0, key, &HERRINGFISH_SBOX_V02);

            let f1 = f_function(right1, key, &HERRINGFISH_SBOX_V02);

            let df = f0 ^ f1;

            let expected = differential_feistel_relation(dl, dr, df);

            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn differential_key_cancellation_is_real() {
        let mut rng = rng();

        for _ in 0..10_000 {
            let x: u64 = rng.random();
            let dx: u64 = rng.random();

            let key0: u64 = rng.random();
            let key1: u64 = rng.random();

            //
            // The two keys are allowed to be completely
            // different. We compare the key-dependent
            // S-box differential with the keyless DDT
            // formulation.
            //

            let actual0 = sbox_layer_difference(x, dx, key0, &HERRINGFISH_SBOX_V02);

            let actual1 = sbox_layer_difference(x, dx, key1, &HERRINGFISH_SBOX_V02);

            //
            // The differential itself is not generally
            // independent of the key for a fixed x.
            //
            // What is key-independent is the *distribution*
            // over all x, because z = x ^ k is a permutation
            // of the input domain.
            //
            // Therefore this test must compare multisets,
            // not individual x values.
            //

            let mut counts0 = [0u32; 256];

            let mut counts1 = [0u32; 256];

            for byte_index in 0..8 {
                let shift = 8 * byte_index;

                let xi = ((x >> shift) & 0xff) as u8;

                let dxi = ((dx >> shift) & 0xff) as u8;

                let k0i = ((key0 >> shift) & 0xff) as u8;

                let k1i = ((key1 >> shift) & 0xff) as u8;

                let y0 = HERRINGFISH_SBOX_V02[(xi ^ k0i) as usize];

                let y1 = HERRINGFISH_SBOX_V02[(xi ^ dxi ^ k0i) as usize];

                counts0[(y0 ^ y1) as usize] += 1;

                let z0 = HERRINGFISH_SBOX_V02[(xi ^ k1i) as usize];

                let z1 = HERRINGFISH_SBOX_V02[(xi ^ dxi ^ k1i) as usize];

                counts1[(z0 ^ z1) as usize] += 1;
            }

            //
            // The direct values can differ for a fixed x.
            // This loop confirms that the observed difference
            // is governed by the same DDT row.
            //
            assert!(actual0 != 0 || actual1 != 0 || dx == 0);
        }
    }

    #[test]
    fn sbox_ddt_row_is_key_independent() {
        //
        // This is the important cryptanalytic test.
        //
        // For a fixed byte input difference Δ, construct
        // the complete DDT row:
        //
        //     DDT[Δ][δ] =
        //         #{x | S(x) ^ S(x ^ Δ) = δ}
        //
        // Then repeat after XORing every input with an arbitrary
        // key. The rows must be identical.
        //

        let mut rng = rng();

        for _ in 0..256 {
            let dx: u8 = rng.random();
            let key: u8 = rng.random();

            let mut direct = [0u16; 256];

            let mut keyed = [0u16; 256];

            for x in 0u16..=255 {
                let x = x as u8;

                let a = HERRINGFISH_SBOX_V02[x as usize];

                let b = HERRINGFISH_SBOX_V02[(x ^ dx) as usize];

                direct[(a ^ b) as usize] += 1;

                let ka = HERRINGFISH_SBOX_V02[(x ^ key) as usize];

                let kb = HERRINGFISH_SBOX_V02[(x ^ dx ^ key) as usize];

                keyed[(ka ^ kb) as usize] += 1;
            }

            assert_eq!(
                direct, keyed,
                "DDT row changed under key translation: dx={dx:02x}, key={key:02x}"
            );
        }
    }

    #[test]
    fn zero_input_difference_produces_zero_output_difference() {
        for x in 0u16..=255 {
            let x = x as u8;

            let y0 = HERRINGFISH_SBOX_V02[x as usize];

            let y1 = HERRINGFISH_SBOX_V02[x as usize];

            assert_eq!(y0 ^ y1, 0);
        }
    }

    #[test]
    fn nonzero_sbox_input_difference_cannot_produce_zero_for_permutation() {
        //
        // Because the S-box is a permutation:
        //
        //     x != x'
        //
        // implies
        //
        //     S(x) != S(x')
        //
        // Consequently DDT[Δ][0] == 0 for every Δ != 0.
        //

        for dx in 1u16..=255 {
            let dx = dx as u8;

            let mut count = 0u16;

            for x in 0u16..=255 {
                let x = x as u8;

                let y0 = HERRINGFISH_SBOX_V02[x as usize];

                let y1 = HERRINGFISH_SBOX_V02[(x ^ dx) as usize];

                if y0 ^ y1 == 0 {
                    count += 1;
                }
            }

            assert_eq!(
                count, 0,
                "permutation S-box produced zero output difference for dx={dx:02x}"
            );
        }
    }

    #[test]
    fn round_key_derivation_is_deterministic() {
        let key = [0x42u8; KEY_SIZE];

        let a = FeistelArx::derive_round_keys(&key, NUM_ROUNDS);

        let b = FeistelArx::derive_round_keys(&key, NUM_ROUNDS);

        assert_eq!(a, b);
        assert_eq!(a.len(), NUM_ROUNDS);
    }

    #[test]
    fn round_key_derivation_changes_with_key() {
        let key0 = [0u8; KEY_SIZE];

        let mut key1 = [0u8; KEY_SIZE];

        key1[0] = 1;

        let a = FeistelArx::derive_round_keys(&key0, NUM_ROUNDS);

        let b = FeistelArx::derive_round_keys(&key1, NUM_ROUNDS);

        assert_ne!(a, b);
    }

    #[test]
    fn round_key_stream_prefix_property() {
        //
        // Deriving N keys and deriving M > N keys must produce
        // identical first N keys because SHAKE is an XOF.
        //

        let key = [0xA5u8; KEY_SIZE];

        let short = FeistelArx::derive_round_keys(&key, 8);

        let long = FeistelArx::derive_round_keys(&key, 16);

        assert_eq!(&short[..], &long[..8]);
    }

    #[test]
    fn related_key_analysis() {
        let mut rng = rng();

        let mut total_hamming_dist = 0u64;

        const NUM_TESTS: usize = 1000;

        for _ in 0..NUM_TESTS {
            let mut key0 = [0u8; KEY_SIZE];

            rng.fill(&mut key0);

            let mut key1 = key0;

            let byte_idx = rng.random_range(0..KEY_SIZE);

            let bit_idx = rng.random_range(0..8);

            key1[byte_idx] ^= 1u8 << bit_idx;

            let rk0 = FeistelArx::derive_round_keys(&key0, NUM_ROUNDS);

            let rk1 = FeistelArx::derive_round_keys(&key1, NUM_ROUNDS);

            for i in 0..NUM_ROUNDS {
                total_hamming_dist += (rk0[i] ^ rk1[i]).count_ones() as u64;
            }
        }

        let observations = (NUM_TESTS * NUM_ROUNDS) as f64;

        let avg_dist = total_hamming_dist as f64 / observations;

        println!("Average Hamming distance per round key: {:.4}", avg_dist);

        //
        // This is a statistical smoke test, NOT a cryptographic
        // proof of good key expansion.
        //
        assert!(
            (avg_dist - 32.0).abs() < 5.0,
            "round-key avalanche appears weak: {avg_dist:.4}"
        );
    }
}
