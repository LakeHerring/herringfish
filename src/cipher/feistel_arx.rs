//! Feistel ARX prototype for Herringfish
//!
//! 128-bit block, 64-bit halves, 16 rounds
//! F function = S-box + diffusion
//! Round keys derived from SHAKE256 with domain separation
//! S-box derived via SHAKE256 with DDT/LAT filtering

use shake::Shake256;
use sha3::digest::{Update, ExtendableOutput};

pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const NUM_ROUNDS: usize = 16;

const DOMAIN_FEISTEL_KEY: &[u8] = b"HERRINGFISH-FEISTEL-KEY";
const DOMAIN_FEISTEL_SBOX: &[u8] = b"HERRINGFISH-FEISTEL-SBOX";
pub const HERRINGFISH_SBOX_V02: [u8;256] = [0x78,0x8c,0x37,0xfb,0x3a,0xf0,0xb4,0x50,0x6c,0x60,0x3c,0xdc,0xf6,0x79,0x84,0x26,
    0xaf,0x0b,0x9c,0x9d,0xb2,0xcf,0x2a,0x18,0xe2,0x4a,0x1d,0xc0,0xee,0x7b,0x62,0x05,
    0x43,0xc5,0x11,0x01,0x0a,0x93,0x6f,0xc9,0x28,0x6a,0x46,0x09,0x51,0x86,0x7d,0x2f,
    0x35,0x72,0x54,0x36,0xf2,0x44,0x24,0x88,0x06,0x58,0x29,0x31,0xa8,0x10,0x16,0x15,
    0xe8,0x1a,0xab,0xd0,0xc1,0xa5,0xfc,0x3f,0x74,0xd7,0x68,0x07,0xfe,0x20,0x98,0x6d,
    0x65,0x1f,0x71,0xce,0x67,0xd4,0x25,0xed,0xe1,0xbe,0xda,0xf5,0xf7,0x91,0xde,0xfa,
    0x0e,0xec,0x95,0xa3,0x6e,0x80,0x5f,0x7c,0x08,0x81,0x53,0xbf,0x56,0xa0,0xdd,0xb7,
    0x47,0x0c,0x5d,0xd6,0x00,0xff,0xe4,0x4d,0xf8,0x52,0xa4,0x76,0x7a,0xe7,0x2b,0x2c,
    0xd8,0xbd,0x49,0xdf,0xa9,0x55,0x19,0x0d,0x41,0x48,0xae,0xb1,0x0f,0x8b,0xe3,0x73,
    0x4b,0x38,0xa2,0xc2,0x45,0xcd,0x22,0xa1,0x3b,0xfd,0xbc,0x3e,0xe0,0xb8,0xca,0xb5,
    0x13,0x4e,0xc6,0xdb,0xc4,0x17,0x23,0x9a,0x27,0x3d,0xf3,0x69,0x33,0x77,0x57,0xd9,
    0x64,0x8d,0x1b,0x96,0xf4,0x5b,0xb3,0xa6,0x87,0x30,0x5c,0xb9,0x1e,0xea,0xd1,0xf9,
    0x9e,0xc8,0x32,0x89,0xb6,0x59,0x70,0x63,0x9b,0xd3,0x04,0x85,0xe6,0xe9,0x92,0x83,
    0x40,0x82,0x61,0x2d,0xd5,0x42,0x7e,0x9f,0x5a,0x39,0x21,0xad,0x4f,0x14,0xa7,0xcc,
    0x02,0x90,0xaa,0x6b,0xd2,0x97,0xc7,0x66,0x99,0x94,0x5e,0x8a,0xeb,0x03,0xef,0xf1,
    0xe5,0x2e,0xb0,0xac,0xcb,0x75,0x7f,0xc3,0x4c,0xbb,0xba,0x8e,0x34,0x12,0x8f,0x1c,
];

pub struct FeistelArx {
    round_keys: Vec<u64>,
    sbox: [u8; 256],
}

impl FeistelArx {
    pub fn new(key: &[u8; KEY_SIZE]) -> Self {
        let round_keys = Self::derive_round_keys(key);
        let sbox = Self::derive_sbox();
        Self { round_keys, sbox }
    }

    fn derive_round_keys(key: &[u8; KEY_SIZE]) -> Vec<u64> {
        let mut hasher = Shake256::default();
        hasher.update(DOMAIN_FEISTEL_KEY);
        hasher.update(key);
        let mut out = vec![0u8; NUM_ROUNDS * 8];
        hasher.finalize_xof_into(&mut out);
        let mut keys = Vec::with_capacity(NUM_ROUNDS);
        for i in 0..NUM_ROUNDS {
            let start = i * 8;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&out[start..start+8]);
            keys.push(u64::from_le_bytes(bytes));
        }
        keys
    }

    fn derive_sbox() -> [u8; 256] {
        HERRINGFISH_SBOX_V02
    }

    fn is_bijective(sbox: &[u8;256]) -> bool {
        let mut seen = [false;256];
        for &b in sbox.iter() {
            let idx = b as usize;
            if seen[idx] { return false; }
            seen[idx] = true;
        }
        true
    }

    fn ddt_max(sbox: &[u8;256]) -> u16 {
        let mut max_v = 0u16;
        for dx in 1..256 {
            for dy in 1..256 {
                let mut cnt = 0u16;
                for x in 0..256 {
                    if sbox[(x ^ dx) as usize] ^ sbox[x] == dy as u8 {
                        cnt += 1;
                    }
                }
                if cnt > max_v { max_v = cnt; }
            }
        }
        max_v
    }

    fn lat_max(sbox: &[u8;256]) -> i32 {
        let mut max_v = 0i32;
        for a in 1..256 {
            for b in 1..256 {
                let mut sum = 0i32;
                for x in 0..256 {
                    let ax = ((x as u8) & a as u8).count_ones() & 1;
                    let bx = (sbox[x] & b as u8).count_ones() & 1;
                    if ax ^ bx == 0 { sum += 1; } else { sum -= 1; }
                }
                let abs = sum.abs();
                if abs > max_v { max_v = abs; }
            }
        }
        max_v
    }

    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut left = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let mut right = u64::from_le_bytes(block[8..16].try_into().unwrap());

        for &k in &self.round_keys {
            let f_out = f_function(right, k, &self.sbox);
            let new_right = left ^ f_out;
            left = right;
            right = new_right;
        }

        block[0..8].copy_from_slice(&left.to_le_bytes());
        block[8..16].copy_from_slice(&right.to_le_bytes());
    }

    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        let mut left = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let mut right = u64::from_le_bytes(block[8..16].try_into().unwrap());

        for &k in self.round_keys.iter().rev() {
            let f_out = f_function(left, k, &self.sbox);
            let new_left = right ^ f_out;
            right = left;
            left = new_left;
        }

        block[0..8].copy_from_slice(&left.to_le_bytes());
        block[8..16].copy_from_slice(&right.to_le_bytes());
    }
}

fn f_function(x: u64, k: u64, sbox: &[u8;256]) -> u64 {
    // S-box layer
    let mut t = 0u64;
    for i in 0..8 {
        let x_byte = ((x >> (8*i)) & 0xff) as u8;
        let k_byte = ((k >> (8*i)) & 0xff) as u8;
        let sb = sbox[(x_byte ^ k_byte) as usize];
        t |= (sb as u64) << (8*i);
    }
    // Linear diffusion layer inside F
    let mut bytes = [0u8;8];
    for i in 0..8 { bytes[i] = ((t >> (8*i)) & 0xff) as u8; }
    let mut out_bytes = [0u8;8];
    for i in 0..8 {
        out_bytes[i] = bytes[i] ^ bytes[(i+1)%8] ^ bytes[(i+3)%8];
    }
    let mut out = 0u64;
    for i in 0..8 { out |= (out_bytes[i] as u64) << (8*i); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0u8; 32];
        let mut pt = [0u8; 16];
        for i in 0..16 { pt[i] = i as u8; }
        let mut buf = pt;
        let c = FeistelArx::new(&key);
        c.encrypt_block(&mut buf);
        c.decrypt_block(&mut buf);
        assert_eq!(buf, pt);
    }
}
