use rand::{Rng, SeedableRng};
use sha3::{digest::{Update, ExtendableOutput}};
use std::collections::HashMap;
use std::convert::TryInto;
use shake::Shake256;

const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const SPN_ROUNDS: usize = 14;
const FEISTEL_ROUNDS: usize = 16;

// ---------- Feistel ARX ----------

fn f_function(x: u64, k: u64) -> u64 {
    let mut t = x ^ k;
    t = t.wrapping_add(k.rotate_left(13));
    t = t.rotate_left(7);
    t ^= k.rotate_left(3);
    t = t.wrapping_add(x);
    t.rotate_left(11)
}

fn feistel_derive_keys(key: &[u8; KEY_SIZE]) -> Vec<u64> {
    const DOMAIN: &[u8] = b"HERRINGFISH-FEISTEL-KEY";
    let mut hasher = Shake256::default();
    hasher.update(DOMAIN);
    hasher.update(key);
    let mut out = vec![0u8; FEISTEL_ROUNDS * 8];
    hasher.finalize_xof_into(&mut out);
    (0..FEISTEL_ROUNDS).map(|i| {
        let mut b = [0u8;8];
        b.copy_from_slice(&out[i*8..i*8+8]);
        u64::from_le_bytes(b)
    }).collect()
}

fn feistel_encrypt_trace(key: &[u8; KEY_SIZE], pt: &[u8; 16], rounds: usize) -> Vec<[u8;16]> {
    let keys = feistel_derive_keys(key);
    let mut left = u64::from_le_bytes(pt[0..8].try_into().unwrap());
    let mut right = u64::from_le_bytes(pt[8..16].try_into().unwrap());
    let mut states = Vec::with_capacity(rounds+1);
    let mut block = [0u8;16];
    block[0..8].copy_from_slice(&left.to_le_bytes());
    block[8..16].copy_from_slice(&right.to_le_bytes());
    states.push(block);
    for i in 0..rounds {
        let f_out = f_function(right, keys[i]);
        let new_right = left ^ f_out;
        left = right;
        right = new_right;
        block[0..8].copy_from_slice(&left.to_le_bytes());
        block[8..16].copy_from_slice(&right.to_le_bytes());
        states.push(block);
    }
    states
}

// ---------- SPN ----------
// Minimal SPN components copied from cipher/round.rs for self-containment
fn sbox(x: u8) -> u8 {
    const SBOX: [u8;256] = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ];
    SBOX[x as usize]
}
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut res = 0u8;
    let mut aa = a as u16;
    let mut bb = b as u16;
    while bb > 0 {
        if bb & 1 != 0 { res ^= aa as u8; }
        aa = (aa << 1) ^ if aa & 0x80 != 0 { 0x1b } else { 0 };
        bb >>= 1;
    }
    res
}
fn spn_round(state: &mut [u8;16], round_key: &[u8;16], final_round: bool) {
    for b in state.iter_mut() { *b = sbox(*b); }
    // ShiftRows
    let mut tmp = *state;
    for row in 0..4 {
        for col in 0..4 {
            let src_col = (col + row) % 4;
            state[row*4 + col] = tmp[row*4 + src_col];
        }
    }
    if !final_round {
        for col in 0..4 {
            let i0 = col; let i1 = col+4; let i2 = col+8; let i3 = col+12;
            let s0 = state[i0]; let s1 = state[i1]; let s2 = state[i2]; let s3 = state[i3];
            state[i0] = gf_mul(s0,2) ^ gf_mul(s1,3) ^ s2 ^ s3;
            state[i1] = s0 ^ gf_mul(s1,2) ^ gf_mul(s2,3) ^ s3;
            state[i2] = s0 ^ s1 ^ gf_mul(s2,2) ^ gf_mul(s3,3);
            state[i3] = gf_mul(s0,3) ^ s1 ^ s2 ^ gf_mul(s3,2);
        }
    }
    for i in 0..16 { state[i] ^= round_key[i]; }
}
fn spn_key_schedule(key: &[u8;32]) -> Vec<[u8;16]> {
    // Simple placeholder matching existing KeySchedule
    let mut state = [0u8;32];
    state.copy_from_slice(key);
    let mut round_keys = Vec::with_capacity(SPN_ROUNDS+1);
    for round in 0..=SPN_ROUNDS {
        let mut rk = [0u8;16];
        for i in 0..16 {
            let rc = round as u8;
            rk[i] = state[i % 32] ^ state[(i+13)%32] ^ rc ^ (round as u8);
        }
        round_keys.push(rk);
        // update state
        let first = state[0];
        state.copy_within(1..,0);
        state[31] = first;
        for i in 0..32 { state[i] ^= round as u8 ^ i as u8; }
    }
    round_keys
}
fn spn_encrypt_trace(key: &[u8;32], pt: &[u8;16]) -> Vec<[u8;16]> {
    let round_keys = spn_key_schedule(key);
    let mut state = *pt;
    for i in 0..16 { state[i] ^= round_keys[0][i]; }
    let mut states = vec![state];
    for r in 1..SPN_ROUNDS {
        let mut s = states.last().unwrap().clone();
        spn_round(&mut s, &round_keys[r], false);
        states.push(s);
    }
    let mut s = states.last().unwrap().clone();
    spn_round(&mut s, &round_keys[SPN_ROUNDS], true);
    states.push(s);
    states
}

// ---------- Utilities ----------
fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).map(|(x,y)| (x ^ y).count_ones() as usize).sum()
}

fn differential_max_prob(key: &[u8;32], rounds: usize, samples: usize, is_feistel: bool) -> f64 {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x12345678);
    let base_pt = [0u8;16];
    let base_trace = if is_feistel {
        feistel_encrypt_trace(key, &base_pt, rounds)
    } else {
        spn_encrypt_trace(key, &base_pt)
    };
    let base_out = *base_trace.last().unwrap();
    // Use 1-bit input difference
    let mut best = 0.0;
    for bit in 0..8 { // sample subset of bits for speed
        let mut pt = base_pt;
        pt[0] ^= 1 << bit;
        let mut freq: HashMap<[u8;16], usize> = HashMap::new();
        for _ in 0..samples {
            let mut p = [0u8;16];
            rng.fill_bytes(&mut p);
            let mut p2 = p;
            p2[0] ^= 1 << bit;
            let out1 = if is_feistel {
                feistel_encrypt_trace(key, &p, rounds).last().unwrap().clone()
            } else {
                // For SPN we need reduced rounds, approximate by truncating trace
                let tr = spn_encrypt_trace(key, &p);
                // take state after 'rounds' steps
                tr[rounds.min(tr.len()-1)].clone()
            };
            let out2 = if is_feistel {
                feistel_encrypt_trace(key, &p2, rounds).last().unwrap().clone()
            } else {
                let tr = spn_encrypt_trace(key, &p2);
                tr[rounds.min(tr.len()-1)].clone()
            };
            let mut diff = [0u8;16];
            for i in 0..16 { diff[i] = out1[i] ^ out2[i]; }
            *freq.entry(diff).or_insert(0) += 1;
        }
        let max_count = freq.values().cloned().max().unwrap_or(0);
        let prob = max_count as f64 / samples as f64;
        if prob > best { best = prob; }
    }
    best
}

fn main() {
    let key = [0u8;32];
    
    println!("=== Avalanche per round ===");
    // Feistel
    println!("Feistel ARX:");
    let base_pt = [0u8;16];
    let mut sums = vec![0usize; FEISTEL_ROUNDS+1];
    for bit in 0..128 {
        let mut pt = base_pt;
        pt[bit/8] ^= 1 << (bit%8);
        let trace = feistel_encrypt_trace(&key, &pt, FEISTEL_ROUNDS);
        for r in 0..=FEISTEL_ROUNDS {
            sums[r] += hamming_distance(&base_pt, &trace[r]);
        }
    }
    for r in 0..=FEISTEL_ROUNDS {
        let avg = sums[r] as f64 / 128.0;
        println!(" R{:2} avg {:.2} bits", r, avg);
    }

    // Differential max prob sampling
    println!("\n=== Differential max prob sampling (1-bit input diff, 256 samples per bit) ===");
    for rounds in [4,8,12] {
        let p_feistel = differential_max_prob(&key, rounds, 256, true);
        println!("Feistel {} rounds max prob approx {:.4}", rounds, p_feistel);
    }
    for rounds in [4,8,12] {
        let p_spn = differential_max_prob(&key, rounds, 256, false);
        println!("SPN {} rounds max prob approx {:.4}", rounds, p_spn);
    }

    // DDT/LAT for Feistel F-function: sample-based
    println!("\n=== F-function DDT/LAT sampling ===");
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xabcdef);
    let mut diff_counts: HashMap<(u64,u64), usize> = HashMap::new();
    for _ in 0..500_000 {
        let x = rng.next_u64();
        let k = rng.next_u64();
        let y1 = f_function(x, k);
        let x2 = x ^ 1;
        let y2 = f_function(x2, k);
        let dx = x ^ x2;
        let dy = y1 ^ y2;
        *diff_counts.entry((dx, dy)).or_insert(0) += 1;
    }
    let max_diff = diff_counts.values().cloned().max().unwrap_or(0);
    println!("F-function sampled max diff count {}/500k = {:.6}", max_diff, max_diff as f64/500_000.0);
}
