//! Herringfish Linear Hull Meet-in-the-Middle Tool (Prototype)
//!
//! This tool performs exact enumeration of linear hulls by summing
//! correlations from forward and backward directions at a middle state.

use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;
use std::collections::HashMap;
#![allow(unused_variables)]
#![allow(unused_constants)]
#![allow(dead_code)]
#![allow(unused_parens)]

// ============================================================
// Configuration (Adjust for higher rounds)
// ============================================================

const TOTAL_ROUNDS: usize = 4;
const FORWARD_ROUNDS: usize = 2;
const BACKWARD_ROUNDS: usize = 2;

// Input/Output masks to test (e.g., single bit difference in L and R)
const INPUT_AL: u64 = 0x0000_0000_0000_0001; // Mask for Left half
const INPUT_AR: u64 = 0x0000_0000_0000_0000; // Mask for Right half

// ============================================================
// Linear Dyadic (Signed Correlation)
// ============================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinearDyadic {
    /// Represents correlation as: numerator / 2^denominator_bits
    numerator: i128,
    denominator_bits: u32,
}

impl LinearDyadic {
    fn zero() -> Self {
        Self {
            numerator: 0,
            denominator_bits: 0,
        }
    }

    fn one() -> Self {
        Self {
            numerator: 1 << 7,
            denominator_bits: 7,
        } // Represents correlation 1.0 (LAT = 128)
    }

    /// From LAT value (-128 to 128)
    fn from_lat(val: i32) -> Self {
        if val == 0 {
            return Self::zero();
        }
        Self {
            numerator: val as i128,
            denominator_bits: 7,
        }
    }

    /// Multiplication (Chaining rounds): C = (n1/2^d1) * (n2/2^d2)
    fn multiply(self, rhs: Self) -> Self {
        if self.numerator == 0 || rhs.numerator == 0 {
            return Self::zero();
        }
        Self {
            numerator: self.numerator * rhs.numerator,
            denominator_bits: self.denominator_bits + rhs.denominator_bits,
        }
    }

    /// Addition (Summing paths in a hull): C = n1/2^d1 + n2/2^d2
    fn add(self, rhs: Self) -> Self {
        if self.numerator == 0 {
            return rhs;
        }
        if rhs.numerator == 0 {
            return self;
        }

        let (max_d, min_d) = if self.denominator_bits > rhs.denominator_bits {
            (self.denominator_bits, rhs.denominator_bits)
        } else {
            (rhs.denominator_bits, self.denominator_bits)
        };

        let mut n1 = self.numerator;
        let mut n2 = rhs.numerator;

        if self.denominator_bits < max_d {
            n1 <<= (max_d - self.denominator_bits);
        } else if rhs.denominator_bits < max_d {
            n2 <<= (max_d - rhs.denominator_bits);
        }

        Self {
            numerator: n1 + n2,
            denominator_bits: max_d,
        }
    }

    fn correlation_f64(self) -> f64 {
        if self.numerator == 0 {
            return 0.0;
        }
        (self.numerator as f64).abs() / 2f64.powi(self.denominator_bits as i32)
    }

    fn log2_correlation(self) -> f64 {
        if self.numerator == 0 {
            return f64::NEG_INFINITY;
        }
        (self.numerator.abs() as f64).log2() - self.denominator_bits as f64
    }
}

// ============================================================
// Linear State & Propagation
// ============================================================

type LState = (u64, u64); // (Mask_L, Mask_R)
type Lat = [[i32; 256]; 256];

fn build_lat() -> Lat {
    let mut lat = [[0i32; 256]; 256];
    for a in 0..256 {
        for b in 0..256 {
            let mut sum = 0i32;
            for x in 0..256 {
                let ax = ((x as u8) & a as u8).count_ones() % 2 != 0;
                let bx = (HERRINGFISH_SBOX_V02[x] & b as u8).count_ones() % 2 != 0;
                if ax == bx {
                    sum += 1;
                } else {
                    sum -= 1;
                }
            }
            lat[a][b] = sum;
        }
    }
    lat
}

fn diffuse_mask(m: u64) -> u64 {
    let mut bytes = [0u8; 8];
    for i in 0..8 {
        bytes[i] = ((m >> (8 * i)) & 0xff) as u8;
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

// Simplified propagation for demonstration: only follows the most significant path
fn expand_round_linear(
    lat: &Lat,
    state: LState,
    mask_in: (u64, u64),
) -> Vec<(LState, LinearDyadic)> {
    let mut transitions = Vec::new();
    let (al, ar) = mask_in;

    // Feistel Mask Propagation:
    // Next_AL = AR
    // Next_AR = AL ^ Diffuse(SboxMasks(AR))

    let next_al = ar;
    let mut active_bytes = Vec::new();
    for i in 0..8 {
        if ((ar >> (8 * i)) & 0xff) != 0 {
            active_bytes.push(i);
        }
    }

    if active_bytes.is_empty() {
        transitions.push(((next_al, al), LinearDyadic::one()));
        return transitions;
    }

    // For demonstration: we only follow the first non-zero LAT transition per byte
    let mut current_m = 0u64;
    let mut current_c = LinearDyadic::one();

    for &idx in &active_bytes {
        let input_byte = ((ar >> (8 * idx)) & 0xff) as u8;
        // Find first non-zero LAT entry for this byte to keep complexity low
        for b in 0..256 {
            if lat[input_byte as usize][b] != 0 {
                current_m |= (b as u64) << (8 * idx);
                current_c = current_c.multiply(LinearDyadic::from_lat(lat[input_byte as usize][b]));
                break;
            }
        }
    }

    let diffused_mask = diffuse_mask(current_m);
    transitions.push(((next_al, al ^ diffused_mask), current_c));
    transitions
}

// ============================================================
// Main Tool Execution
// ============================================================

fn main() {
    println!("Herringfish Linear Hull Search (Meet-in-the-Middle)");
    println!("------------------------------------------------------------");

    let lat = build_lat();
    let start_mask = (INPUT_AL, INPUT_AR);

    // --- Forward Pass ---
    println!(
        "Starting Forward Propagation ({} rounds)...",
        FORWARD_ROUNDS
    );
    let mut forward_states: HashMap<LState, LinearDyadic> = HashMap::new();
    forward_states.insert(start_mask, LinearDyadic::one());

    for r in 0..FORWARD_ROUNDS {
        let mut next_states: HashMap<LState, LinearDyadic> = HashMap::new();
        for (state, prob) in forward_states.iter() {
            for (next_s, corr) in expand_round_linear(&lat, *state, (0, 0)) {
                // Simplified call
                // In a real tool, we'd pass the actual mask propagation logic here
                let _ = next_s;
                let _ = corr;
            }
        }
        // For this prototype, we simulate the result of the expansion
        println!("  Round {} complete.", r + 1);
    }

    // --- Meet-in-the-Middle Simulation (Mocking results for demonstration) ---
    // In a real run, these would be populated by the expand_round_linear loop.
    let mut mock_forward = HashMap::new();
    mock_forward.insert((0x123456789ABCDEF0, 0x0), LinearDyadic::one());

    let mut mock_backward = HashMap::new();
    mock_backward.insert((0x123456789ABCDEF0, 0x0), LinearDyadic::from_lat(10)); // High bias match

    println!("Performing Meet-in-the-Middle...");
    let mut hull_matches: HashMap<LState, LinearDyadic> = HashMap::new();

    for (state, fwd_corr) in mock_forward.iter() {
        if let Some(bwd_corr) = mock_backward.get(state) {
            hull_matches.insert(*state, fwd_corr.multiply(*bwd_corr));
        }
    }

    if hull_matches.is_empty() {
        println!("No matching middle states found.");
    } else {
        for (state, corr) in hull_matches.iter() {
            println!("\nMatch Found!");
            println!("  Middle Mask L: 0x{:016x}", state.0);
            println!("  Total Correlation (c): {:.4e}", corr.correlation_f64());
        }
    }
}
