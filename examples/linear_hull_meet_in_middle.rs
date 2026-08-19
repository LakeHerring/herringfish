// HERRINGFISH LINEAR HULL MEET-IN-THE-MIDDLE
//
// Exact / bounded linear-hull propagation for the Herringfish Feistel
// construction, with an independent exact sanity oracle for reduced
// two-round cases.
//
// Feistel round:
//
//     L' = R
//     R' = L XOR F(R)
//
// Round-function:
//
//     F(x) = D(S(x))
//
// where D is the Herringfish linear byte diffusion.
//
// For linear masks:
//
// Forward:
//
//     (a, b) -> (b XOR q, a)
//
// where q is the output mask of F and
//
//     C_F(a, q)
//
// is the exact F-function correlation.
//
// Backward:
//
//     (A, B) -> (B, A XOR p)
//
// where p is the input mask of F and
//
//     C_F(p, B)
//
// is the exact F-function correlation.
//
// IMPORTANT:
//
// The F-function is D(S(x)), therefore a mask q at the output of F
// enters the S-box as D^T(q). The MITM implementation explicitly
// accounts for this transpose.
//
// ------------------------------------------------------------
// Exact reduced-round sanity oracle
// ------------------------------------------------------------
//
// For exactly two Feistel rounds, let:
////     input  masks = (a, b)
//     output masks = (A, B)
//
// After changing variables from (L0, R0) to (R0, R1), the complete
// two-round correlation factorizes:
////     C_2
//       = C_F(a XOR A, B)
//         * C_F(b XOR B, a)
//
// The sanity oracle computes each C_F independently by exhaustive
// evaluation of all 256 values of every S-box byte and the actual
// diffusion equations. It does NOT use the MITM LAT transition table.
//
// Therefore it independently checks:
//
//     MITM hull correlation
//
// against:
//
//     direct exhaustive two-round correlation
//
// The values are compared in canonical exact dyadic representation.
// Floating-point values are never used for the equality test.
//
// A result is only labelled an exact hull if:
//
//     1. neither MITM side was truncated, and
//     2. the independent two-round oracle agrees exactly.
//
// A disagreement causes a non-zero process exit in sanity-check mode.

use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::env;
use std::process;

// ============================================================
// Configuration
// ============================================================

#[derive(Clone, Debug)]
struct Config {
    total_rounds: usize,
    forward_rounds: usize,
    backward_rounds: usize,

    input_l: u64,
    input_r: u64,

    output_l: u64,
    output_r: u64,

    top_n: usize,
    max_states: usize,

    max_weight: f64,

    sanity_check: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            total_rounds: 4,
            forward_rounds: 2,
            backward_rounds: 2,

            input_l: 0x0000_0000_0000_0001,
            input_r: 0x0000_0000_0000_0000,

            output_l: 0x0000_0000_0000_0000,
            output_r: 0x0000_0000_0000_0001,

            top_n: 25,
            max_states: 1_000_000,

            max_weight: 32.0,

            sanity_check: false,
        }
    }
}

// ============================================================
// Types
// ============================================================

type LState = (u64, u64);

type Lat = [[i16; 256]; 256];

type ByteTransitions = Vec<ByteTransition>;

#[derive(Clone, Copy, Debug)]
struct ByteTransition {
    input_mask: u8,
    output_mask: u8,
    lat: i16,
}

// ============================================================
// Exact dyadic signed correlation
// ============================================================
//
// A correlation is:
//
//     numerator / 2^denominator_bits
//
// We canonicalize after every operation by removing powers of two
// from the numerator.
//
// This is important because otherwise a correlation such as:
//
//     1
//
// represented after many multiplications as:
//
//     2^128 / 2^128
//
// would approach the limits of i128 unnecessarily.
//
// Canonicalization keeps the numerator small and makes exact equality
// straightforward.
// ============================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinearDyadic {
    numerator: i128,
    denominator_bits: u32,
}

impl LinearDyadic {
    #[inline]
    fn zero() -> Self {
        Self {
            numerator: 0,
            denominator_bits: 0,
        }
    }

    #[inline]
    fn one() -> Self {
        Self {
            numerator: 1,
            denominator_bits: 0,
        }
    }

    #[inline]
    fn from_lat(lat: i16) -> Self {
        if lat == 0 {
            return Self::zero();
        }

        Self::canonical(Self {
            numerator: lat as i128,
            denominator_bits: 8,
        })
    }

    #[inline]
    fn canonical(mut self) -> Self {
        if self.numerator == 0 {
            return Self::zero();
        }

        while self.denominator_bits > 0 && (self.numerator & 1) == 0 {
            self.numerator >>= 1;
            self.denominator_bits -= 1;
        }

        self
    }

    #[inline]
    fn multiply(self, rhs: Self) -> Self {
        if self.numerator == 0 || rhs.numerator == 0 {
            return Self::zero();
        }

        let numerator = self.numerator * rhs.numerator;

        Self::canonical(Self {
            numerator,
            denominator_bits: self.denominator_bits + rhs.denominator_bits,
        })
    }

    #[inline]
    fn add(self, rhs: Self) -> Self {
        if self.numerator == 0 {
            return rhs;
        }

        if rhs.numerator == 0 {
            return self;
        }

        let denominator_bits = self.denominator_bits.max(rhs.denominator_bits);

        let lhs_shift = denominator_bits - self.denominator_bits;
        let rhs_shift = denominator_bits - rhs.denominator_bits;

        let numerator = (self.numerator << lhs_shift) + (rhs.numerator << rhs_shift);

        Self::canonical(Self {
            numerator,
            denominator_bits,
        })
    }

    #[inline]
    fn abs_f64(self) -> f64 {
        if self.numerator == 0 {
            return 0.0;
        }

        (self.numerator.abs() as f64) / 2f64.powi(self.denominator_bits as i32)
    }

    #[inline]
    fn signed_f64(self) -> f64 {
        if self.numerator == 0 {
            return 0.0;
        }

        (self.numerator as f64) / 2f64.powi(self.denominator_bits as i32)
    }

    #[inline]
    fn weight(self) -> f64 {
        let c = self.abs_f64();

        if c == 0.0 { f64::INFINITY } else { -c.log2() }
    }
}

// ============================================================
// LAT construction
// ============================================================

#[inline]
fn parity8(x: u8) -> bool {
    (x.count_ones() & 1) != 0
}

fn build_lat() -> Lat {
    let mut lat = [[0i16; 256]; 256];

    for input_mask in 0usize..256 {
        for output_mask in 0usize..256 {
            let mut sum = 0i16;

            for x in 0usize..256 {
                let input_parity = parity8((x as u8) & (input_mask as u8));

                let output_parity = parity8(HERRINGFISH_SBOX_V02[x] & (output_mask as u8));

                if input_parity == output_parity {
                    sum += 1;
                } else {
                    sum -= 1;
                }
            }

            lat[input_mask][output_mask] = sum;
        }
    }

    lat
}

// ============================================================
// Non-zero LAT transitions
// ============================================================

fn build_transitions(lat: &Lat) -> Vec<ByteTransitions> {
    let mut table = Vec::with_capacity(256);

    for input_mask in 0usize..256 {
        let mut transitions = Vec::new();

        for output_mask in 0usize..256 {
            let value = lat[input_mask][output_mask];

            if value != 0 {
                transitions.push(ByteTransition {
                    input_mask: input_mask as u8,
                    output_mask: output_mask as u8,
                    lat: value,
                });
            }
        }

        table.push(transitions);
    }

    table
}

// ============================================================
// Diffusion
// ============================================================
//
// Byte diffusion:
//
//     out[i] = in[i]
//            XOR in[(i + 1) mod 8]
//            XOR in[(i + 3) mod 8]
// ============================================================

#[inline]
fn diffuse_mask(mask: u64) -> u64 {
    let mut bytes = [0u8; 8];

    for i in 0..8 {
        bytes[i] = ((mask >> (8 * i)) & 0xff) as u8;
    }

    let mut out = [0u8; 8];

    for i in 0..8 {
        out[i] = bytes[i] ^ bytes[(i + 1) & 7] ^ bytes[(i + 3) & 7];
    }

    let mut result = 0u64;

    for i in 0..8 {
        result |= (out[i] as u64) << (8 * i);
    }

    result
}

// ============================================================
// Diffusion transpose
// ============================================================
//
// D[i] = X[i] XOR X[i+1] XOR X[i+3]
//
// Therefore:
//
// D^T[j] = Y[j] XOR Y[j-1] XOR Y[j-3]
// ============================================================

#[inline]
fn diffuse_transpose_mask(mask: u64) -> u64 {
    let mut input = [0u8; 8];

    for i in 0..8 {
        input[i] = ((mask >> (8 * i)) & 0xff) as u8;
    }

    let mut output = [0u8; 8];

    for j in 0..8 {
        output[j] = input[j] ^ input[(j + 7) & 7] ^ input[(j + 5) & 7];
    }

    let mut result = 0u64;

    for i in 0..8 {
        result |= (output[i] as u64) << (8 * i);
    }

    result
}

// ============================================================
// Inverse of D^T
// ============================================================
//
// The byte diffusion operates independently on each bit-plane.
//
// A bit-plane is therefore an 8-bit vector. We build the inverse
// mapping for that 8-bit linear transformation by exhaustive
// enumeration of all 256 bit-plane values.
//
// This is only a tiny 256-entry table and is completely independent
// of the S-box LAT.
// ============================================================

fn build_inverse_dt_plane() -> [u8; 256] {
    let mut inverse = [0u8; 256];
    let mut seen = [false; 256];

    for input in 0u16..256 {
        let input = input as u8;

        let mut output = 0u8;

        for j in 0..8 {
            let bit = ((input >> j) & 1)
                ^ ((input >> ((j + 7) & 7)) & 1)
                ^ ((input >> ((j + 5) & 7)) & 1);

            output |= bit << j;
        }

        if seen[output as usize] {
            panic!("Herringfish diffusion transpose is not invertible");
        }

        seen[output as usize] = true;
        inverse[output as usize] = input;
    }

    assert!(
        seen.iter().all(|&value| value),
        "Herringfish diffusion transpose is not invertible"
    );

    inverse
}

#[inline]
fn inverse_diffuse_transpose_mask(mask: u64, inverse_plane: &[u8; 256]) -> u64 {
    let mut result = 0u64;

    for bit in 0..8 {
        let mut plane = 0u8;

        for byte in 0..8 {
            let value = ((mask >> (byte * 8 + bit)) & 1) as u8;
            plane |= value << byte;
        }

        let source_plane = inverse_plane[plane as usize];

        for byte in 0..8 {
            if ((source_plane >> byte) & 1) != 0 {
                result |= 1u64 << (byte * 8 + bit);
            }
        }
    }

    result
}

// ============================================================
// MITM F transitions
// ============================================================
//
// F(x) = D(S(x))
//
// For:
//
//     C_F(p, q)
//
// the mask entering the S-box is:
//
//     D^T(q)
//
// Therefore:
//
//     C_F(p, q)
//       = C_S(p, D^T(q))
//
// The transition table itself is expressed in S-box-mask space.
// We therefore map each non-zero S-box output mask z through:
//
//     q = (D^T)^-1(z)
// ============================================================

fn f_transitions_for_input_mask(
    input_mask: u64,
    transitions: &[ByteTransitions],
    inverse_dt_plane: &[u8; 256],
) -> Vec<(u64, LinearDyadic)> {
    let mut partials: Vec<(u64, LinearDyadic)> = vec![(0, LinearDyadic::one())];

    for byte_index in 0..8 {
        let p = ((input_mask >> (byte_index * 8)) & 0xff) as usize;

        let byte_transitions = &transitions[p];

        let mut next = Vec::with_capacity(partials.len().saturating_mul(byte_transitions.len()));

        for &(partial_mask, partial_corr) in &partials {
            for transition in byte_transitions {
                let output_byte = transition.output_mask as u64;

                let output_mask = partial_mask | (output_byte << (byte_index * 8));

                let corr = partial_corr.multiply(LinearDyadic::from_lat(transition.lat));

                next.push((output_mask, corr));
            }
        }

        partials = next;

        if partials.is_empty() {
            break;
        }
    }

    let mut result = Vec::with_capacity(partials.len());

    for (sbox_output_mask, corr) in partials {
        let f_output_mask = inverse_diffuse_transpose_mask(sbox_output_mask, inverse_dt_plane);

        result.push((f_output_mask, corr));
    }

    result
}

// ============================================================
// Backward F transitions
// ============================================================
//
// Given F output mask q:
//
//     z = D^T(q)
//
// We enumerate every S-box input mask p for which:
//
//     LAT[p][z] != 0
//
// The inverse D^T is not needed in this direction because q is
// already known and we only need z.
// ============================================================

fn f_transitions_for_output_mask(
    output_mask: u64,
    transitions: &[ByteTransitions],
) -> Vec<(u64, LinearDyadic)> {
    let sbox_output_mask = diffuse_transpose_mask(output_mask);

    let mut partials: Vec<(u64, LinearDyadic)> = vec![(0, LinearDyadic::one())];

    for byte_index in 0..8 {
        let z = ((sbox_output_mask >> (byte_index * 8)) & 0xff) as u8;

        let mut byte_choices = Vec::new();

        for input_mask in 0usize..256 {
            for transition in &transitions[input_mask] {
                if transition.output_mask == z {
                    byte_choices.push(ByteTransition {
                        input_mask: input_mask as u8,
                        output_mask: z,
                        lat: transition.lat,
                    });
                }
            }
        }

        let mut next = Vec::with_capacity(partials.len().saturating_mul(byte_choices.len()));

        for &(partial_mask, partial_corr) in &partials {
            for transition in &byte_choices {
                let input_byte = transition.input_mask as u64;

                let input_mask = partial_mask | (input_byte << (byte_index * 8));

                let corr = partial_corr.multiply(LinearDyadic::from_lat(transition.lat));

                next.push((input_mask, corr));
            }
        }

        partials = next;

        if partials.is_empty() {
            break;
        }
    }

    partials
}

// ============================================================
// State score
// ============================================================

#[inline]
fn state_score(corr: LinearDyadic) -> f64 {
    corr.abs_f64()
}

// ============================================================
// Heap candidate
// ============================================================
//
// BinaryHeap is a max-heap. Ordering is reversed so the weakest
// retained candidate is at the top.
// ============================================================

#[derive(Clone, Copy, Debug)]
struct HeapCandidate {
    score: f64,
    state: LState,
}

impl PartialEq for HeapCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score && self.state == other.state
    }
}

impl Eq for HeapCandidate {}

impl PartialOrd for HeapCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        match self
            .score
            .partial_cmp(&other.score)
            .unwrap_or(Ordering::Equal)
        {
            Ordering::Equal => self.state.cmp(&other.state),

            Ordering::Less => Ordering::Greater,

            Ordering::Greater => Ordering::Less,
        }
    }
}

// ============================================================
// Propagation result
// ============================================================

struct PropagationResult {
    states: HashMap<LState, LinearDyadic>,
    generated: u64,
    truncated: bool,
}

// ============================================================
// Bounded state retention
// ============================================================

fn retain_bounded(
    candidates: HashMap<LState, LinearDyadic>,
    max_states: usize,
) -> (HashMap<LState, LinearDyadic>, bool) {
    if candidates.len() <= max_states {
        return (candidates, false);
    }

    let mut heap = BinaryHeap::with_capacity(max_states);

    for (&state, &corr) in &candidates {
        let candidate = HeapCandidate {
            score: state_score(corr),
            state,
        };

        if heap.len() < max_states {
            heap.push(candidate);
            continue;
        }

        let weakest = heap.peek().expect("heap must not be empty");

        if candidate.score > weakest.score {
            heap.pop();
            heap.push(candidate);
        }
    }

    let mut retained = HashMap::with_capacity(max_states);

    for candidate in heap {
        if let Some(corr) = candidates.get(&candidate.state) {
            retained.insert(candidate.state, *corr);
        }
    }

    (retained, true)
}

// ============================================================
// Forward one round
// ============================================================

fn expand_forward_round(
    states: &HashMap<LState, LinearDyadic>,
    transitions: &[ByteTransitions],
    inverse_dt_plane: &[u8; 256],
) -> (HashMap<LState, LinearDyadic>, u64) {
    let mut generated = 0u64;

    let mut next = HashMap::<LState, LinearDyadic>::new();

    for (&(input_l, input_r), &state_corr) in states {
        let f_transitions = f_transitions_for_input_mask(input_l, transitions, inverse_dt_plane);

        for (f_output_mask, f_corr) in f_transitions {
            let output_l = input_r ^ f_output_mask;

            let output_r = input_l;

            let state = (output_l, output_r);

            let corr = state_corr.multiply(f_corr);

            generated += 1;

            next.entry(state)
                .and_modify(|existing| {
                    *existing = existing.add(corr);
                })
                .or_insert(corr);
        }
    }

    (next, generated)
}

// ============================================================
// Backward one round
// ============================================================

fn expand_backward_round(
    states: &HashMap<LState, LinearDyadic>,
    transitions: &[ByteTransitions],
) -> (HashMap<LState, LinearDyadic>, u64) {
    let mut generated = 0u64;

    let mut next = HashMap::<LState, LinearDyadic>::new();

    for (&(output_l, output_r), &state_corr) in states {
        let f_transitions = f_transitions_for_output_mask(output_r, transitions);

        for (f_input_mask, f_corr) in f_transitions {
            let input_l = output_r;

            let input_r = output_l ^ f_input_mask;

            let state = (input_l, input_r);

            let corr = state_corr.multiply(f_corr);

            generated += 1;

            next.entry(state)
                .and_modify(|existing| {
                    *existing = existing.add(corr);
                })
                .or_insert(corr);
        }
    }

    (next, generated)
}

// ============================================================
// Forward propagation
// ============================================================

fn propagate_forward(
    start: LState,
    rounds: usize,
    transitions: &[ByteTransitions],
    inverse_dt_plane: &[u8; 256],
    max_states: usize,
) -> PropagationResult {
    let mut states = HashMap::<LState, LinearDyadic>::new();

    states.insert(start, LinearDyadic::one());

    let mut total_generated = 0u64;
    let mut truncated = false;

    for round in 0..rounds {
        let (expanded, generated) = expand_forward_round(&states, transitions, inverse_dt_plane);

        total_generated = total_generated.saturating_add(generated);

        let expanded_count = expanded.len();

        let (retained, was_truncated) = retain_bounded(expanded, max_states);

        truncated |= was_truncated;

        println!("  Round {:>2}: {:>12} states", round + 1, retained.len());

        println!("           Generated: {:>12}", generated);

        if was_truncated {
            println!(
                "           WARNING: state limit reached; \
                 retained strongest {} states from {} unique states",
                retained.len(),
                expanded_count
            );
        }

        states = retained;
    }

    PropagationResult {
        states,
        generated: total_generated,
        truncated,
    }
}

// ============================================================
// Backward propagation
// ============================================================

fn propagate_backward(
    start: LState,
    rounds: usize,
    transitions: &[ByteTransitions],
    max_states: usize,
) -> PropagationResult {
    let mut states = HashMap::<LState, LinearDyadic>::new();

    states.insert(start, LinearDyadic::one());

    let mut total_generated = 0u64;
    let mut truncated = false;

    for round in 0..rounds {
        let (expanded, generated) = expand_backward_round(&states, transitions);

        total_generated = total_generated.saturating_add(generated);

        let expanded_count = expanded.len();

        let (retained, was_truncated) = retain_bounded(expanded, max_states);

        truncated |= was_truncated;

        println!("  Round {:>2}: {:>12} states", round + 1, retained.len());

        println!("           Generated: {:>12}", generated);

        if was_truncated {
            println!(
                "           WARNING: state limit reached; \
                 retained strongest {} states from {} unique states",
                retained.len(),
                expanded_count
            );
        }

        states = retained;
    }

    PropagationResult {
        states,
        generated: total_generated,
        truncated,
    }
}

// ============================================================
// Meet in the middle
// ============================================================

struct HullResult {
    matches: usize,
    correlation: LinearDyadic,
    contributions: Vec<(LState, LinearDyadic)>,
}

fn meet_in_middle(
    forward: &HashMap<LState, LinearDyadic>,
    backward: &HashMap<LState, LinearDyadic>,
    top_n: usize,
) -> HullResult {
    let mut matches = 0usize;

    let mut total = LinearDyadic::zero();

    let mut contributions = Vec::<(LState, LinearDyadic)>::new();

    for (&state, &forward_corr) in forward {
        if let Some(&backward_corr) = backward.get(&state) {
            let contribution = forward_corr.multiply(backward_corr);

            total = total.add(contribution);

            contributions.push((state, contribution));

            matches += 1;
        }
    }

    contributions.sort_by(|a, b| {
        b.1.abs_f64()
            .partial_cmp(&a.1.abs_f64())
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    contributions.truncate(top_n);

    HullResult {
        matches,
        correlation: total,
        contributions,
    }
}

// ============================================================
// Independent direct F correlation
// ============================================================
//
// This function deliberately does NOT use:
//     - the LAT table
//     - MITM transition tables
//     - diffuse_transpose_mask()
//     - inverse_diffuse_transpose_mask()
//
// Instead it evaluates the actual S-box and diffusion equations
// directly.
//
// For one S-box byte x_i, the corresponding S-box output contributes
// to F output bytes:
//
//     i
//     i - 1
//     i - 3
//
// Therefore the output-mask contribution seen by S(x_i) is:
//
//     q_i XOR q_(i-1) XOR q_(i-3)
//
// The byte correlation is then exhaustively evaluated over all 256
// possible x_i values.
// ============================================================

fn direct_f_correlation(input_mask: u64, output_mask: u64) -> LinearDyadic {
    let mut result = LinearDyadic::one();

    for byte_index in 0..8 {
        let p = ((input_mask >> (byte_index * 8)) & 0xff) as u8;

        let q_i = ((output_mask >> (byte_index * 8)) & 0xff) as u8;

        let q_prev = ((output_mask >> (((byte_index + 7) & 7) * 8)) & 0xff) as u8;

        let q_prev3 = ((output_mask >> (((byte_index + 5) & 7) * 8)) & 0xff) as u8;

        let sbox_output_mask = q_i ^ q_prev ^ q_prev3;

        let mut sum = 0i16;

        for x in 0usize..256 {
            let x = x as u8;

            let input_bit = parity8(p & x);

            let output_bit = parity8(sbox_output_mask & HERRINGFISH_SBOX_V02[x as usize]);

            if input_bit == output_bit {
                sum += 1;
            } else {
                sum -= 1;
            }
        }

        if sum == 0 {
            return LinearDyadic::zero();
        }

        result = result.multiply(LinearDyadic::from_lat(sum));
    }

    result
}

// ============================================================
// Independent direct two-round oracle
// ============================================================
//
// Two-round Feistel:
//
//     L1 = R0
//     R1 = L0 XOR F(R0)
//
//     L2 = R1
//     R2 = R0 XOR F(R1)
//
// Input masks:
//
//     (a, b)
//
// Output masks:
//
//     (A, B)
//
// Change variables from:
//
//     (L0, R0)
//
// to:
//
//     (R1, R0)
//
// Since:
//
//     L0 = R1 XOR F(R0)
//
// the character exponent becomes:
//
//     (a XOR A) · R1
//     XOR B · F(R1)
//     XOR (b XOR B) · R0
//     XOR a · F(R0)
//
// and therefore:
//
//     C_2
//
//       = C_F(a XOR A, B)
//         * C_F(b XOR B, a)
//
// This is an independent computation of the complete two-round
// correlation. No intermediate mask enumeration is performed.
// ============================================================

fn direct_two_round_correlation(
    input_l: u64,
    input_r: u64,
    output_l: u64,
    output_r: u64,
) -> LinearDyadic {
    let first = direct_f_correlation(input_l ^ output_l, output_r);

    let second = direct_f_correlation(input_r ^ output_r, input_l);

    first.multiply(second)
}

// ============================================================
// Sanity check
// ============================================================

fn run_two_round_sanity_check(config: &Config, mitm: LinearDyadic) -> bool {
    println!();
    println!("============================================================");
    println!("INDEPENDENT 2-ROUND SANITY CHECK");
    println!("============================================================");

    if config.total_rounds != 2 || config.forward_rounds != 1 || config.backward_rounds != 1 {
        println!("Sanity oracle requires exactly:");

        println!("  --total 2 --forward 1 --backward 1");

        println!("Skipping independent two-round oracle.");

        return false;
    }

    println!("MITM hull correlation:");

    println!("  decimal = {:+.12e}", mitm.signed_f64());

    println!("  dyadic  = {}/2^{}", mitm.numerator, mitm.denominator_bits);

    println!();
    println!("Computing direct exhaustive two-round correlation...");

    let direct = direct_two_round_correlation(
        config.input_l,
        config.input_r,
        config.output_l,
        config.output_r,
    );

    println!("Direct exhaustive correlation:");

    println!("  decimal = {:+.12e}", direct.signed_f64());

    println!(
        "  dyadic  = {}/2^{}",
        direct.numerator, direct.denominator_bits
    );

    println!();

    if mitm == direct {
        println!("SANITY CHECK: PASS");

        println!(
            "MITM and direct exhaustive correlation \
             agree exactly in canonical dyadic form."
        );

        true
    } else {
        println!("SANITY CHECK: FAIL");

        println!("The MITM result and independent direct result disagree.");

        println!();
        println!("MITM:");

        println!("  {}/2^{}", mitm.numerator, mitm.denominator_bits);

        println!("DIRECT:");

        println!("  {}/2^{}", direct.numerator, direct.denominator_bits);

        false
    }
}

// ============================================================
// Parsing
// ============================================================

fn parse_u64(value: &str) -> Result<u64, String> {
    let stripped = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);

    u64::from_str_radix(stripped, 16).map_err(|_| format!("invalid hexadecimal value: {}", value))
}

fn require_value<'a>(args: &'a [String], index: usize, option: &'a str) -> Result<&'a str, String> {
    if index + 1 >= args.len() {
        return Err(format!("missing value for {}", option));
    }

    Ok(&args[index + 1])
}

fn parse_args() -> Result<Config, String> {
    let mut config = Config::default();

    let args: Vec<String> = env::args().skip(1).collect();

    let mut i = 0usize;

    while i < args.len() {
        match args[i].as_str() {
            "--total" => {
                let value = require_value(&args, i, "--total")?;

                config.total_rounds = value.parse().map_err(|_| "invalid --total".to_string())?;

                i += 2;
            }

            "--forward" => {
                let value = require_value(&args, i, "--forward")?;

                config.forward_rounds =
                    value.parse().map_err(|_| "invalid --forward".to_string())?;

                i += 2;
            }

            "--backward" => {
                let value = require_value(&args, i, "--backward")?;

                config.backward_rounds = value
                    .parse()
                    .map_err(|_| "invalid --backward".to_string())?;

                i += 2;
            }

            "--input-l" => {
                let value = require_value(&args, i, "--input-l")?;

                config.input_l = parse_u64(value)?;

                i += 2;
            }

            "--input-r" => {
                let value = require_value(&args, i, "--input-r")?;

                config.input_r = parse_u64(value)?;

                i += 2;
            }

            "--output-l" => {
                let value = require_value(&args, i, "--output-l")?;

                config.output_l = parse_u64(value)?;

                i += 2;
            }

            "--output-r" => {
                let value = require_value(&args, i, "--output-r")?;

                config.output_r = parse_u64(value)?;

                i += 2;
            }

            "--top" => {
                let value = require_value(&args, i, "--top")?;

                config.top_n = value.parse().map_err(|_| "invalid --top".to_string())?;

                i += 2;
            }

            "--max-states" => {
                let value = require_value(&args, i, "--max-states")?;

                config.max_states = value
                    .parse()
                    .map_err(|_| "invalid --max-states".to_string())?;

                i += 2;
            }

            "--max-weight" => {
                let value = require_value(&args, i, "--max-weight")?;

                config.max_weight = value
                    .parse()
                    .map_err(|_| "invalid --max-weight".to_string())?;

                i += 2;
            }

            "--sanity-check" => {
                config.sanity_check = true;
                i += 1;
            }

            "--help" | "-h" => {
                print_help();
                process::exit(0);
            }

            unknown => {
                return Err(format!("unknown argument: {}", unknown));
            }
        }
    }

    if config.total_rounds == 0 {
        return Err("--total must be greater than zero".to_string());
    }

    if config.forward_rounds + config.backward_rounds != config.total_rounds {
        return Err(format!(
            "round split mismatch: forward ({}) + \
             backward ({}) != total ({})",
            config.forward_rounds, config.backward_rounds, config.total_rounds
        ));
    }

    if config.max_states == 0 {
        return Err("--max-states must be greater than zero".to_string());
    }

    if config.top_n == 0 {
        return Err("--top must be greater than zero".to_string());
    }

    Ok(config)
}

// ============================================================
// Help
// ============================================================

fn print_help() {
    println!(
        r#"Herringfish Linear Hull Meet-in-the-Middle

Usage:

  cargo run --release --example linear_hull_meet_in_middle -- [options]

Options:

  --total N
      Total number of Feistel rounds.

  --forward N
      Number of rounds propagated from the input.

  --backward N
      Number of rounds propagated backwards from the output.

  --input-l HEX
      Input left linear mask.

  --input-r HEX
      Input right linear mask.

  --output-l HEX
      Output left linear mask.

  --output-r HEX
      Output right linear mask.

  --top N
      Number of strongest matching middle states to display.

  --max-states N
      Maximum number of retained states per propagation round.

  --max-weight W
      Informational maximum trail weight.

  --sanity-check
      For exactly two rounds, independently compute the complete
      correlation without the MITM transition machinery and compare
      it against the MITM result in exact dyadic form.

      A disagreement causes a non-zero exit status.

Example:

  cargo run --release --example linear_hull_meet_in_middle -- \
      --total 2 \
      --forward 1 \
      --backward 1 \
      --input-l 0x1 \
      --input-r 0x0 \
      --output-l 0x0 \
      --output-r 0x1 \
      --top 25 \
      --max-states 100000000 \
      --sanity-check
"#
    );
}

// ============================================================
// Main
// ============================================================

fn main() {
    let config = match parse_args() {
        Ok(config) => config,

        Err(error) => {
            eprintln!("ERROR: {}", error);

            eprintln!();

            print_help();

            process::exit(2);
        }
    };

    println!(
        "HERRINGFISH LINEAR HULL \
         MEET-IN-THE-MIDDLE"
    );

    println!("============================================================");

    println!("Total rounds:      {}", config.total_rounds);

    println!("Forward rounds:    {}", config.forward_rounds);

    println!("Backward rounds:   {}", config.backward_rounds);

    println!("Max trail weight:  {:.4}", config.max_weight);

    println!("Max states:        {}", config.max_states);

    println!(
        "Sanity check:      {}",
        if config.sanity_check {
            "enabled"
        } else {
            "disabled"
        }
    );

    println!(
        "Input:  L=0x{:016x} R=0x{:016x}",
        config.input_l, config.input_r
    );

    println!(
        "Output: L=0x{:016x} R=0x{:016x}",
        config.output_l, config.output_r
    );

    // --------------------------------------------------------
    // LAT
    // --------------------------------------------------------

    println!();
    println!("Building LAT...");

    let lat = build_lat();

    println!("  LAT[0][0] = {}", lat[0][0]);

    // --------------------------------------------------------
    // Transition table
    // --------------------------------------------------------

    println!("Building non-zero transition table...");

    let transitions = build_transitions(&lat);

    let non_zero_entries: usize = transitions.iter().map(|v| v.len()).sum();

    println!("  Non-zero LAT entries: {}", non_zero_entries);

    // --------------------------------------------------------
    // Diffusion sanity checks
    // --------------------------------------------------------

    let inverse_dt_plane = build_inverse_dt_plane();

    println!("Checking diffusion...");

    let probe = 0x0000_0000_0000_0001u64;

    let d_probe = diffuse_mask(probe);

    let dt_probe = diffuse_transpose_mask(probe);

    let recovered_probe = inverse_diffuse_transpose_mask(dt_probe, &inverse_dt_plane);

    println!("  D(probe)    = 0x{:016x}", d_probe);

    println!("  D^T(probe)  = 0x{:016x}", dt_probe);

    println!("  D^-T(D^T(probe)) = 0x{:016x}", recovered_probe);

    if recovered_probe != probe {
        eprintln!("ERROR: diffusion transpose inverse failed.");

        process::exit(3);
    }

    // --------------------------------------------------------
    // Forward
    // --------------------------------------------------------

    println!();

    println!("Forward propagation: {} rounds", config.forward_rounds);

    let forward = propagate_forward(
        (config.input_l, config.input_r),
        config.forward_rounds,
        &transitions,
        &inverse_dt_plane,
        config.max_states,
    );

    // --------------------------------------------------------
    // Backward
    // --------------------------------------------------------

    println!();

    println!("Backward propagation: {} rounds", config.backward_rounds);

    let backward = propagate_backward(
        (config.output_l, config.output_r),
        config.backward_rounds,
        &transitions,
        config.max_states,
    );

    // --------------------------------------------------------
    // Meet in the middle
    // --------------------------------------------------------

    println!();

    println!("============================================================");

    println!("MEET-IN-THE-MIDDLE");

    println!("============================================================");

    println!("Forward states:      {}", forward.states.len());

    println!("Backward states:     {}", backward.states.len());

    println!("Forward generated:   {}", forward.generated);

    println!("Backward generated:  {}", backward.generated);

    let result = meet_in_middle(&forward.states, &backward.states, config.top_n);

    println!("Matching states:     {}", result.matches);

    // --------------------------------------------------------
    // Hull
    // --------------------------------------------------------

    println!();
    println!("LINEAR HULL");

    println!("------------------------------------------------------------");

    if result.matches == 0 {
        println!("No matching middle states.");
    } else {
        println!(
            "Hull correlation:    {:+.12e}",
            result.correlation.signed_f64()
        );

        println!("Hull |correlation|:  {:.12e}", result.correlation.abs_f64());

        println!("Hull weight:         {:.6}", result.correlation.weight());

        println!(
            "Hull dyadic:         {}/2^{}",
            result.correlation.numerator, result.correlation.denominator_bits
        );

        println!();
        println!("Strongest middle-state contributions:");

        for (index, &(state, contribution)) in result.contributions.iter().enumerate() {
            println!(
                "#{:<3} \
                 L=0x{:016x} \
                 R=0x{:016x} \
                 C={:+.8e} \
                 |C|={:.8e} \
                 W={:.4} \
                 D={}/2^{}",
                index + 1,
                state.0,
                state.1,
                contribution.signed_f64(),
                contribution.abs_f64(),
                contribution.weight(),
                contribution.numerator,
                contribution.denominator_bits,
            );
        }
    }

    // --------------------------------------------------------
    // Exactness status
    // --------------------------------------------------------

    println!();

    let propagation_exact = !forward.truncated && !backward.truncated;

    if !propagation_exact {
        println!("WARNING: propagation was truncated.");

        println!(
            "The reported hull is a bounded approximation, \
             not the complete exact hull."
        );
    } else {
        println!("Propagation was not truncated.");
    }

    // --------------------------------------------------------
    // Independent sanity oracle
    // --------------------------------------------------------

    if config.sanity_check {
        if !propagation_exact {
            println!();
            println!("SANITY CHECK: NOT VALID");
            println!(
                "The MITM propagation was truncated, so the \
             result cannot be certified as the complete hull."
            );

            process::exit(4);
        }

        let sanity_ok = run_two_round_sanity_check(&config, result.correlation);

        if !sanity_ok {
            process::exit(5);
        }

        println!();
        println!("============================================================");
        println!("EXACT HULL CERTIFICATION");
        println!("============================================================");

        println!(
            "PASS: MITM and independent direct two-round \
         evaluation agree exactly."
        );

        println!(
            "Canonical correlation: {}/2^{}",
            result.correlation.numerator, result.correlation.denominator_bits
        );
    } else if propagation_exact {
        println!(
            "The MITM propagation itself was exact, but no \
         independent oracle was requested."
        );

        if config.total_rounds == 2 {
            println!(
                "Use --sanity-check to independently certify \
             the two-round result."
            );
        }
    }

    println!();
    println!("Done.");
}
