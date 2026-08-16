#![allow(clippy::all)]
#![allow(dead_code)]

use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;
use std::collections::HashMap;
use std::fs;
use std::ops::Neg;
use std::path::Path;

// ============================================================
// Configuration
// ============================================================

const TOTAL_ROUNDS: usize = 2;
const FORWARD_ROUNDS: usize = 1;
const BACKWARD_ROUNDS: usize = 1;

const TOP_OUTPUTS: usize = 25;

const INPUT_DL: u64 = 0x0000_0000_0000_0000;
const INPUT_DR: u64 = 0x0000_0000_0000_0001;

// One byte transition has denominator 2^8.
// For one round, at most 8 active S-boxes => 2^64.
// For two rounds => 2^128.
//
// We DO NOT represent 2^128 in u128.
// Instead, all probabilities are stored as integer
// numerators with an implicit denominator of 2^128.

const TOTAL_PROBABILITY_BITS: usize = 128;

// ============================================================
// Exact probability
// ============================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Dyadic {
    numerator: u128,
    denominator_bits: u32,
}

impl Dyadic {
    fn zero() -> Self {
        Self {
            numerator: 0,
            denominator_bits: 0,
        }
    }

    fn one() -> Self {
        Self {
            numerator: 1,
            denominator_bits: 0,
        }
    }

    fn from_ddt_count(count: u16) -> Self {
        if count == 0 {
            return Self::zero();
        }

        Self {
            numerator: count as u128,
            denominator_bits: 8,
        }
    }

    fn multiply(self, rhs: Self) -> Self {
        if self.numerator == 0 || rhs.numerator == 0 {
            return Self::zero();
        }

        Self {
            numerator: self.numerator * rhs.numerator,
            denominator_bits: self.denominator_bits + rhs.denominator_bits,
        }
    }

    fn add(self, rhs: Self) -> Self {
        if self.numerator == 0 {
            return rhs;
        }

        if rhs.numerator == 0 {
            return self;
        }

        if self.denominator_bits == rhs.denominator_bits {
            return Self {
                numerator: self.numerator + rhs.numerator,
                denominator_bits: self.denominator_bits,
            };
        }

        if self.denominator_bits > rhs.denominator_bits {
            let shift = self.denominator_bits - rhs.denominator_bits;

            return Self {
                numerator: self.numerator + (rhs.numerator << shift),
                denominator_bits: self.denominator_bits,
            };
        }

        let shift = rhs.denominator_bits - self.denominator_bits;

        Self {
            numerator: (self.numerator << shift) + rhs.numerator,
            denominator_bits: rhs.denominator_bits,
        }
    }

    fn normalize_to_bits(self, target_bits: u32) -> Self {
        if self.numerator == 0 {
            return Self {
                numerator: 0,
                denominator_bits: target_bits,
            };
        }

        assert!(
            self.denominator_bits <= target_bits,
            "Cannot normalize probability upward in denominator bits"
        );

        let shift = target_bits - self.denominator_bits;

        Self {
            numerator: self.numerator << shift,
            denominator_bits: target_bits,
        }
    }

    fn probability_f64(self) -> f64 {
        if self.numerator == 0 {
            return 0.0;
        }

        let n = self.numerator as f64;
        n / 2f64.powi(self.denominator_bits as i32)
    }

    fn log2_probability(self) -> f64 {
        if self.numerator == 0 {
            return f64::NEG_INFINITY;
        }

        (self.numerator as f64).log2() - self.denominator_bits as f64
    }
}

// ============================================================
// Differential state
// ============================================================

type State = (u64, u64);

// ============================================================
// Paths / reference tables
// ============================================================

fn table_paths() -> Vec<(&'static str, &'static str)> {
    vec![
        ("ddt_matrix.txt", "docs/tables/ddt_matrix.txt"),
        ("sbox_accepted.txt", "docs/tables/sbox_accepted.txt"),
        (
            "kat_reduced_rounds_v02.txt",
            "docs/tables/kat_reduced_rounds_v02.txt",
        ),
        ("kat_reduced_all.txt", "docs/tables/kat_reduced_all.txt"),
        ("kat_expanded_v02.txt", "docs/tables/kat_expanded_v02.txt"),
        ("kat_vectors_v02.txt", "docs/tables/kat_vectors_v02.txt"),
        ("lat_matrix.txt", "docs/tables/lat_matrix.txt"),
    ]
}

// ============================================================
// DDT
// ============================================================

type Ddt = [[u16; 256]; 256];

fn build_ddt_from_sbox() -> Ddt {
    let mut ddt = [[0u16; 256]; 256];

    for dx in 0..256 {
        for x in 0..256 {
            let dy = HERRINGFISH_SBOX_V02[x ^ dx] ^ HERRINGFISH_SBOX_V02[x];

            ddt[dx][dy as usize] += 1;
        }
    }

    ddt
}

fn parse_ddt_file(path: &Path) -> Result<Ddt, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

    let mut rows: Vec<Vec<u16>> = Vec::new();

    for line in text.lines() {
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        if line.starts_with('#') {
            continue;
        }

        let values: Vec<u16> = line
            .split_whitespace()
            .filter_map(|token| {
                let cleaned = token.trim_matches(|c: char| !c.is_ascii_hexdigit());

                if cleaned.is_empty() {
                    return None;
                }

                if let Ok(v) = cleaned.parse::<u16>() {
                    return Some(v);
                }

                if let Some(hex) = cleaned.strip_prefix("0x") {
                    return u16::from_str_radix(hex, 16).ok();
                }

                None
            })
            .collect();

        if values.len() >= 256 {
            rows.push(values);
        }
    }

    if rows.len() < 256 {
        return Err(format!(
            "Could not find 256 DDT rows in {}. Found {} rows.",
            path.display(),
            rows.len()
        ));
    }

    let mut ddt = [[0u16; 256]; 256];

    for dx in 0..256 {
        if rows[dx].len() < 256 {
            return Err(format!(
                "DDT row {} contains only {} values",
                dx,
                rows[dx].len()
            ));
        }

        for dy in 0..256 {
            ddt[dx][dy] = rows[dx][dy];
        }
    }

    Ok(ddt)
}

fn load_exact_ddt(path: &Path) -> Result<Ddt, String> {
    parse_ddt_file(path)
}

// ============================================================
// DDT validation
// ============================================================

fn validate_ddt_rows(ddt: &Ddt) -> Result<(), String> {
    for dx in 0..256 {
        let sum: u32 = ddt[dx].iter().map(|&x| x as u32).sum();

        if sum != 256 {
            return Err(format!("DDT row dx=0x{dx:02x} sums to {sum}, expected 256"));
        }
    }

    Ok(())
}

fn validate_ddt_against_sbox(ddt: &Ddt) -> bool {
    let reference = build_ddt_from_sbox();

    for dx in 0..256 {
        for dy in 0..256 {
            if ddt[dx][dy] != reference[dx][dy] {
                println!(
                    "Mismatch at dx=0x{dx:02x}, dy=0x{dy:02x}: file={}, S-box={}",
                    ddt[dx][dy], reference[dx][dy]
                );

                return false;
            }
        }
    }

    true
}

fn print_ddt_validation(ddt: &Ddt, dx: usize) {
    println!("------------------------------------------------------------");
    println!("DDT VALIDATION");
    println!("------------------------------------------------------------");

    let non_zero = ddt[dx].iter().filter(|&&x| x != 0).count();

    let max_count = *ddt[dx].iter().max().unwrap_or(&0);

    let max_probability = max_count as f64 / 256.0;

    let max_weight = if max_probability > 0.0 {
        -max_probability.log2()
    } else {
        f64::INFINITY
    };

    println!("S-box size: 256 × 256");
    println!("Examining dx = 0x{dx:02x}");
    println!("Non-zero transitions: {non_zero}");
    println!("Maximum differential count: {max_count}");
    println!("Maximum probability: {:.6e}", max_probability);
    println!("Maximum -log2(P): {:.4}", max_weight);

    let mut entries: Vec<(usize, u16)> = ddt[dx]
        .iter()
        .enumerate()
        .filter(|&(_, count)| *count != 0)
        .map(|(dy, count)| (dy, *count))
        .collect();

    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    println!();
    println!("Top DDT transitions:");

    for (rank, &(dy, count)) in entries.iter().take(10).enumerate() {
        let p = count as f64 / 256.0;

        println!(
            "#{:2}  dx=0x{:02x}  dy=0x{:02x}  count={:3}  P={:.6e}",
            rank + 1,
            dx,
            dy,
            count,
            p
        );
    }

    let sum: u32 = ddt[dx].iter().map(|&x| x as u32).sum();

    println!();
    println!("DDT row count sum: {sum} / 256");

    if sum == 256 {
        println!("DDT row validation: PASS");
    } else {
        println!("DDT row validation: FAIL");
    }
}

// ============================================================
// Diffusion
// ============================================================

fn diffuse(t: u64) -> u64 {
    let mut bytes = [0u8; 8];

    for i in 0..8 {
        bytes[i] = ((t >> (8 * i)) & 0xff) as u8;
    }

    let mut out = [0u8; 8];

    for i in 0..8 {
        out[i] = bytes[i] ^ bytes[(i + 1) % 8] ^ bytes[(i + 3) % 8];
    }

    let mut result = 0u64;

    for i in 0..8 {
        result |= (out[i] as u64) << (8 * i);
    }

    result
}

// ============================================================
// Differential round
// ============================================================
//
// Feistel differential transition:
//
//   ΔL' = ΔR
//   ΔR' = ΔL XOR F(ΔR)
//
// F consists of:
//
//   bytewise S-box differential
//   followed by diffuse()
//
// ============================================================

fn active_byte_indices(value: u64) -> Vec<usize> {
    let mut result = Vec::new();

    for i in 0..8 {
        if ((value >> (8 * i)) & 0xff) != 0 {
            result.push(i);
        }
    }

    result
}

fn enumerate_byte_transitions(ddt: &Ddt, dx: u8) -> Vec<(u8, u16)> {
    let mut result = Vec::new();

    for dy in 0..256 {
        let count = ddt[dx as usize][dy];

        if count != 0 {
            result.push((dy as u8, count));
        }
    }

    result
}

// ============================================================
// Exact round expansion
// ============================================================

fn expand_round(ddt: &Ddt, input: &HashMap<State, Dyadic>) -> HashMap<State, Dyadic> {
    let mut output: HashMap<State, Dyadic> = HashMap::new();

    for (state, probability) in input.iter() {
        let dl = state.0;
        let dr = state.1;

        let active = active_byte_indices(dr);

        if active.is_empty() {
            let next = (dr, dl);

            let entry = output.entry(next).or_insert_with(Dyadic::zero);

            *entry = entry.add(*probability);

            continue;
        }

        let mut choices: Vec<Vec<(u8, u16)>> = Vec::with_capacity(active.len());

        for &index in active.iter() {
            let dx = ((dr >> (8 * index)) & 0xff) as u8;

            choices.push(enumerate_byte_transitions(ddt, dx));
        }

        let total_combinations: usize = choices.iter().map(|v| v.len()).product();

        for combination in 0..total_combinations {
            let mut selector = combination;

            let mut t_value = 0u64;

            let mut path_count: u128 = 1;

            for (byte_index, &state_byte_index) in active.iter().enumerate() {
                let list = &choices[byte_index];

                let choice = selector % list.len();
                selector /= list.len();

                let (dy, count) = list[choice];

                t_value |= (dy as u64) << (8 * state_byte_index);

                path_count *= count as u128;
            }

            let f_out = diffuse(t_value);

            let dl_next = dr;
            let dr_next = dl ^ f_out;

            let transition_probability = Dyadic {
                numerator: path_count,
                denominator_bits: (active.len() * 8) as u32,
            };

            let contribution = probability.multiply(transition_probability);

            let entry = output
                .entry((dl_next, dr_next))
                .or_insert_with(Dyadic::zero);

            *entry = entry.add(contribution);
        }
    }

    output
}

// ============================================================
// Probability mass
// ============================================================

fn total_probability(map: &HashMap<State, Dyadic>) -> Dyadic {
    let mut total = Dyadic::zero();

    for probability in map.values() {
        total = total.add(*probability);
    }

    total
}

fn print_probability_mass(label: &str, map: &HashMap<State, Dyadic>) {
    let total = total_probability(map);

    println!("{label}:");
    println!("  Numerator        : {}", total.numerator);
    println!("  Denominator bits : {}", total.denominator_bits);
    println!("  Probability      : {:.20e}", total.probability_f64());
    println!(
        "  -log2(P)         : {:.12}",
        total.log2_probability().neg()
    );
}

// ============================================================
// Sorting / reporting
// ============================================================

fn sorted_states(map: &HashMap<State, Dyadic>) -> Vec<(State, Dyadic)> {
    let mut values: Vec<(State, Dyadic)> = map
        .iter()
        .map(|(state, probability)| (*state, *probability))
        .collect();

    values.sort_by(|a, b| {
        b.1.numerator
            .cmp(&a.1.numerator)
            .then_with(|| a.0.0.cmp(&b.0.0))
            .then_with(|| a.0.1.cmp(&b.0.1))
    });

    values
}

fn print_top_states(title: &str, map: &HashMap<State, Dyadic>, count: usize) {
    println!();
    println!("------------------------------------------------------------");
    println!("{title}");
    println!("------------------------------------------------------------");

    println!(
        "{:<6} {:18} {:18} {:20} {:12}",
        "#", "ΔL", "ΔR", "Probability", "-log2(P)"
    );

    for (rank, (state, probability)) in sorted_states(map).into_iter().take(count).enumerate() {
        println!(
            "{:<6} 0x{:016x} 0x{:016x} {:.10e} {:12.6}",
            rank + 1,
            state.0,
            state.1,
            probability.probability_f64(),
            -probability.log2_probability()
        );
    }
}

// ============================================================
// MITM backward expansion
// ============================================================
//
// For a forward Feistel transition:
//
//   L1 = R0
//   R1 = L0 XOR F(R0)
//
// Given output (L1,R1), recover predecessor:
//
//   R0 = L1
//   L0 = R1 XOR F(R0)
//
// The probability of a predecessor transition is exactly
// the same DDT-derived transition probability used forward.
// ============================================================

fn expand_backward(ddt: &Ddt, output_map: &HashMap<State, Dyadic>) -> HashMap<State, Dyadic> {
    let mut result: HashMap<State, Dyadic> = HashMap::new();

    for (state, probability) in output_map.iter() {
        let dl_out = state.0;
        let dr_out = state.1;

        let dr_prev = dl_out;

        let active = active_byte_indices(dr_prev);

        if active.is_empty() {
            let dl_prev = dr_out;

            let predecessor = (dl_prev, dr_prev);

            let entry = result.entry(predecessor).or_insert_with(Dyadic::zero);

            *entry = entry.add(*probability);

            continue;
        }

        let mut choices: Vec<Vec<(u8, u16)>> = Vec::with_capacity(active.len());

        for &index in active.iter() {
            let dx = ((dr_prev >> (8 * index)) & 0xff) as u8;

            choices.push(enumerate_byte_transitions(ddt, dx));
        }

        let total_combinations: usize = choices.iter().map(|v| v.len()).product();

        for combination in 0..total_combinations {
            let mut selector = combination;

            let mut t_value = 0u64;

            let mut path_count: u128 = 1;

            for (byte_index, &state_byte_index) in active.iter().enumerate() {
                let list = &choices[byte_index];

                let choice = selector % list.len();
                selector /= list.len();

                let (dy, count) = list[choice];

                t_value |= (dy as u64) << (8 * state_byte_index);

                path_count *= count as u128;
            }

            let f_out = diffuse(t_value);

            let dl_prev = dr_out ^ f_out;

            let transition_probability = Dyadic {
                numerator: path_count,
                denominator_bits: (active.len() * 8) as u32,
            };

            let contribution = probability.multiply(transition_probability);

            let entry = result
                .entry((dl_prev, dr_prev))
                .or_insert_with(Dyadic::zero);

            *entry = entry.add(contribution);
        }
    }

    result
}

// ============================================================
// Exact MITM hull
// ============================================================

fn calculate_mitm_hull(
    forward: &HashMap<State, Dyadic>,
    backward: &HashMap<State, Dyadic>,
) -> HashMap<State, Dyadic> {
    let mut result = HashMap::new();

    for (middle, forward_probability) in forward.iter() {
        if let Some(backward_probability) = backward.get(middle) {
            let contribution = forward_probability.multiply(*backward_probability);

            result.insert(*middle, contribution);
        }
    }

    result
}

// ============================================================
// Main
// ============================================================

fn main() {
    println!("============================================================");
    println!("HERRINGFISH EXACT 2-ROUND DIFFERENTIAL HULL");
    println!("============================================================");
    println!();

    println!("Configuration:");
    println!("  Total rounds          : {TOTAL_ROUNDS}");
    println!("  Forward rounds        : {FORWARD_ROUNDS}");
    println!("  Backward rounds       : {BACKWARD_ROUNDS}");
    println!("  TOP OUTPUTS           : {TOP_OUTPUTS}");
    println!("  State pruning         : DISABLED");
    println!("  Probability arithmetic: EXACT INTEGER");
    println!("  Probability denominator: 2^128");
    println!("  DDT source            : ddt_matrix.txt");
    println!();
    println!("  Input ΔL              : 0x{INPUT_DL:016x}");
    println!("  Input ΔR              : 0x{INPUT_DR:016x}");
    println!();

    // --------------------------------------------------------
    // Reference tables
    // --------------------------------------------------------

    println!("------------------------------------------------------------");
    println!("HERRINGFISH REFERENCE TABLES");
    println!("------------------------------------------------------------");

    for (_name, path) in table_paths() {
        let status = if Path::new(path).exists() {
            "FOUND"
        } else {
            "MISSING"
        };

        println!("  {:<70} {}", path, status);
    }

    println!();

    // --------------------------------------------------------
    // DDT
    // --------------------------------------------------------

    let ddt_path = table_paths()[0].1;

    println!("------------------------------------------------------------");
    println!("LOADING EXACT DDT");
    println!("------------------------------------------------------------");
    println!("Loading DDT from:");
    println!("  {ddt_path}");

    let ddt = match load_exact_ddt(Path::new(ddt_path)) {
        Ok(ddt) => {
            println!("DDT construction/loading: COMPLETE");
            ddt
        }

        Err(error) => {
            eprintln!("ERROR: {error}");
            return;
        }
    };

    match validate_ddt_rows(&ddt) {
        Ok(()) => {
            println!("DDT row validation: PASS");
        }

        Err(error) => {
            eprintln!("DDT row validation: FAIL");
            eprintln!("{error}");
            return;
        }
    }

    println!();

    // --------------------------------------------------------
    // DDT vs S-box
    // --------------------------------------------------------

    println!("------------------------------------------------------------");
    println!("DDT ↔ S-BOX IMPLEMENTATION VALIDATION");
    println!("------------------------------------------------------------");

    if validate_ddt_against_sbox(&ddt) {
        println!("DDT file matches HERRINGFISH_SBOX_V02: PASS");
    } else {
        println!("DDT file matches HERRINGFISH_SBOX_V02: FAIL");
        return;
    }

    println!();

    // --------------------------------------------------------
    // DDT inspection
    // --------------------------------------------------------

    print_ddt_validation(&ddt, 0x01);

    println!();

    // --------------------------------------------------------
    // Initial state
    // --------------------------------------------------------

    println!("------------------------------------------------------------");
    println!("INITIAL DIFFERENTIAL STATE");
    println!("------------------------------------------------------------");

    println!("ΔL = 0x{INPUT_DL:016x}");

    println!("ΔR = 0x{INPUT_DR:016x}");

    println!("Active ΔR bytes = {}", active_byte_indices(INPUT_DR).len());

    // --------------------------------------------------------
    // Forward half
    // --------------------------------------------------------

    println!();
    println!("============================================================");
    println!("FORWARD HALF");
    println!("============================================================");

    let mut forward: HashMap<State, Dyadic> = HashMap::new();

    forward.insert((INPUT_DL, INPUT_DR), Dyadic::one());

    for round in 0..FORWARD_ROUNDS {
        println!();
        println!(
            "Forward round {} input states: {}",
            round + 1,
            forward.len()
        );

        forward = expand_round(&ddt, &forward);

        println!(
            "Forward round {} output states: {}",
            round + 1,
            forward.len()
        );

        let mass = total_probability(&forward);

        println!("Forward probability mass: {:.20e}", mass.probability_f64());
    }

    print_top_states("TOP FORWARD MIDDLE STATES", &forward, TOP_OUTPUTS);

    // --------------------------------------------------------
    // Select strongest forward middle
    // --------------------------------------------------------

    let selected_middle = sorted_states(&forward).into_iter().next();

    if let Some((middle, probability)) = selected_middle {
        println!();
        println!("------------------------------------------------------------");
        println!("STRONGEST FORWARD MIDDLE");
        println!("------------------------------------------------------------");

        println!("Middle ΔL = 0x{:016x}", middle.0);

        println!("Middle ΔR = 0x{:016x}", middle.1);

        println!("P(Input → Middle) = {:.20e}", probability.probability_f64());

        println!("-log2(P) = {:.12}", -probability.log2_probability());
    }

    // --------------------------------------------------------
    // Exact output expansion
    // --------------------------------------------------------

    println!();
    println!("============================================================");
    println!("EXACT 2-ROUND OUTPUT ENUMERATION");
    println!("============================================================");

    let mut outputs: HashMap<State, Dyadic> = HashMap::new();

    outputs.insert((INPUT_DL, INPUT_DR), Dyadic::one());

    for round in 0..TOTAL_ROUNDS {
        println!();
        println!("Round {} input states : {}", round + 1, outputs.len());

        outputs = expand_round(&ddt, &outputs);

        println!("Round {} output states: {}", round + 1, outputs.len());

        let mass = total_probability(&outputs);

        println!(
            "Round {} probability mass: {:.20e}",
            round + 1,
            mass.probability_f64()
        );
    }

    // --------------------------------------------------------
    // Output statistics
    // --------------------------------------------------------

    println!();
    println!("------------------------------------------------------------");
    println!("2-ROUND OUTPUT STATISTICS");
    println!("------------------------------------------------------------");

    println!("Unique output states : {}", outputs.len());

    let total_output_probability = total_probability(&outputs);

    println!("Total probability mass:");

    println!(
        "  Numerator        : {}",
        total_output_probability.numerator
    );

    println!(
        "  Denominator bits : {}",
        total_output_probability.denominator_bits
    );

    println!(
        "  Probability      : {:.20e}",
        total_output_probability.probability_f64()
    );

    println!(
        "  -log2(P)         : {:.12}",
        -total_output_probability.log2_probability()
    );

    let conservation = (total_output_probability.probability_f64() - 1.0).abs() < 1e-12;

    println!();
    println!(
        "Probability conservation : {}",
        if conservation { "PASS" } else { "FAIL" }
    );

    // --------------------------------------------------------
    // Top outputs
    // --------------------------------------------------------

    print_top_states("TOP 2-ROUND OUTPUT HULLS", &outputs, TOP_OUTPUTS);

    // --------------------------------------------------------
    // Best output
    // --------------------------------------------------------

    let best_output = sorted_states(&outputs).into_iter().next();

    if let Some((output, probability)) = best_output {
        println!();
        println!("------------------------------------------------------------");
        println!("BEST 2-ROUND DIFFERENTIAL");
        println!("------------------------------------------------------------");

        println!("Output ΔL = 0x{:016x}", output.0);

        println!("Output ΔR = 0x{:016x}", output.1);

        println!("Hull probability = {:.20e}", probability.probability_f64());

        println!("-log2(P) = {:.12}", -probability.log2_probability());
    }

    // --------------------------------------------------------
    // Backward half from strongest output
    // --------------------------------------------------------

    if let Some((target_output, direct_probability)) = sorted_states(&outputs).into_iter().next() {
        println!();
        println!("============================================================");
        println!("BACKWARD HALF / MITM VALIDATION");
        println!("============================================================");

        println!("Target output ΔL = 0x{:016x}", target_output.0);

        println!("Target output ΔR = 0x{:016x}", target_output.1);

        println!();

        let mut backward_output_map = HashMap::new();

        backward_output_map.insert(target_output, Dyadic::one());

        let mut backward = backward_output_map;

        for round in 0..BACKWARD_ROUNDS {
            println!(
                "Backward round {} input states : {}",
                round + 1,
                backward.len()
            );

            backward = expand_backward(&ddt, &backward);

            println!(
                "Backward round {} output states: {}",
                round + 1,
                backward.len()
            );

            let mass = total_probability(&backward);

            println!("Backward probability mass: {:.20e}", mass.probability_f64());
        }

        // ----------------------------------------------------
        // MITM intersection
        // ----------------------------------------------------

        let hull = calculate_mitm_hull(&forward, &backward);

        println!();
        println!("------------------------------------------------------------");
        println!("MITM INTERSECTION");
        println!("------------------------------------------------------------");

        println!("Forward states  : {}", forward.len());

        println!("Backward states : {}", backward.len());

        println!("Matching states : {}", hull.len());

        if let Some((middle, contribution)) = sorted_states(&hull).into_iter().next() {
            println!();
            println!("Strongest matching middle:");

            println!("  ΔL = 0x{:016x}", middle.0);

            println!("  ΔR = 0x{:016x}", middle.1);

            let forward_probability = forward.get(&middle).copied().unwrap_or_else(Dyadic::zero);

            let backward_probability = backward.get(&middle).copied().unwrap_or_else(Dyadic::zero);

            println!(
                "  Forward  P = {:.20e}",
                forward_probability.probability_f64()
            );

            println!(
                "  Backward P = {:.20e}",
                backward_probability.probability_f64()
            );

            println!("  Contribution = {:.20e}", contribution.probability_f64());

            println!(
                "  Contribution -log2(P) = {:.12}",
                -contribution.log2_probability()
            );

            println!();
            println!(
                "Direct 2-round hull = {:.20e}",
                direct_probability.probability_f64()
            );

            println!(
                "MITM reconstructed hull = {:.20e}",
                contribution.probability_f64()
            );

            let difference =
                (direct_probability.probability_f64() - contribution.probability_f64()).abs();

            println!("Absolute difference = {:.20e}", difference);

            if difference < 1e-30 {
                println!("MITM consistency: PASS");
            } else {
                println!("MITM consistency: FAIL");
            }
        } else {
            println!("No matching middle state found.");
        }
    }

    // --------------------------------------------------------
    // Final validation
    // --------------------------------------------------------

    println!();
    println!("============================================================");
    println!("VALIDATION RESULT");
    println!("============================================================");

    println!("Output states generated : {}", outputs.len());

    println!(
        "Total probability mass   : {:.20e}",
        total_output_probability.probability_f64()
    );

    println!(
        "Probability conservation : {}",
        if conservation { "PASS" } else { "FAIL" }
    );

    println!();
    println!("The complete 2-round differential output distribution");
    println!("has been enumerated without TOP_N state pruning.");

    println!();
    println!("============================================================");
    println!("IMPORTANT CRYPTANALYSIS NOTES");
    println!("============================================================");

    println!("The DDT is loaded directly from ddt_matrix.txt.");

    println!("The file DDT is independently compared against");

    println!("HERRINGFISH_SBOX_V02 before enumeration.");

    println!();
    println!("Each S-box transition uses its exact integer DDT count.");

    println!("No floating-point probability accumulation is used");

    println!("during the differential enumeration.");

    println!();
    println!("Probabilities are represented as:");

    println!("    numerator / 2^k");

    println!("where k is tracked explicitly.");

    println!();
    println!("For the complete two-round distribution, all output");

    println!("probabilities are therefore exact within the current");

    println!("bytewise-S-box + diffuse differential model.");

    println!();
    println!("IMPORTANT:");

    println!("This does NOT yet prove that the analytical differential");

    println!("model is identical to the full Herringfish round.");

    println!("The next cryptanalytic validation step should compare");

    println!("this differential model against the actual round");

    println!("implementation and the KAT/reference vectors.");

    println!();
    println!("============================================================");
    println!("END REPORT");
    println!("============================================================");
}
