use herringfish::cipher::feistel_arx::{HERRINGFISH_SBOX_V02, diffuse};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ============================================================
// Configuration
// ============================================================

#[derive(Clone, Debug)]
struct Config {
    total_rounds: usize,
    forward_rounds: usize,
    backward_rounds: usize,
    top_outputs: usize,

    input_dl: u64,
    input_dr: u64,

    prune: bool,
    prune_threshold: f64,

    /// Maximum number of unique differential states that may
    /// exist in any one expansion map.
    max_states: usize,

    /// In strict mode, reaching the state limit terminates the
    /// current analysis instead of silently dropping states.
    strict_state_limit: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            total_rounds: 2,
            forward_rounds: 1,
            backward_rounds: 1,
            top_outputs: 25,

            input_dl: 0,
            input_dr: 1,

            prune: false,
            prune_threshold: -64.0,

            max_states: 100_000,

            strict_state_limit: true,
        }
    }
}

impl Config {
    fn from_args() -> Result<Self, String> {
        let mut config = Self::default();

        let args: Vec<String> = std::env::args().skip(1).collect();

        let mut positional_count = 0usize;
        let mut i = 0usize;

        while i < args.len() {
            let arg = &args[i];

            match arg.as_str() {
                // ------------------------------------------------
                // Help
                // ------------------------------------------------
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }

                // ------------------------------------------------
                // Explicit options
                // ------------------------------------------------
                "--rounds" => {
                    config.total_rounds =
                        parse_usize_flag("--rounds", &take_value(&args, &mut i, "--rounds")?)?;
                }

                "--forward" => {
                    config.forward_rounds =
                        parse_usize_flag("--forward", &take_value(&args, &mut i, "--forward")?)?;
                }

                "--backward" => {
                    config.backward_rounds =
                        parse_usize_flag("--backward", &take_value(&args, &mut i, "--backward")?)?;
                }

                "--top" => {
                    config.top_outputs =
                        parse_usize_flag("--top", &take_value(&args, &mut i, "--top")?)?;
                }

                "--max-states" => {
                    config.max_states = parse_usize_flag(
                        "--max-states",
                        &take_value(&args, &mut i, "--max-states")?,
                    )?;
                }

                "--dl" => {
                    config.input_dl = parse_u64(&take_value(&args, &mut i, "--dl")?)?;
                }

                "--dr" => {
                    config.input_dr = parse_u64(&take_value(&args, &mut i, "--dr")?)?;
                }

                "--prune" => {
                    config.prune = true;
                }

                "--prune-threshold" => {
                    let raw = take_value(&args, &mut i, "--prune-threshold")?;
                    config.prune_threshold = raw
                        .parse::<f64>()
                        .map_err(|_| format!("Invalid --prune-threshold value: {raw}"))?;
                }

                "--no-strict-limit" => {
                    config.strict_state_limit = false;
                }

                // ------------------------------------------------
                // Unknown option
                // ------------------------------------------------
                _ if arg.starts_with("--") => {
                    return Err(format!("Unknown argument: {}", arg));
                }

                // ------------------------------------------------
                // Positional arguments
                //
                // TOTAL FORWARD BACKWARD
                // ------------------------------------------------
                _ => {
                    const LABELS: [&str; 3] = ["total-round", "forward-round", "backward-round"];

                    match positional_count {
                        0..=2 => {
                            let value: usize = arg.parse().map_err(|_| {
                                format!(
                                    "Invalid positional {} count: {}",
                                    LABELS[positional_count], arg
                                )
                            })?;

                            match positional_count {
                                0 => config.total_rounds = value,
                                1 => config.forward_rounds = value,
                                _ => config.backward_rounds = value,
                            }
                        }

                        _ => {
                            return Err(
                                "Too many positional arguments. Expected: TOTAL FORWARD BACKWARD"
                                    .to_string(),
                            );
                        }
                    }

                    positional_count += 1;
                }
            }

            i += 1;
        }

        // --------------------------------------------------------
        // Validate configuration
        // --------------------------------------------------------

        if config.total_rounds == 0 {
            return Err("Total rounds must be greater than zero".to_string());
        }

        if config.forward_rounds + config.backward_rounds != config.total_rounds {
            return Err(format!(
                "Invalid MITM configuration: forward ({}) + backward ({}) != total ({})",
                config.forward_rounds, config.backward_rounds, config.total_rounds
            ));
        }

        if config.top_outputs == 0 {
            return Err("--top must be greater than zero".to_string());
        }

        if config.max_states == 0 {
            return Err("--max-states must be greater than zero".to_string());
        }

        Ok(config)
    }
}

/// Fetch the value that follows an option flag, advancing the scan index.
fn take_value(args: &[String], i: &mut usize, flag: &'static str) -> Result<String, String> {
    *i += 1;

    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

/// Parse an unsigned integer option value with a flag-specific error message.
fn parse_usize_flag(flag: &'static str, value: &str) -> Result<usize, String> {
    let value = value.trim();

    value
        .parse::<usize>()
        .map_err(|_| format!("Invalid {flag} value: {value}"))
}

fn parse_u64(value: &str) -> Result<u64, String> {
    let value = value.trim();

    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|_| format!("Invalid hexadecimal value: {value}"))
    } else {
        value
            .parse::<u64>()
            .map_err(|_| format!("Invalid integer value: {value}"))
    }
}

fn print_usage() {
    println!(
        r#"
HERRINGFISH EXACT DIFFERENTIAL HULL / MITM ANALYSIS

Usage:

    cargo run --example hull_meet_in_middle -- TOTAL FORWARD BACKWARD [OPTIONS]

Example:

    cargo run --example hull_meet_in_middle -- 2 1 1 --top 25 --max-states 100000

Options:

    --rounds N
    --forward N
    --backward N
    --top N
    --max-states N
    --dl VALUE
    --dr VALUE
    --prune
    --prune-threshold N
    --no-strict-limit
    --help

Examples:

    cargo run --example hull_meet_in_middle -- 2 1 1

    cargo run --example hull_meet_in_middle -- 2 1 1 --top 25 --max-states 100000

    cargo run --example hull_meet_in_middle -- 3 2 1 --top 25 --max-states 100000

    cargo run --example hull_meet_in_middle -- 4 2 2 --max-states 1000000

State limiting:

    --max-states N

is enforced DURING state expansion.

The implementation never intentionally constructs the old
260-million-entry state map.
"#
    );
}

// ============================================================
// Exact dyadic probability
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

    fn multiply(self, rhs: Self) -> Self {
        if self.numerator == 0 || rhs.numerator == 0 {
            return Self::zero();
        }

        Self {
            numerator: self.numerator.saturating_mul(rhs.numerator),

            denominator_bits: self.denominator_bits.saturating_add(rhs.denominator_bits),
        }
    }

    fn add(self, rhs: Self) -> Self {
        if self.numerator == 0 {
            return rhs;
        }

        if rhs.numerator == 0 {
            return self;
        }

        // Align to the larger denominator (the finer grid).
        let (base, other) = if self.denominator_bits >= rhs.denominator_bits {
            (self, rhs)
        } else {
            (rhs, self)
        };

        let shift = base.denominator_bits - other.denominator_bits;

        let numerator = match other.numerator.checked_shl(shift) {
            Some(value) => base.numerator.saturating_add(value),
            None => u128::MAX,
        };

        Self {
            numerator,
            denominator_bits: base.denominator_bits,
        }
    }

    fn probability_f64(self) -> f64 {
        if self.numerator == 0 {
            return 0.0;
        }

        (self.numerator as f64) / 2f64.powi(self.denominator_bits as i32)
    }

    fn log2_probability(self) -> f64 {
        if self.numerator == 0 {
            return f64::NEG_INFINITY;
        }

        (self.numerator as f64).log2() - self.denominator_bits as f64
    }
}

type State = (u64, u64);

// ============================================================
// Expansion status
// ============================================================

#[derive(Debug)]
enum ExpansionError {
    StateLimitExceeded {
        round: usize,
        current_states: usize,
        max_states: usize,
        source_state: State,
    },
}

impl ExpansionError {
    fn print(&self) {
        match self {
            Self::StateLimitExceeded {
                round,
                current_states,
                max_states,
                source_state,
            } => {
                eprintln!();
                eprintln!("============================================================");
                eprintln!("STATE-SPACE LIMIT REACHED");
                eprintln!("============================================================");
                eprintln!("Round                  : {round}");
                eprintln!("Current states         : {current_states}");
                eprintln!("Maximum states         : {max_states}");
                eprintln!("Source ΔL              : 0x{:016x}", source_state.0);
                eprintln!("Source ΔR              : 0x{:016x}", source_state.1);
                eprintln!();
                eprintln!("Expansion stopped BEFORE inserting another unique state.");
                eprintln!("No unbounded HashMap allocation was attempted.");
                eprintln!();
            }
        }
    }
}

// ============================================================
// Reference tables
// ============================================================

const REFERENCE_TABLES: &[(&str, &str)] = &[
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
];

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

/// Parse one DDT cell token.
///
/// Accepts plain decimal ("4"), explicit hex ("0x1f" / "0X1F") and bare
/// hex containing at least one letter ("c8"). Tokens that are neither are
/// rejected instead of being silently dropped.
fn parse_ddt_token(token: &str) -> Option<u16> {
    let token = token.trim();

    if token.is_empty() {
        return None;
    }

    // Explicit hex prefix (0x / 0X).
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        return u16::from_str_radix(hex, 16).ok();
    }

    // Plain decimal.
    if token.bytes().all(|b| b.is_ascii_digit()) {
        return token.parse::<u16>().ok();
    }

    // Bare hex — only when a letter is present so decimal tokens are
    // never misread as hexadecimal.
    if token.bytes().all(|b| b.is_ascii_hexdigit()) && token.bytes().any(|b| !b.is_ascii_digit()) {
        return u16::from_str_radix(token, 16).ok();
    }

    None
}

fn parse_ddt_file(path: &Path) -> Result<Ddt, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

    let mut rows: Vec<Vec<u16>> = Vec::new();

    for line in text.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let values: Vec<u16> = line
            .split_whitespace()
            .filter_map(parse_ddt_token)
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
                "DDT row {dx} contains only {} values",
                rows[dx].len()
            ));
        }

        for dy in 0..256 {
            ddt[dx][dy] = rows[dx][dy];
        }
    }

    Ok(ddt)
}

// Numeric indices are needed for the 2-D table access and error messages.
#[allow(clippy::needless_range_loop)]
fn validate_ddt_rows(ddt: &Ddt) -> Result<(), String> {
    for dx in 0..256 {
        let sum: u32 = ddt[dx].iter().map(|&v| v as u32).sum();

        if sum != 256 {
            return Err(format!("DDT row dx=0x{dx:02x} sums to {sum}, expected 256"));
        }
    }

    Ok(())
}

// Numeric indices are needed for the 2-D table access and mismatch messages.
#[allow(clippy::needless_range_loop)]
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

    let non_zero = ddt[dx].iter().filter(|&&v| v != 0).count();

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
        let probability = count as f64 / 256.0;

        println!(
            "#{:2} dx=0x{:02x} dy=0x{:02x} count={:3} P={:.6e}",
            rank + 1,
            dx,
            dy,
            count,
            probability
        );
    }

    let sum: u32 = ddt[dx].iter().map(|&v| v as u32).sum();

    println!();
    println!("DDT row count sum: {sum} / 256");
    println!(
        "DDT row validation: {}",
        if sum == 256 { "PASS" } else { "FAIL" }
    );
}

// ============================================================
// Differential helpers
// ============================================================

fn active_byte_indices(value: u64) -> Vec<usize> {
    value
        .to_le_bytes()
        .iter()
        .enumerate()
        .filter_map(|(i, byte)| (*byte != 0).then_some(i))
        .collect()
}

// The numeric index is needed both for the row access and the result entry.
#[allow(clippy::needless_range_loop)]
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
// Bounded insertion
// ============================================================

fn add_state_checked(
    output: &mut HashMap<State, Dyadic>,
    state: State,
    contribution: Dyadic,
    round: usize,
    source_state: State,
    config: &Config,
) -> Result<(), ExpansionError> {
    if let Some(existing) = output.get_mut(&state) {
        *existing = existing.add(contribution);
        return Ok(());
    }

    if output.len() >= config.max_states {
        if config.strict_state_limit {
            return Err(ExpansionError::StateLimitExceeded {
                round,
                current_states: output.len(),
                max_states: config.max_states,
                source_state,
            });
        }

        // Non-strict mode:
        //
        // Do not add another state, but continue processing.
        return Ok(());
    }

    output.insert(state, contribution);

    Ok(())
}

// ============================================================
// Direction-aware round expansion (forward and backward)
// ============================================================
//
// Forward and backward expansion are the SAME per-byte DDT enumeration
// with different state-update rules. For one Feistel round:
//
//     L' = R,   R' = L XOR F(R)
//
//     forward : (dl, dr) -> (dr, dl XOR f),  rows indexed by bytes of dr
//     backward: (dl, dr) -> (dr XOR f, dl),  rows indexed by bytes of dl
//
// A single implementation covers both directions; only the row source
// and the state step differ.
//
// Transitions are generated recursively, one active byte at a time, so no
// giant combination list is ever materialized.

#[derive(Clone, Copy, Debug)]
enum Direction {
    Forward,
    Backward,
}

impl Direction {
    /// Half-word whose bytes index the DDT rows for this direction.
    fn row_source(self, state: State) -> u64 {
        match self {
            Self::Forward => state.1,
            Self::Backward => state.0,
        }
    }

    /// Apply one sampled F-difference to obtain the next differential state.
    fn step(self, state: State, f_out: u64) -> State {
        match self {
            Self::Forward => (state.1, state.0 ^ f_out),
            Self::Backward => (state.1 ^ f_out, state.0),
        }
    }
}

// Recursive enumeration passes its accumulated context explicitly;
// bundling it into a struct would obscure the per-byte recursion.
#[allow(clippy::too_many_arguments)]
fn enumerate_combinations(
    active: &[usize],
    choices: &[Vec<(u8, u16)>],
    index: usize,
    t_value: u64,
    path_count: u128,
    probability: Dyadic,
    state: State,
    round: usize,
    direction: Direction,
    output: &mut HashMap<State, Dyadic>,
    config: &Config,
) -> Result<(), ExpansionError> {
    if index == active.len() {
        let f_out = diffuse(t_value);

        let transition_probability = Dyadic {
            numerator: path_count,
            denominator_bits: (active.len() * 8) as u32,
        };

        let contribution = probability.multiply(transition_probability);

        if config.prune && contribution.log2_probability() < config.prune_threshold {
            return Ok(());
        }

        return add_state_checked(
            output,
            direction.step(state, f_out),
            contribution,
            round,
            state,
            config,
        );
    }

    let byte_index = active[index];

    for &(dy, count) in &choices[index] {
        enumerate_combinations(
            active,
            choices,
            index + 1,
            t_value | ((dy as u64) << (8 * byte_index)),
            path_count.saturating_mul(count as u128),
            probability,
            state,
            round,
            direction,
            output,
            config,
        )?;
    }

    Ok(())
}

fn expand_round(
    ddt: &Ddt,
    input: &HashMap<State, Dyadic>,
    config: &Config,
    round: usize,
    direction: Direction,
) -> Result<HashMap<State, Dyadic>, ExpansionError> {
    let capacity = input.len().min(config.max_states);

    let mut output = HashMap::with_capacity(capacity);

    for (&state, &probability) in input {
        let row_source = direction.row_source(state);

        let active = active_byte_indices(row_source);

        // ----------------------------------------------------
        // F(0) = 0: with no active bytes the transition is deterministic.
        // ----------------------------------------------------

        if active.is_empty() {
            add_state_checked(
                &mut output,
                direction.step(state, 0),
                probability,
                round,
                state,
                config,
            )?;

            continue;
        }

        // ----------------------------------------------------
        // Build per-byte transition lists.
        //
        // This is at most 8 vectors × 256 entries.
        // It is NOT the state space.
        // ----------------------------------------------------

        let mut choices = Vec::with_capacity(active.len());

        for &byte_index in &active {
            let dx = ((row_source >> (8 * byte_index)) & 0xff) as u8;

            choices.push(enumerate_byte_transitions(ddt, dx));
        }

        enumerate_combinations(
            &active,
            &choices,
            0,
            0,
            1,
            probability,
            state,
            round,
            direction,
            &mut output,
            config,
        )?;
    }

    Ok(output)
}

// ============================================================
// Probability mass
// ============================================================

fn sum_probability_mass(map: &HashMap<State, Dyadic>) -> Dyadic {
    map.values()
        .copied()
        .fold(Dyadic::zero(), |total, probability| total.add(probability))
}

fn print_probability_mass(label: &str, map: &HashMap<State, Dyadic>) {
    let total = sum_probability_mass(map);

    println!("{label}:");
    println!("  Numerator        : {}", total.numerator);
    println!("  Denominator bits : {}", total.denominator_bits);
    println!("  Probability      : {:.20e}", total.probability_f64());
    println!("  -log2(P)         : {:.12}", -total.log2_probability());
}

// ============================================================
// Top-N
// ============================================================

fn top_states(map: &HashMap<State, Dyadic>, count: usize) -> Vec<(State, Dyadic)> {
    if count == 0 || map.is_empty() {
        return Vec::new();
    }

    let mut best: Vec<(State, Dyadic)> = Vec::with_capacity(count.min(map.len()));

    for (&state, &probability) in map {
        best.push((state, probability));

        best.sort_unstable_by(|a, b| {
            b.1.log2_probability()
                .partial_cmp(&a.1.log2_probability())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.0.cmp(&b.0.0))
                .then_with(|| a.0.1.cmp(&b.0.1))
        });

        if best.len() > count {
            best.pop();
        }
    }

    best
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

    for (rank, (state, probability)) in top_states(map, count).into_iter().enumerate() {
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
// MITM
// ============================================================

fn calculate_mitm_hull(
    forward: &HashMap<State, Dyadic>,
    backward: &HashMap<State, Dyadic>,
) -> HashMap<State, Dyadic> {
    let capacity = forward.len().min(backward.len());

    let mut result = HashMap::with_capacity(capacity);

    let (smaller, larger) = if forward.len() <= backward.len() {
        (forward, backward)
    } else {
        (backward, forward)
    };

    for (&middle, &small_probability) in smaller {
        if let Some(&large_probability) = larger.get(&middle) {
            let contribution = small_probability.multiply(large_probability);

            result.insert(middle, contribution);
        }
    }

    result
}

// ============================================================
// Main
// ============================================================

fn main() {
    let config = match Config::from_args() {
        Ok(config) => config,

        Err(error) => {
            eprintln!("ERROR: {error}");
            eprintln!();
            print_usage();
            std::process::exit(2);
        }
    };

    println!("============================================================");
    println!("HERRINGFISH EXACT DIFFERENTIAL HULL / MITM ANALYSIS");
    println!("============================================================");
    println!();

    println!("Configuration:");
    println!("  Total rounds          : {}", config.total_rounds);
    println!("  Forward rounds        : {}", config.forward_rounds);
    println!("  Backward rounds       : {}", config.backward_rounds);
    println!("  Top outputs           : {}", config.top_outputs);
    println!(
        "  State pruning         : {}",
        if config.prune { "ENABLED" } else { "DISABLED" }
    );
    println!("  Maximum states        : {}", config.max_states);
    println!(
        "  Strict state limit    : {}",
        if config.strict_state_limit {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    println!("  Input ΔL              : 0x{:016x}", config.input_dl);
    println!("  Input ΔR              : 0x{:016x}", config.input_dr);

    // ========================================================
    // Reference tables
    // ========================================================

    println!();
    println!("------------------------------------------------------------");
    println!("REFERENCE TABLES");
    println!("------------------------------------------------------------");

    for (name, path) in REFERENCE_TABLES {
        let status = if Path::new(path).exists() {
            "FOUND"
        } else {
            "MISSING"
        };

        println!("  {:<32} {} ({})", name, status, path);
    }

    // ========================================================
    // DDT
    // ========================================================

    let ddt_path = "docs/tables/ddt_matrix.txt";

    println!();
    println!("------------------------------------------------------------");
    println!("LOADING EXACT DDT");
    println!("------------------------------------------------------------");

    let ddt = match parse_ddt_file(Path::new(ddt_path)) {
        Ok(ddt) => {
            println!("DDT construction/loading: COMPLETE");
            ddt
        }

        Err(error) => {
            eprintln!("ERROR: {error}");
            std::process::exit(1);
        }
    };

    if let Err(error) = validate_ddt_rows(&ddt) {
        eprintln!("DDT row validation: FAIL");
        eprintln!("{error}");
        std::process::exit(1);
    }

    println!("DDT row validation: PASS");

    println!();
    println!("------------------------------------------------------------");
    println!("DDT ↔ S-BOX VALIDATION");
    println!("------------------------------------------------------------");

    if !validate_ddt_against_sbox(&ddt) {
        eprintln!("DDT file does not match HERRINGFISH_SBOX_V02.");
        std::process::exit(1);
    }

    println!("DDT file matches HERRINGFISH_SBOX_V02: PASS");

    println!();

    print_ddt_validation(&ddt, 0x01);

    // ========================================================
    // Forward half
    // ========================================================

    println!();
    println!("============================================================");
    println!("FORWARD HALF");
    println!("============================================================");

    let mut forward = HashMap::with_capacity(1);

    forward.insert((config.input_dl, config.input_dr), Dyadic::one());

    let mut forward_complete = true;

    for round in 1..=config.forward_rounds {
        println!();
        println!("Forward round {} input states : {}", round, forward.len());

        match expand_round(&ddt, &forward, &config, round, Direction::Forward) {
            Ok(next) => {
                forward = next;
            }

            Err(error) => {
                error.print();
                forward_complete = false;
                break;
            }
        }

        println!("Forward round {} output states: {}", round, forward.len());

        print_probability_mass("Forward probability mass", &forward);
    }

    if !forward_complete {
        println!();
        println!("============================================================");
        println!("ANALYSIS STOPPED SAFELY");
        println!("============================================================");
        println!("The forward differential state space exceeded the");
        println!("configured limit of {} states.", config.max_states);
        println!();
        println!("The state map was bounded during expansion.");
        println!("No 260-million-entry HashMap was constructed.");
        return;
    }

    print_top_states("TOP FORWARD MIDDLE STATES", &forward, config.top_outputs);

    // ========================================================
    // Direct full output enumeration
    // ========================================================

    println!();
    println!("============================================================");
    println!("EXACT {}-ROUND OUTPUT ENUMERATION", config.total_rounds);
    println!("============================================================");

    let mut outputs = HashMap::with_capacity(1);

    outputs.insert((config.input_dl, config.input_dr), Dyadic::one());

    let mut direct_complete = true;

    for round in 1..=config.total_rounds {
        println!();
        println!("Round {} input states : {}", round, outputs.len());

        match expand_round(&ddt, &outputs, &config, round, Direction::Forward) {
            Ok(next) => {
                outputs = next;
            }

            Err(error) => {
                error.print();
                direct_complete = false;
                break;
            }
        }

        println!("Round {} output states: {}", round, outputs.len());

        print_probability_mass(&format!("Round {} probability mass", round), &outputs);
    }

    if !direct_complete {
        println!();
        println!("============================================================");
        println!("DIRECT ENUMERATION INCOMPLETE");
        println!("============================================================");
        println!(
            "The complete {}-round distribution could not fit",
            config.total_rounds
        );
        println!("within --max-states={}.", config.max_states);
        println!();
        println!("This is a bounded analytical result, not a crash.");
        println!();
        println!("For larger round counts, use a targeted MITM/hull");
        println!("search rather than full output enumeration.");
        return;
    }

    // ========================================================
    // Direct statistics
    // ========================================================

    let direct_hull_probability = sum_probability_mass(&outputs);

    println!();
    println!("------------------------------------------------------------");
    println!("{}-ROUND OUTPUT STATISTICS", config.total_rounds);
    println!("------------------------------------------------------------");

    println!("Unique output states : {}", outputs.len());

    println!(
        "Total probability    : {:.20e}",
        direct_hull_probability.probability_f64()
    );

    println!(
        "-log2(P)             : {:.12}",
        -direct_hull_probability.log2_probability()
    );

    let conservation = (direct_hull_probability.probability_f64() - 1.0).abs() < 1e-12;

    println!(
        "Probability conservation: {}",
        if conservation { "PASS" } else { "FAIL" }
    );

    print_top_states(
        &format!("TOP {}-ROUND OUTPUT HULLS", config.total_rounds),
        &outputs,
        config.top_outputs,
    );

    // ========================================================
    // Best output
    // ========================================================

    let best_output = top_states(&outputs, 1).into_iter().next();

    let Some((target_output, direct_best_probability)) = best_output else {
        println!("No output states were generated.");
        return;
    };

    println!();
    println!("------------------------------------------------------------");
    println!("BEST DIFFERENTIAL");
    println!("------------------------------------------------------------");

    println!("Output ΔL         : 0x{:016x}", target_output.0);

    println!("Output ΔR         : 0x{:016x}", target_output.1);

    println!(
        "Hull probability  : {:.20e}",
        direct_best_probability.probability_f64()
    );

    println!(
        "-log2(P)          : {:.12}",
        -direct_best_probability.log2_probability()
    );

    // ========================================================
    // Backward half
    // ========================================================

    println!();
    println!("============================================================");
    println!("BACKWARD HALF / MITM VALIDATION");
    println!("============================================================");

    println!("Target ΔL = 0x{:016x}", target_output.0);

    println!("Target ΔR = 0x{:016x}", target_output.1);

    let mut backward = HashMap::with_capacity(1);

    backward.insert(target_output, Dyadic::one());

    let mut backward_complete = true;

    for round in 1..=config.backward_rounds {
        println!();
        println!("Backward round {} input states : {}", round, backward.len());

        match expand_round(&ddt, &backward, &config, round, Direction::Backward) {
            Ok(next) => {
                backward = next;
            }

            Err(error) => {
                error.print();
                backward_complete = false;
                break;
            }
        }

        println!("Backward round {} output states: {}", round, backward.len());

        print_probability_mass("Backward probability mass", &backward);
    }

    if !backward_complete {
        println!();
        println!("============================================================");
        println!("BACKWARD MITM INCOMPLETE");
        println!("============================================================");
        println!("Backward expansion exceeded the configured state limit.");
        println!("No unbounded allocation was attempted.");
        return;
    }

    // ========================================================
    // MITM intersection
    // ========================================================

    let mitm_hull = calculate_mitm_hull(&forward, &backward);

    let mitm_probability = sum_probability_mass(&mitm_hull);

    println!();
    println!("------------------------------------------------------------");
    println!("MITM INTERSECTION");
    println!("------------------------------------------------------------");

    println!("Forward states  : {}", forward.len());

    println!("Backward states : {}", backward.len());

    println!("Matching states : {}", mitm_hull.len());

    println!();

    println!(
        "MITM probability : {:.20e}",
        mitm_probability.probability_f64()
    );

    println!(
        "MITM -log2(P)    : {:.12}",
        -mitm_probability.log2_probability()
    );

    if let Some((middle, contribution)) = top_states(&mitm_hull, 1).into_iter().next() {
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
    }

    // ========================================================
    // Consistency
    // ========================================================

    println!();
    println!("------------------------------------------------------------");
    println!("MITM CONSISTENCY CHECK");
    println!("------------------------------------------------------------");

    let direct_best_f64 = direct_best_probability.probability_f64();

    println!("Direct best-output probability : {:.20e}", direct_best_f64);

    println!(
        "MITM reconstructed probability : {:.20e}",
        mitm_probability.probability_f64()
    );

    let absolute_difference = (direct_best_f64 - mitm_probability.probability_f64()).abs();

    println!(
        "Absolute difference            : {:.20e}",
        absolute_difference
    );

    // NOTE:
    //
    // The MITM calculation above reconstructs the selected target
    // output from middle states. Therefore compare it with the
    // probability of that specific output, NOT the total probability
    // mass of the entire output distribution.

    let relative_difference = if direct_best_f64 != 0.0 {
        absolute_difference / direct_best_f64
    } else {
        absolute_difference
    };

    println!(
        "Relative difference            : {:.20e}",
        relative_difference
    );

    // Relative tolerance: converting large exact dyadic products to f64 can
    // differ by a few ulps in ABSOLUTE terms, so an absolute threshold would
    // produce spurious FAILs for high-probability differentials. A genuine
    // mismatch (e.g. pruning removed states from one half only) is orders of
    // magnitude larger than 1e-9 relative and still fails the check.
    let consistent = if direct_best_f64 == 0.0 {
        mitm_probability.probability_f64() == 0.0
    } else {
        relative_difference <= 1e-9
    };

    println!(
        "MITM consistency: {}",
        if consistent { "PASS" } else { "FAIL" }
    );

    // ========================================================
    // Final report
    // ========================================================

    println!();
    println!("============================================================");
    println!("FINAL REPORT");
    println!("============================================================");

    println!("Rounds                 : {}", config.total_rounds);

    println!("Forward split          : {}", config.forward_rounds);

    println!("Backward split         : {}", config.backward_rounds);

    println!("Direct output states   : {}", outputs.len());

    println!("Forward middle states  : {}", forward.len());

    println!("Backward middle states : {}", backward.len());

    println!("MITM matching states   : {}", mitm_hull.len());

    println!("State limit            : {}", config.max_states);

    println!();
    println!("State expansion is bounded during generation.");

    println!("No giant combination list is constructed.");

    println!("No 260-million-entry HashMap is intentionally created.");

    println!();
    println!("IMPORTANT:");

    println!("This remains an analytical differential model.");

    println!("It should still be validated against the actual");

    println!("Herringfish round implementation and KAT vectors.");

    println!();
    println!("============================================================");
    println!("END REPORT");
    println!("============================================================");
}
