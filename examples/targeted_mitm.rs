#![allow(clippy::all)]
#![allow(dead_code)]

//! Targeted differential verification for Herringfish.
//!
//! This tool answers one specific question:
//!
//!     P[Δout | Δin]
//!
//! It intentionally does NOT construct the complete differential hull.
//!
//! Project-relative table paths:
//!
//!     docs/tables/kat_reduced_rounds_v02.txt
//!     docs/tables/kat_reduced_all.txt
//!     docs/tables/kat_expanded_v02.txt
//!     docs/tables/kat_vectors_v02.txt
//!     docs/tables/lat_matrix.txt
//!     docs/tables/ddt_matrix.txt
//!     docs/tables/sbox_accepted.txt
//!     docs/tables/sbox_ddt_lat.md
//!
//! The DDT is required for differential sampling.
//! The other files are loaded as project-table metadata/reference material.
//!
//! For one round, the target probability can be calculated exactly:
//!
//!     ΔL' = ΔR
//!     ΔR' = ΔL XOR Diffuse(ΔSBox)
//!
//! Therefore:
//!
//!     ΔSBox = Diffuse^-1(ΔL XOR ΔR')
//!
//! is uniquely determined.
//!
//! For multiple rounds, exhaustive enumeration becomes expensive very
//! quickly. The targeted verifier instead samples the exact DDT transition
//! distribution and estimates the probability of the requested final
//! differential.
//!
//! This makes the tool suitable for testing hypotheses at substantially
//! higher round counts than the exhaustive hull analyzer.
//!
//! Usage:
//!
//!     cargo run --release --example targeted_mitm -- 8 4 4 \
//!         --dl 0x0000000000000000 \
//!         --dr 0x0000000000000001 \
//!         --tdl 0x0000000000000000 \
//!         --tdr 0x0000000000000000 \
//!         --samples 10000000
//!
//! Notes:
//!
//! The positional FORWARD/BACKWARD values are retained for compatibility
//! with the previous targeted MITM interface. They are informational here.
//!
//! This program verifies the differential model represented by the DDT.
//! It does not replace direct plaintext/key verification of the actual
//! FeistelArx implementation.

use std::fs;
use std::path::{Path, PathBuf};

// ============================================================
// Project paths
// ============================================================

const TABLE_DIR: &str = "docs/tables";

const KAT_REDUCED_ROUNDS: &str =
    "docs/tables/kat_reduced_rounds_v02.txt";

const KAT_REDUCED_ALL: &str =
    "docs/tables/kat_reduced_all.txt";

const KAT_EXPANDED_V02: &str =
    "docs/tables/kat_expanded_v02.txt";

const KAT_VECTORS_V02: &str =
    "docs/tables/kat_vectors_v02.txt";

const LAT_MATRIX: &str =
    "docs/tables/lat_matrix.txt";

const DDT_MATRIX: &str =
    "docs/tables/ddt_matrix.txt";

const SBOX_ACCEPTED: &str =
    "docs/tables/sbox_accepted.txt";

const SBOX_DDT_LAT: &str =
    "docs/tables/sbox_ddt_lat.md";

// ============================================================
// Configuration
// ============================================================

#[derive(Clone, Debug)]
struct Config {
    total_rounds: usize,
    forward_rounds: usize,
    backward_rounds: usize,

    input_dl: u64,
    input_dr: u64,

    target_dl: u64,
    target_dr: u64,

    samples: u64,
    batch_size: u64,

    seed: u64,

    progress: u64,

    exact: bool,
    check_diffuse: bool,

    load_project_tables: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            total_rounds: 2,
            forward_rounds: 1,
            backward_rounds: 1,

            input_dl: 0,
            input_dr: 1,

            target_dl: 0,
            target_dr: 0,

            samples: 1_000_000,
            batch_size: 65_536,

            seed: 0x9E37_79B9_7F4A_7C15,

            progress: 0,

            exact: true,
            check_diffuse: true,

            load_project_tables: true,
        }
    }
}

impl Config {
    fn from_args() -> Result<Self, String> {
        let mut config = Self::default();

        let args: Vec<String> =
            std::env::args().skip(1).collect();

        let mut positional_count = 0usize;
        let mut i = 0usize;

        while i < args.len() {
            let arg = &args[i];

            match arg.as_str() {
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }

                "--rounds" => {
                    i += 1;
                    config.total_rounds =
                        parse_usize(&args, i, "--rounds")?;
                }

                "--forward" => {
                    i += 1;
                    config.forward_rounds =
                        parse_usize(&args, i, "--forward")?;
                }

                "--backward" => {
                    i += 1;
                    config.backward_rounds =
                        parse_usize(&args, i, "--backward")?;
                }

                "--dl" => {
                    i += 1;
                    config.input_dl =
                        parse_u64(&args, i, "--dl")?;
                }

                "--dr" => {
                    i += 1;
                    config.input_dr =
                        parse_u64(&args, i, "--dr")?;
                }

                "--tdl" => {
                    i += 1;
                    config.target_dl =
                        parse_u64(&args, i, "--tdl")?;
                }

                "--tdr" => {
                    i += 1;
                    config.target_dr =
                        parse_u64(&args, i, "--tdr")?;
                }

                "--samples" => {
                    i += 1;
                    config.samples =
                        parse_u64_required(
                            &args,
                            i,
                            "--samples",
                        )?;
                }

                "--batch-size" => {
                    i += 1;
                    config.batch_size =
                        parse_u64_required(
                            &args,
                            i,
                            "--batch-size",
                        )?;
                }

                "--seed" => {
                    i += 1;
                    config.seed =
                        parse_u64_required(
                            &args,
                            i,
                            "--seed",
                        )?;
                }

                "--progress" => {
                    i += 1;
                    config.progress =
                        parse_u64_required(
                            &args,
                            i,
                            "--progress",
                        )?;
                }

                "--no-exact" => {
                    config.exact = false;
                }

                "--no-diffuse-check" => {
                    config.check_diffuse = false;
                }

                "--no-project-tables" => {
                    config.load_project_tables = false;
                }

                _ if arg.starts_with("--") => {
                    return Err(format!(
                        "Unknown argument: {}",
                        arg
                    ));
                }

                _ => {
                    match positional_count {
                        0 => {
                            config.total_rounds =
                                arg.parse().map_err(|_| {
                                    "Invalid total-round count"
                                        .to_string()
                                })?;
                        }

                        1 => {
                            config.forward_rounds =
                                arg.parse().map_err(|_| {
                                    "Invalid forward-round count"
                                        .to_string()
                                })?;
                        }

                        2 => {
                            config.backward_rounds =
                                arg.parse().map_err(|_| {
                                    "Invalid backward-round count"
                                        .to_string()
                                })?;
                        }

                        _ => {
                            return Err(
                                "Too many positional arguments"
                                    .to_string()
                            );
                        }
                    }

                    positional_count += 1;
                }
            }

            i += 1;
        }

        if config.forward_rounds
            + config.backward_rounds
            != config.total_rounds
        {
            return Err(format!(
                "Invalid configuration: forward ({}) + backward ({}) != total ({})",
                config.forward_rounds,
                config.backward_rounds,
                config.total_rounds
            ));
        }

        if config.samples == 0 {
            return Err(
                "--samples must be greater than zero"
                    .to_string()
            );
        }

        if config.batch_size == 0 {
            return Err(
                "--batch-size must be greater than zero"
                    .to_string()
            );
        }

        Ok(config)
    }
}

fn parse_usize(
    args: &[String],
    index: usize,
    name: &str,
) -> Result<usize, String> {
    if index >= args.len() {
        return Err(format!(
            "Missing value for {}",
            name
        ));
    }

    args[index]
        .parse::<usize>()
        .map_err(|_| format!("Invalid value for {}", name))
}

fn parse_u64_required(
    args: &[String],
    index: usize,
    name: &str,
) -> Result<u64, String> {
    if index >= args.len() {
        return Err(format!(
            "Missing value for {}",
            name
        ));
    }

    parse_u64_string(&args[index])
        .map_err(|e| format!("{}: {}", name, e))
}

fn parse_u64(
    args: &[String],
    index: usize,
    name: &str,
) -> Result<u64, String> {
    parse_u64_required(args, index, name)
}

fn parse_u64_string(
    value: &str,
) -> Result<u64, String> {
    let value = value.trim();

    if let Some(hex) =
        value.strip_prefix("0x")
    {
        u64::from_str_radix(hex, 16)
            .map_err(|_| {
                format!(
                    "Invalid hexadecimal value: {}",
                    value
                )
            })
    } else if let Some(hex) =
        value.strip_prefix("0X")
    {
        u64::from_str_radix(hex, 16)
            .map_err(|_| {
                format!(
                    "Invalid hexadecimal value: {}",
                    value
                )
            })
    } else {
        value
            .parse::<u64>()
            .map_err(|_| {
                format!(
                    "Invalid integer: {}",
                    value
                )
            })
    }
}

fn print_usage() {
    println!(
        r#"
Targeted Differential Verification

Usage:
    cargo run --release --example targeted_mitm -- TOTAL FORWARD BACKWARD [OPTIONS]

Example:
    cargo run --release --example targeted_mitm -- 8 4 4 \
        --dl 0x0000000000000000 \
        --dr 0x0000000000000001 \
        --tdl 0x0000000000000000 \
        --tdr 0x0000000000000000 \
        --samples 10000000

Differential:
    --dl VALUE
    --dr VALUE
    --tdl VALUE
    --tdr VALUE

Verification:
    --samples N
    --batch-size N
    --seed VALUE
    --progress N

Compatibility:
    --rounds N
    --forward N
    --backward N

Diagnostics:
    --no-exact
    --no-diffuse-check
    --no-project-tables

Paths are project-relative:
    docs/tables/...

The working directory must therefore be the Herringfish project root.
"#
    );
}

// ============================================================
// Project table inventory
// ============================================================

#[derive(Clone, Debug)]
struct ProjectTables {
    kat_reduced_rounds: String,
    kat_reduced_all: String,
    kat_expanded_v02: String,
    kat_vectors_v02: String,

    lat_matrix: String,
    ddt_matrix: String,
    sbox_accepted: String,
    sbox_ddt_lat: String,
}

impl ProjectTables {
    fn load() -> Result<Self, String> {
        let paths = [
            KAT_REDUCED_ROUNDS,
            KAT_REDUCED_ALL,
            KAT_EXPANDED_V02,
            KAT_VECTORS_V02,
            LAT_MATRIX,
            DDT_MATRIX,
            SBOX_ACCEPTED,
            SBOX_DDT_LAT,
        ];

        let mut missing = Vec::new();

        for path in paths {
            if !Path::new(path).is_file() {
                missing.push(path);
            }
        }

        if !missing.is_empty() {
            return Err(format!(
                "Missing project table(s):\n{}",
                missing
                    .iter()
                    .map(|p| format!("    {}", p))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }

        Ok(Self {
            kat_reduced_rounds:
                fs::read_to_string(
                    KAT_REDUCED_ROUNDS
                )
                .map_err(|e| {
                    format!(
                        "Unable to read {}: {}",
                        KAT_REDUCED_ROUNDS,
                        e
                    )
                })?,

            kat_reduced_all:
                fs::read_to_string(
                    KAT_REDUCED_ALL
                )
                .map_err(|e| {
                    format!(
                        "Unable to read {}: {}",
                        KAT_REDUCED_ALL,
                        e
                    )
                })?,

            kat_expanded_v02:
                fs::read_to_string(
                    KAT_EXPANDED_V02
                )
                .map_err(|e| {
                    format!(
                        "Unable to read {}: {}",
                        KAT_EXPANDED_V02,
                        e
                    )
                })?,

            kat_vectors_v02:
                fs::read_to_string(
                    KAT_VECTORS_V02
                )
                .map_err(|e| {
                    format!(
                        "Unable to read {}: {}",
                        KAT_VECTORS_V02,
                        e
                    )
                })?,

            lat_matrix:
                fs::read_to_string(
                    LAT_MATRIX
                )
                .map_err(|e| {
                    format!(
                        "Unable to read {}: {}",
                        LAT_MATRIX,
                        e
                    )
                })?,

            ddt_matrix:
                fs::read_to_string(
                    DDT_MATRIX
                )
                .map_err(|e| {
                    format!(
                        "Unable to read {}: {}",
                        DDT_MATRIX,
                        e
                    )
                })?,

            sbox_accepted:
                fs::read_to_string(
                    SBOX_ACCEPTED
                )
                .map_err(|e| {
                    format!(
                        "Unable to read {}: {}",
                        SBOX_ACCEPTED,
                        e
                    )
                })?,

            sbox_ddt_lat:
                fs::read_to_string(
                    SBOX_DDT_LAT
                )
                .map_err(|e| {
                    format!(
                        "Unable to read {}: {}",
                        SBOX_DDT_LAT,
                        e
                    )
                })?,
        })
    }

    fn print_summary(&self) {
        println!(
            "Project table directory: {}",
            TABLE_DIR
        );

        println!(
            "  {:<28} {:>8} bytes",
            "kat_reduced_rounds_v02.txt",
            self.kat_reduced_rounds.len()
        );

        println!(
            "  {:<28} {:>8} bytes",
            "kat_reduced_all.txt",
            self.kat_reduced_all.len()
        );

        println!(
            "  {:<28} {:>8} bytes",
            "kat_expanded_v02.txt",
            self.kat_expanded_v02.len()
        );

        println!(
            "  {:<28} {:>8} bytes",
            "kat_vectors_v02.txt",
            self.kat_vectors_v02.len()
        );

        println!(
            "  {:<28} {:>8} bytes",
            "lat_matrix.txt",
            self.lat_matrix.len()
        );

        println!(
            "  {:<28} {:>8} bytes",
            "ddt_matrix.txt",
            self.ddt_matrix.len()
        );

        println!(
            "  {:<28} {:>8} bytes",
            "sbox_accepted.txt",
            self.sbox_accepted.len()
        );

        println!(
            "  {:<28} {:>8} bytes",
            "sbox_ddt_lat.md",
            self.sbox_ddt_lat.len()
        );
    }
}

// ============================================================
// DDT
// ============================================================

type Ddt = [[u16; 256]; 256];

fn parse_ddt_text(text: &str) -> Result<Ddt, String> {
    let mut ddt = [[0u16; 256]; 256];

    let mut rows = 0usize;
    let mut saw_column_header = false;

    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();

        if line.is_empty() {
            continue;
        }

        // Descriptive/header lines such as:
        //
        //     DDT
        //     DDT (Differential Distribution Table)
        //
        // contain no numeric matrix data and are ignored.
        let tokens: Vec<&str> =
            line.split_whitespace().collect();

        if tokens.is_empty() {
            continue;
        }

        // ----------------------------------------------------
        // Parse numeric tokens.
        //
        // We deliberately allow a trailing ':' on row labels:
        //
        //     0: 256 0 0 ...
        //     1: 0 128 ...
        //
        // ----------------------------------------------------

        let mut numeric = Vec::<u16>::new();

        for token in &tokens {
            let cleaned =
                token.trim_end_matches(':');

            match cleaned.parse::<u16>() {
                Ok(value) => {
                    numeric.push(value);
                }

                Err(_) => {
                    // Non-numeric tokens are acceptable in
                    // descriptive/header lines.
                    //
                    // However, once this looks like a matrix
                    // row, an invalid token should be reported.
                    continue;
                }
            }
        }

        // No numeric material on this line.
        if numeric.is_empty() {
            continue;
        }

        // ----------------------------------------------------
        // Detect the 256-column header.
        //
        // Typical format:
        //
        //      0 1 2 3 ... 255
        //
        // This must NOT become DDT row 0.
        // ----------------------------------------------------

        if !saw_column_header
            && numeric.len() == 256
            && numeric
                .iter()
                .enumerate()
                .all(|(i, &v)| v as usize == i)
        {
            saw_column_header = true;
            continue;
        }

        // ----------------------------------------------------
        // Actual matrix row.
        //
        // Supported forms:
        //
        //     0 256 0 0 ...
        //
        //     0: 256 0 0 ...
        //
        //     256 0 0 ...
        //
        // In the first two cases the first number is the
        // row index, leaving 256 DDT entries.
        // ----------------------------------------------------

        let values: &[u16] = match numeric.len() {
            256 => {
                // Raw row with no explicit row index.
                &numeric[..]
            }

            257 => {
                // Explicit row index + 256 entries.
                //
                // Verify that the row index agrees with the
                // row we're expecting.
                let row_index =
                    numeric[0] as usize;

                if row_index != rows {
                    return Err(format!(
                        "DDT row-label mismatch on source line {}: \
                         found row {}, expected row {}",
                        line_number + 1,
                        row_index,
                        rows
                    ));
                }

                &numeric[1..]
            }

            _ => {
                // A formatted header may contain numbers but
                // isn't a matrix row.
                //
                // Once we've started reading actual rows,
                // however, silently accepting malformed rows
                // would hide a bad DDT file.
                if rows == 0 {
                    continue;
                }

                return Err(format!(
                    "Unexpected DDT row on source line {}: \
                     found {} numeric values, expected 256 \
                     (or 257 including a row index)",
                    line_number + 1,
                    numeric.len()
                ));
            }
        };

        if rows >= 256 {
            return Err(format!(
                "DDT contains more than 256 rows; \
                 unexpected matrix data on source line {}",
                line_number + 1
            ));
        }

        for column in 0..256 {
            ddt[rows][column] =
                values[column];
        }

        // Every DDT row must contain exactly 256
        // possible S-box output differences.
        let sum: u32 =
            ddt[rows]
                .iter()
                .map(|&x| x as u32)
                .sum();

        if sum != 256 {
            return Err(format!(
                "Invalid DDT row {} \
                 (source line {}): sum={} expected=256",
                rows,
                line_number + 1,
                sum
            ));
        }

        rows += 1;
    }

    if rows != 256 {
        return Err(format!(
            "DDT contains {} matrix rows; expected 256",
            rows
        ));
    }

    // --------------------------------------------------------
    // Final validation
    // --------------------------------------------------------

    for dx in 0..256 {
        let sum: u32 =
            ddt[dx]
                .iter()
                .map(|&x| x as u32)
                .sum();

        if sum != 256 {
            return Err(format!(
                "Invalid DDT row {}: sum={} expected=256",
                dx,
                sum
            ));
        }
    }

    Ok(ddt)
}

fn load_ddt_from_project_tables(
    tables: &ProjectTables,
) -> Result<Ddt, String> {
    parse_ddt_text(&tables.ddt_matrix)
}

// ============================================================
// Diffusion
// ============================================================

/// Herringfish byte diffusion:
///
///     y[i] = x[i] XOR x[i+1] XOR x[i+3]
fn diffuse(
    value: u64,
) -> u64 {
    let mut bytes = [0u8; 8];

    for i in 0..8 {
        bytes[i] =
            ((value >> (8 * i)) & 0xff) as u8;
    }

    let mut output = [0u8; 8];

    for i in 0..8 {
        output[i] =
            bytes[i]
            ^ bytes[(i + 1) & 7]
            ^ bytes[(i + 3) & 7];
    }

    let mut result = 0u64;

    for i in 0..8 {
        result |=
            (output[i] as u64)
            << (8 * i);
    }

    result
}

/// Compute the inverse of the byte-position matrix.
///
/// This is performed once and cached by the caller in normal use.
/// Keeping the reference implementation explicit makes correctness
/// straightforward to verify.
fn inverse_diffuse_reference(
    value: u64,
) -> u64 {
    // Matrix for:
    //
    //     y_i = x_i ^ x_(i+1) ^ x_(i+3)
    //
    // Its inverse is:
    //
    // x0 = y0 ^ y2 ^ y5 ^ y6 ^ y7
    // x1 = y0 ^ y1 ^ y3 ^ y6 ^ y7
    // x2 = y0 ^ y1 ^ y2 ^ y4 ^ y7
    // x3 = y0 ^ y1 ^ y2 ^ y3 ^ y5
    // x4 = y1 ^ y2 ^ y3 ^ y4 ^ y6
    // x5 = y2 ^ y3 ^ y4 ^ y5 ^ y7
    // x6 = y0 ^ y3 ^ y4 ^ y5 ^ y6
    // x7 = y1 ^ y4 ^ y5 ^ y6 ^ y7

    let mut y = [0u8; 8];

    for i in 0..8 {
        y[i] =
            ((value >> (8 * i)) & 0xff) as u8;
    }

    let x = [
        y[0] ^ y[2] ^ y[5] ^ y[6] ^ y[7],
        y[0] ^ y[1] ^ y[3] ^ y[6] ^ y[7],
        y[0] ^ y[1] ^ y[2] ^ y[4] ^ y[7],
        y[0] ^ y[1] ^ y[2] ^ y[3] ^ y[5],
        y[1] ^ y[2] ^ y[3] ^ y[4] ^ y[6],
        y[2] ^ y[3] ^ y[4] ^ y[5] ^ y[7],
        y[0] ^ y[3] ^ y[4] ^ y[5] ^ y[6],
        y[1] ^ y[4] ^ y[5] ^ y[6] ^ y[7],
    ];

    let mut result = 0u64;

    for i in 0..8 {
        result |=
            (x[i] as u64)
            << (8 * i);
    }

    result
}

fn check_diffuse_bijection() -> Result<(), String> {
    let test_values = [
        0u64,
        1u64,
        u64::MAX,
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0x8000_0000_0000_0000,
        0x0100_0000_0000_0000,
        0x0000_0000_0000_0001,
    ];

    for &x in &test_values {
        let y = diffuse(x);

        let recovered =
            inverse_diffuse_reference(y);

        if recovered != x {
            return Err(format!(
                "Diffuse inverse failure: \
                 x={:016x}, y={:016x}, recovered={:016x}",
                x,
                y,
                recovered
            ));
        }
    }

    // Additional deterministic coverage.
    let mut x =
        0x6a09_e667_f3bc_c908u64;

    for _ in 0..4096 {
        let y = diffuse(x);

        let recovered =
            inverse_diffuse_reference(y);

        if recovered != x {
            return Err(format!(
                "Diffuse inverse failure: \
                 x={:016x}, y={:016x}, recovered={:016x}",
                x,
                y,
                recovered
            ));
        }

        x = x
            .wrapping_mul(
                0x9E37_79B9_7F4A_7C15
            )
            .rotate_left(17);
    }

    Ok(())
}

// ============================================================
// Exact probability
// ============================================================

#[derive(Clone, Copy, Debug)]
struct Probability {
    numerator: u128,
    denominator_bits: u32,
}

impl Probability {
    fn zero() -> Self {
        Self {
            numerator: 0,
            denominator_bits: 0,
        }
    }

    fn probability_f64(self) -> f64 {
        if self.numerator == 0 {
            return 0.0;
        }

        (self.numerator as f64)
            * 2f64.powi(
                -(self.denominator_bits as i32)
            )
    }

    fn log2_probability(self) -> f64 {
        if self.numerator == 0 {
            return f64::NEG_INFINITY;
        }

        (self.numerator as f64)
            .log2()
            - self.denominator_bits as f64
    }
}

/// Exact one-round probability.
///
/// For:
///
///     (dl, dr) -> (next_dl, next_dr)
///
/// the Feistel equations require:
///
///     next_dl = dr
///
/// and:
///
///     ΔF = dl XOR next_dr
///
/// Because Diffuse is bijective:
///
///     ΔSBox = Diffuse^-1(ΔF)
///
/// is unique.
///
/// The probability is then:
///
///     Π_i DDT[dx_i][dy_i] / 256
fn exact_round_probability(
    ddt: &Ddt,
    dl: u64,
    dr: u64,
    next_dl: u64,
    next_dr: u64,
) -> Probability {
    if next_dl != dr {
        return Probability::zero();
    }

    let delta_f =
        dl ^ next_dr;

    let delta_sbox =
        inverse_diffuse_reference(delta_f);

    let mut numerator = 1u128;

    for i in 0..8 {
        let dx =
            ((dr >> (8 * i)) & 0xff)
            as usize;

        let dy =
            ((delta_sbox >> (8 * i)) & 0xff)
            as usize;

        let count =
            ddt[dx][dy] as u128;

        if count == 0 {
            return Probability::zero();
        }

        numerator =
            numerator.saturating_mul(count);
    }

    Probability {
        numerator,
        denominator_bits: 64,
    }
}

// ============================================================
// RNG
// ============================================================

/// Deterministic non-cryptographic RNG.
///
/// This is deliberately used only for Monte-Carlo sampling.
#[derive(Clone, Debug)]
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        let state =
            if seed == 0 {
                0xA409_3822_299F_31D0
            } else {
                seed
            };

        Self { state }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;

        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;

        self.state = x;

        x.wrapping_mul(
            0x2545_F491_4F6C_DD1D
        )
    }

    #[inline]
    fn uniform_below(
        &mut self,
        upper: u32,
    ) -> u32 {
        debug_assert!(upper > 0);

        let upper64 =
            upper as u64;

        let limit =
            u64::MAX
                - (u64::MAX % upper64);

        loop {
            let value =
                self.next_u64();

            if value < limit {
                return
                    (value % upper64)
                    as u32;
            }
        }
    }
}

// ============================================================
// DDT transition sampling
// ============================================================

#[inline]
fn sample_ddt_row(
    ddt: &Ddt,
    dx: u8,
    rng: &mut Rng,
) -> u8 {
    let row =
        &ddt[dx as usize];

    let random =
        rng.uniform_below(256);

    let mut cumulative = 0u32;

    for dy in 0..256 {
        cumulative +=
            row[dy] as u32;

        if random < cumulative {
            return dy as u8;
        }
    }

    unreachable!(
        "valid DDT row must sum to 256"
    );
}

#[inline]
fn sample_sbox_difference(
    ddt: &Ddt,
    input_difference: u64,
    rng: &mut Rng,
) -> u64 {
    let mut output = 0u64;

    for i in 0..8 {
        let dx =
            ((input_difference
                >> (8 * i))
                & 0xff) as u8;

        let dy =
            sample_ddt_row(
                ddt,
                dx,
                rng,
            );

        output |=
            (dy as u64)
            << (8 * i);
    }

    output
}

// ============================================================
// One Feistel differential transition
// ============================================================

#[inline]
fn sample_round(
    ddt: &Ddt,
    dl: u64,
    dr: u64,
    rng: &mut Rng,
) -> (u64, u64) {
    let delta_sbox =
        sample_sbox_difference(
            ddt,
            dr,
            rng,
        );

    let delta_f =
        diffuse(delta_sbox);

    let next_dl = dr;
    let next_dr =
        dl ^ delta_f;

    (next_dl, next_dr)
}

// ============================================================
// Verification result
// ============================================================

#[derive(Clone, Copy, Debug)]
struct VerificationResult {
    samples: u64,
    hits: u64,
}

impl VerificationResult {
    fn probability(self) -> f64 {
        self.hits as f64
            / self.samples as f64
    }

    fn log2_probability(self) -> f64 {
        let p =
            self.probability();

        if p == 0.0 {
            f64::NEG_INFINITY
        } else {
            p.log2()
        }
    }

    fn standard_error(self) -> f64 {
        let p =
            self.probability();

        (
            p * (1.0 - p)
                / self.samples as f64
        )
        .sqrt()
    }

    fn confidence_interval_95(
        self,
    ) -> (f64, f64) {
        let p =
            self.probability();

        let se =
            self.standard_error();

        let z =
            1.959_963_984_540_054;

        (
            (p - z * se).max(0.0),
            (p + z * se).min(1.0),
        )
    }
}

fn format_probability(
    p: f64,
) -> String {
    if p == 0.0 {
        "0".to_string()
    } else {
        format!("{:.8e}", p)
    }
}

// ============================================================
// Targeted Monte-Carlo verification
// ============================================================

fn verify_target(
    ddt: &Ddt,
    config: &Config,
) -> VerificationResult {
    let mut rng =
        Rng::new(config.seed);

    let mut hits = 0u64;
    let mut completed = 0u64;

    while completed < config.samples {
        let remaining =
            config.samples
                - completed;

        let batch =
            remaining.min(
                config.batch_size
            );

        for _ in 0..batch {
            let mut dl =
                config.input_dl;

            let mut dr =
                config.input_dr;

            for _ in 0..config.total_rounds {
                let next =
                    sample_round(
                        ddt,
                        dl,
                        dr,
                        &mut rng,
                    );

                dl = next.0;
                dr = next.1;
            }

            if dl == config.target_dl
                && dr == config.target_dr
            {
                hits += 1;
            }
        }

        completed += batch;

        if config.progress != 0
            && (
                completed
                    % config.progress
                    == 0
                || completed
                    == config.samples
            )
        {
            let p =
                hits as f64
                    / completed as f64;

            println!(
                "  {:>12}/{:<12}  hits={:<10}  P={:.8e}",
                completed,
                config.samples,
                hits,
                p
            );
        }
    }

    VerificationResult {
        samples: config.samples,
        hits,
    }
}

// ============================================================
// Main
// ============================================================

fn main() {
    let config =
        match Config::from_args() {
            Ok(c) => c,

            Err(e) => {
                eprintln!(
                    "ERROR: {}",
                    e
                );

                eprintln!(
                    "Use --help for usage."
                );

                std::process::exit(1);
            }
        };

    println!(
        "============================================================"
    );

    println!(
        "HERRINGFISH TARGETED DIFFERENTIAL VERIFIER"
    );

    println!(
        "============================================================"
    );

    println!(
        "Input  ΔL : 0x{:016x}",
        config.input_dl
    );

    println!(
        "Input  ΔR : 0x{:016x}",
        config.input_dr
    );

    println!(
        "Target ΔL : 0x{:016x}",
        config.target_dl
    );

    println!(
        "Target ΔR : 0x{:016x}",
        config.target_dr
    );

    println!(
        "Rounds    : {}",
        config.total_rounds
    );

    println!(
        "MITM split: {} forward + {} backward",
        config.forward_rounds,
        config.backward_rounds
    );

    println!(
        "Samples   : {}",
        config.samples
    );

    println!(
        "Seed      : 0x{:016x}",
        config.seed
    );

    println!();

    // --------------------------------------------------------
    // Project root / paths
    // --------------------------------------------------------

    let cwd =
        match std::env::current_dir() {
            Ok(path) => path,

            Err(e) => {
                eprintln!(
                    "ERROR: unable to determine current directory: {}",
                    e
                );

                std::process::exit(1);
            }
        };

    println!(
        "Project working directory:"
    );

    println!(
        "  {}",
        cwd.display()
    );

    println!();

    if !Path::new(TABLE_DIR).is_dir() {
        eprintln!(
            "ERROR: '{}' does not exist.",
            TABLE_DIR
        );

        eprintln!(
            "Run this example from the Herringfish project root."
        );

        std::process::exit(1);
    }

    // --------------------------------------------------------
    // Load project tables
    // --------------------------------------------------------

    let tables =
        if config.load_project_tables {
            match ProjectTables::load() {
                Ok(tables) => {
                    println!(
                        "Project tables: OK"
                    );

                    tables.print_summary();

                    println!();

                    Some(tables)
                }

                Err(e) => {
                    eprintln!(
                        "ERROR loading project tables:"
                    );

                    eprintln!(
                        "{}",
                        e
                    );

                    eprintln!();
                    eprintln!(
                        "Use --no-project-tables if you intentionally want to bypass project-table validation."
                    );

                    std::process::exit(1);
                }
            }
        } else {
            println!(
                "Project-table loading disabled."
            );

            println!();

            None
        };

    // --------------------------------------------------------
    // DDT
    // --------------------------------------------------------

    let ddt =
        if let Some(ref tables) = tables {
            match load_ddt_from_project_tables(
                tables
            ) {
                Ok(ddt) => ddt,

                Err(e) => {
                    eprintln!(
                        "ERROR parsing {}:",
                        DDT_MATRIX
                    );

                    eprintln!(
                        "{}",
                        e
                    );

                    std::process::exit(1);
                }
            }
        } else {
            match fs::read_to_string(
                DDT_MATRIX
            ) {
                Ok(text) => {
                    match parse_ddt_text(&text) {
                        Ok(ddt) => ddt,

                        Err(e) => {
                            eprintln!(
                                "ERROR parsing {}: {}",
                                DDT_MATRIX,
                                e
                            );

                            std::process::exit(1);
                        }
                    }
                }

                Err(e) => {
                    eprintln!(
                        "ERROR reading {}: {}",
                        DDT_MATRIX,
                        e
                    );

                    std::process::exit(1);
                }
            }
        };

    println!(
        "DDT: validated 256 x 256"
    );

    // --------------------------------------------------------
    // Diffusion
    // --------------------------------------------------------

    if config.check_diffuse {
        print!(
            "Diffuse bijection: "
        );

        if let Err(e) =
            check_diffuse_bijection()
        {
            println!("FAILED");

            eprintln!(
                "ERROR: {}",
                e
            );

            std::process::exit(1);
        }

        println!("OK");
    }

    // --------------------------------------------------------
    // Exact one-round calculation
    // --------------------------------------------------------

    if config.exact {
        println!();
        println!(
            "============================================================"
        );

        println!(
            "EXACT TARGETED ROUND CHECK"
        );

        println!(
            "============================================================"
        );

        if config.total_rounds == 1 {
            let exact =
                exact_round_probability(
                    &ddt,
                    config.input_dl,
                    config.input_dr,
                    config.target_dl,
                    config.target_dr,
                );

            let p =
                exact.probability_f64();

            println!(
                "Probability : {}",
                format_probability(p)
            );

            if p == 0.0 {
                println!(
                    "-log2(P)   : ∞"
                );
            } else {
                println!(
                    "-log2(P)   : {:.8}",
                    -exact.log2_probability()
                );
            }

            println!(
                "Numerator   : {}",
                exact.numerator
            );

            println!(
                "Denominator : 2^{}",
                exact.denominator_bits
            );
        } else {
            println!(
                "Exact single-round check is not applicable to the complete {}-round target.",
                config.total_rounds
            );

            println!(
                "The multi-round result below is obtained by targeted sampling."
            );
        }
    }

    // --------------------------------------------------------
    // Targeted verification
    // --------------------------------------------------------

    println!();
    println!(
        "============================================================"
    );

    println!(
        "TARGETED VERIFICATION"
    );

    println!(
        "============================================================"
    );

    println!(
        "No differential hull is being constructed."
    );

    println!(
        "No intermediate-state HashMap is being constructed."
    );

    println!(
        "Only the requested Δin → Δout hypothesis is measured."
    );

    println!();

    let result =
        verify_target(
            &ddt,
            &config,
        );

    let p =
        result.probability();

    let (ci_low, ci_high) =
        result.confidence_interval_95();

    println!();
    println!(
        "------------------------------------------------------------"
    );

    println!(
        "RESULT"
    );

    println!(
        "------------------------------------------------------------"
    );

    println!(
        "Samples        : {}",
        result.samples
    );

    println!(
        "Target hits    : {}",
        result.hits
    );

    println!(
        "Estimated P    : {}",
        format_probability(p)
    );

    if p == 0.0 {
        println!(
            "Estimated -log2(P): > {:.6}",
            (result.samples as f64).log2()
        );
    } else {
        println!(
            "Estimated -log2(P): {:.6}",
            -result.log2_probability()
        );
    }

    println!(
        "Standard error : {:.8e}",
        result.standard_error()
    );

    println!(
        "Approx. 95% CI : [{:.8e}, {:.8e}]",
        ci_low,
        ci_high
    );

    // --------------------------------------------------------
    // Interpretation
    // --------------------------------------------------------

    println!();
    println!(
        "------------------------------------------------------------"
    );

    println!(
        "INTERPRETATION"
    );

    println!(
        "------------------------------------------------------------"
    );

    if result.hits == 0 {
        println!(
            "No target hits were observed."
        );

        println!(
            "This does NOT establish P = 0."
        );

        println!(
            "The empirical resolution is approximately 1/N:"
        );

        println!(
            "    1/N = {:.8e}",
            1.0 / result.samples as f64
        );

        println!(
            "Increase --samples if a smaller probability must be resolved."
        );
    } else {
        println!(
            "The requested target differential was observed."
        );

        println!(
            "The measured frequency estimates:"
        );

        println!(
            "    P[Δout | Δin]"
        );

        println!(
            "for the requested {}-round differential.",
            config.total_rounds
        );
    }

    println!();
    println!(
        "============================================================"
    );

    println!(
        "Targeted verification complete."
    );

    println!(
        "============================================================"
    );
}