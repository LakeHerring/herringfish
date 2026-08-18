//! Herringfish Differential Characteristic Searcher
//!
//! Searches for high-probability differential characteristics through
//! the Herringfish v0.2 Feistel construction.
//!
//! The search works with differential weights:
//!
//!     W = -log2(P)
//!
//! Thus:
//!
//!     P >= 2^-35  <=>  W <= 35
//!
//! IMPORTANT:
//!
//! This searches INDIVIDUAL DIFFERENTIAL CHARACTERISTICS.
//!
//! It does NOT calculate differential hull probabilities.
//!
//! A hull requires summing the probabilities of multiple characteristics
//! having the same input/output differential pair.

use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

use std::cmp::Ordering;
use std::collections::HashMap;

// ============================================================================
// Configuration
// ============================================================================

const TOTAL_ROUNDS: usize = 8;

const START_DL: u64 = 0x0000_0000_0000_0000;
const START_DR: u64 = 0x0000_0000_0000_0001;

/// Maximum characteristic weight we are willing to consider.
///
///     W = -log2(P)
///
/// Therefore:
///
///     W <= 35  <=>  P >= 2^-35
const MAX_WEIGHT: f64 = 35.0;

/// Maximum number of states retained in the search frontier.
///
/// This prevents the Cartesian-product expansion from consuming
/// unbounded memory.
const BEAM_WIDTH: usize = 1_000_000;

/// Number of best final characteristics to display.
const MAX_RESULTS: usize = 25;

/// Maximum number of F-function differential transitions retained
/// for a single Feistel state.
///
/// Keeping only the strongest F transitions makes the search tractable
/// while still targeting the highest-probability characteristics.
const MAX_F_TRANSITIONS: usize = 50_000;

// ============================================================================
// DDT
// ============================================================================

type Ddt = [[u16; 256]; 256];

/// Construct the complete 8-bit S-box DDT.
fn build_ddt() -> Ddt {
    let mut ddt = [[0u16; 256]; 256];

    for dx in 0u16..=255 {
        for x in 0u16..=255 {
            let x0 = x as u8;
            let x1 = (x ^ dx) as u8;

            let y0 = HERRINGFISH_SBOX_V02[x0 as usize];
            let y1 = HERRINGFISH_SBOX_V02[x1 as usize];

            let dy = y0 ^ y1;

            ddt[dx as usize][dy as usize] += 1;
        }
    }

    ddt
}

/// Differential weight:
///
///     W = -log2(count / 256)
fn ddt_weight(count: u16) -> f64 {
    debug_assert!(count > 0);

    8.0 - (count as f64).log2()
}

// ============================================================================
// DDT diagnostics
// ============================================================================

fn print_ddt_statistics(ddt: &Ddt) {
    let mut nonzero_entries = 0usize;

    let mut trivial_max = 0u16;
    let mut nontrivial_max = 0u16;

    let mut max_dx = 0usize;
    let mut max_dy = 0usize;

    for dx in 0..256 {
        for dy in 0..256 {
            let count = ddt[dx][dy];

            if count == 0 {
                continue;
            }

            nonzero_entries += 1;

            if count > trivial_max {
                trivial_max = count;
            }

            // Ignore the trivial dx = 0 row for cryptographic
            // differential uniformity.
            if dx != 0 && count > nontrivial_max {
                nontrivial_max = count;
                max_dx = dx;
                max_dy = dy;
            }
        }
    }

    println!("DDT non-zero entries      : {}", nonzero_entries);

    println!(
        "DDT trivial maximum       : {} (Δx = 0, Δy = 0)",
        trivial_max
    );

    println!(
        "DDT nontrivial maximum    : {}",
        nontrivial_max
    );

    println!(
        "Maximum transition        : Δx = {:#04x}, Δy = {:#04x}",
        max_dx,
        max_dy
    );

    println!(
        "Maximum nontrivial P      : {:.10}",
        nontrivial_max as f64 / 256.0
    );

    println!(
        "Maximum nontrivial weight : {:.4}",
        ddt_weight(nontrivial_max)
    );

    if nontrivial_max <= 4 {
        println!("DDT acceptance             : PASS (max <= 4)");
    } else {
        println!("DDT acceptance             : FAIL (max > 4)");
    }
}

// ============================================================================
// Byte transitions
// ============================================================================

#[derive(Clone, Copy, Debug)]
struct ByteTransition {
    dy: u8,
    weight: f64,
}

fn build_byte_transitions(ddt: &Ddt) -> Vec<Vec<ByteTransition>> {
    let mut result = vec![Vec::new(); 256];

    for dx in 0..256 {
        for dy in 0..256 {
            let count = ddt[dx][dy];

            if count == 0 {
                continue;
            }

            result[dx].push(ByteTransition {
                dy: dy as u8,
                weight: ddt_weight(count),
            });
        }

        // Strongest transitions first.
        result[dx].sort_by(|a, b| {
            a.weight
                .partial_cmp(&b.weight)
                .unwrap_or(Ordering::Equal)
        });
    }

    result
}

// ============================================================================
// Diffusion
// ============================================================================

/// Herringfish v0.2:
///
///     out[i] = in[i]
///            XOR in[(i + 1) mod 8]
///            XOR in[(i + 3) mod 8]
fn apply_diffusion(diff: u64) -> u64 {
    let mut input = [0u8; 8];

    for i in 0..8 {
        input[i] = ((diff >> (8 * i)) & 0xff) as u8;
    }

    let mut output = [0u8; 8];

    for i in 0..8 {
        output[i] =
            input[i]
            ^ input[(i + 1) % 8]
            ^ input[(i + 3) % 8];
    }

    let mut result = 0u64;

    for i in 0..8 {
        result |= (output[i] as u64) << (8 * i);
    }

    result
}

// ============================================================================
// F-function differential expansion
// ============================================================================

#[derive(Clone, Copy, Debug)]
struct FTransition {
    output_diff: u64,
    weight: f64,
}

/// Expand:
///
///     ΔR
///      │
///      ▼
///     S-box layer
///      │
///      ▼
///     Diffusion
///      │
///      ▼
///     ΔF
///
/// The byte S-box transitions are combined using a Cartesian product.
fn expand_f_difference(
    input_diff: u64,
    byte_transitions: &[Vec<ByteTransition>],
    max_weight: f64,
) -> Vec<FTransition> {
    let mut candidates = Vec::new();

    enumerate_sbox_layer(
        0,
        input_diff,
        0,
        0.0,
        max_weight,
        byte_transitions,
        &mut candidates,
    );

    // The Cartesian product can still become large.
    //
    // Keep only the strongest F transitions.
    candidates.sort_by(|a, b| {
        a.weight
            .partial_cmp(&b.weight)
            .unwrap_or(Ordering::Equal)
    });

    candidates.truncate(MAX_F_TRANSITIONS);

    candidates
}

fn enumerate_sbox_layer(
    byte_index: usize,
    input_diff: u64,
    output_diff: u64,
    current_weight: f64,
    max_weight: f64,
    byte_transitions: &[Vec<ByteTransition>],
    output: &mut Vec<FTransition>,
) {
    if current_weight > max_weight {
        return;
    }

    if byte_index == 8 {
        output.push(FTransition {
            output_diff: apply_diffusion(output_diff),
            weight: current_weight,
        });

        return;
    }

    let dx =
        ((input_diff >> (byte_index * 8)) & 0xff) as usize;

    for transition in &byte_transitions[dx] {
        let new_weight =
            current_weight + transition.weight;

        if new_weight > max_weight {
            continue;
        }

        let mask = !(0xffu64 << (byte_index * 8));

        let new_output =
            (output_diff & mask)
            | ((transition.dy as u64) << (byte_index * 8));

        enumerate_sbox_layer(
            byte_index + 1,
            input_diff,
            new_output,
            new_weight,
            max_weight,
            byte_transitions,
            output,
        );
    }
}

// ============================================================================
// Differential state
// ============================================================================

#[derive(Clone, Debug)]
struct DifferentialState {
    round: usize,
    dl: u64,
    dr: u64,
    weight: f64,
    path: Vec<(u64, u64)>,
}

// ============================================================================
// Characteristic
// ============================================================================

#[derive(Clone, Debug)]
struct Characteristic {
    weight: f64,
    path: Vec<(u64, u64)>,
}

impl Characteristic {
    fn probability(&self) -> f64 {
        2.0_f64.powf(-self.weight)
    }
}

// ============================================================================
// Search
// ============================================================================

fn main() {
    println!("============================================================");
    println!("HERRINGFISH DIFFERENTIAL CHARACTERISTIC SEARCH");
    println!("============================================================");

    println!("Rounds          : {}", TOTAL_ROUNDS);
    println!("Start ΔL        : {:#018x}", START_DL);
    println!("Start ΔR        : {:#018x}", START_DR);
    println!("Threshold       : P >= 2^-{}", MAX_WEIGHT);
    println!("Beam width      : {}", BEAM_WIDTH);
    println!("Max results     : {}", MAX_RESULTS);
    println!();

    // ------------------------------------------------------------------------
    // DDT
    // ------------------------------------------------------------------------

    println!("Building S-box DDT...");

    let ddt = build_ddt();

    print_ddt_statistics(&ddt);

    println!();

    let byte_transitions =
        build_byte_transitions(&ddt);

    // ------------------------------------------------------------------------
    // Initial state
    // ------------------------------------------------------------------------

    let mut frontier = vec![DifferentialState {
        round: 0,
        dl: START_DL,
        dr: START_DR,
        weight: 0.0,
        path: vec![(START_DL, START_DR)],
    }];

    let mut visited: HashMap<
        (usize, u64, u64),
        f64,
    > = HashMap::new();

    let mut final_results = Vec::<Characteristic>::new();

    let mut total_expanded = 0usize;
    let mut total_generated = 1usize;

    // ------------------------------------------------------------------------
    // Round-by-round beam search
    // ------------------------------------------------------------------------

    for round in 0..TOTAL_ROUNDS {
        println!(
            "Round {:>2}: frontier = {}",
            round,
            frontier.len()
        );

        /*
         * IMPORTANT OWNERSHIP FIX
         *
         * `frontier.into_iter()` would move `frontier`.
         *
         * We need `frontier` to remain initialized because control flow
         * later checks it and then assigns the next frontier.
         *
         * `mem::take()` moves the Vec out while replacing `frontier`
         * with an empty Vec.
         *
         * This avoids cloning potentially millions of states.
         */
        let current_frontier =
            std::mem::take(&mut frontier);

        let mut next_frontier =
            Vec::<DifferentialState>::new();

        for current in current_frontier {
            total_expanded += 1;

            if current.weight > MAX_WEIGHT {
                continue;
            }

            // ---------------------------------------------------------------
            // Feistel differential:
            //
            //     ΔL' = ΔR
            //
            //     ΔR' = ΔL XOR ΔF
            // ---------------------------------------------------------------

            let remaining_weight =
                MAX_WEIGHT - current.weight;

            let f_transitions =
                expand_f_difference(
                    current.dr,
                    &byte_transitions,
                    remaining_weight,
                );

            for f_transition in f_transitions {
                let new_weight =
                    current.weight
                    + f_transition.weight;

                if new_weight > MAX_WEIGHT {
                    continue;
                }

                let new_dl = current.dr;

                let new_dr =
                    current.dl
                    ^ f_transition.output_diff;

                let new_round = round + 1;

                let key =
                    (new_round, new_dl, new_dr);

                // Keep only the best path to an identical
                // differential state.
                if let Some(&old_weight) =
                    visited.get(&key)
                {
                    if old_weight <= new_weight {
                        continue;
                    }
                }

                visited.insert(key, new_weight);

                let mut path =
                    current.path.clone();

                path.push((new_dl, new_dr));

                next_frontier.push(
                    DifferentialState {
                        round: new_round,
                        dl: new_dl,
                        dr: new_dr,
                        weight: new_weight,
                        path,
                    },
                );

                total_generated += 1;
            }
        }

        // --------------------------------------------------------------------
        // Keep only the strongest states.
        // --------------------------------------------------------------------

        next_frontier.sort_by(|a, b| {
            a.weight
                .partial_cmp(&b.weight)
                .unwrap_or(Ordering::Equal)
        });

        if next_frontier.len() > BEAM_WIDTH {
            next_frontier.truncate(BEAM_WIDTH);
        }

        println!(
            "Round {:>2}: retained  = {}",
            round + 1,
            next_frontier.len()
        );

        if let Some(best) =
            next_frontier.first()
        {
            println!(
                "         best W   = {:.4}",
                best.weight
            );

            println!(
                "         best P   = {:.6e}",
                2.0_f64.powf(-best.weight)
            );
        }

        println!();

        // If this is the final round, collect results.
        if round + 1 == TOTAL_ROUNDS {
            for state in &next_frontier {
                final_results.push(
                    Characteristic {
                        weight: state.weight,
                        path: state.path.clone(),
                    },
                );
            }
        }

        frontier = next_frontier;

        if frontier.is_empty() {
            println!(
                "Search terminated: no states remain."
            );

            break;
        }
    }

    // ------------------------------------------------------------------------
    // Sort final characteristics
    // ------------------------------------------------------------------------

    final_results.sort_by(|a, b| {
        a.weight
            .partial_cmp(&b.weight)
            .unwrap_or(Ordering::Equal)
    });

    // ------------------------------------------------------------------------
    // Results
    // ------------------------------------------------------------------------

    println!("============================================================");
    println!("SEARCH COMPLETE");
    println!("============================================================");

    println!(
        "States expanded  : {}",
        total_expanded
    );

    println!(
        "States generated : {}",
        total_generated
    );

    println!(
        "Visited states   : {}",
        visited.len()
    );

    println!(
        "Final candidates : {}",
        final_results.len()
    );

    println!();

    if final_results.is_empty() {
        println!("No characteristics found.");
        return;
    }

    println!(
        "Top {} characteristics:",
        final_results
            .len()
            .min(MAX_RESULTS)
    );

    println!();

    for (index, characteristic) in
        final_results
            .iter()
            .take(MAX_RESULTS)
            .enumerate()
    {
        println!(
            "#{:<3} W = {:>8.4}   P = {:>12.6e}",
            index + 1,
            characteristic.weight,
            characteristic.probability()
        );

        for (round, &(dl, dr)) in
            characteristic.path.iter().enumerate()
        {
            println!(
                "      r{:>2}: ΔL = {:#018x}  ΔR = {:#018x}",
                round,
                dl,
                dr
            );
        }

        println!();
    }
}