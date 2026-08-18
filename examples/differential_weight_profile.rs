//! Herringfish Differential Weight Profile
//!
//! Measures the best observed differential-characteristic weight
//! at each round without applying a probability/weight cutoff.
//!
//! IMPORTANT:
//!
//! This searches INDIVIDUAL DIFFERENTIAL CHARACTERISTICS.
//!
//! It does NOT calculate differential hull probabilities.
//!
//! The search is bounded:
//!
//!     - finite beam width
//!     - finite number of F-function transitions per state
//!
//! Therefore the result is an observed lower bound on the best
//! characteristic found by this search configuration, not a proof
//! of the globally optimal characteristic.
//!
//! The implementation is deliberately memory-bounded.
//!
//! It does NOT materialize:
//!
//!     states × F-transitions
//!
//! as a giant intermediate vector.
//!
//! Instead, F transitions are generated in bounded best-first order
//! and inserted directly into the next beam.

use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

// ============================================================================
// Configuration
// ============================================================================

const TOTAL_ROUNDS: usize = 8;

const START_DL: u64 = 0x0000_0000_0000_0000;
const START_DR: u64 = 0x0000_0000_0000_0001;

/// Number of states retained between rounds.
///
/// 1,000,000 is possible, but is unnecessarily expensive for a profile
/// experiment. Start smaller and increase only after the algorithm has
/// demonstrated stable behaviour.
const BEAM_WIDTH: usize = 100_000;

/// Number of strongest F-function transitions generated per state.
///
/// This is deliberately much smaller than the previous 50,000.
///
/// Because transitions are generated best-first, these are the strongest
/// transitions rather than an arbitrary subset.
const MAX_F_TRANSITIONS: usize = 256;

/// Number of final characteristics to report.
const MAX_RESULTS: usize = 10;

// ============================================================================
// DDT
// ============================================================================

type Ddt = [[u16; 256]; 256];

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

            if dx != 0 && count > nontrivial_max {
                nontrivial_max = count;
                max_dx = dx;
                max_dy = dy;
            }
        }
    }

    println!(
        "DDT non-zero entries      : {}",
        nonzero_entries
    );

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
// F-transition representation
// ============================================================================

#[derive(Clone, Copy, Debug)]
struct FTransition {
    output_diff: u64,
    weight: f64,
}

// ============================================================================
// Best-first partial S-box expansion
// ============================================================================
//
// Instead of recursively constructing every Cartesian-product transition,
// we search the Cartesian product in increasing weight order.
//
// For each byte:
//
//     transitions[byte][index]
//
// is already sorted by weight.
//
// A state:
//
//     [i0, i1, ..., i7]
//
// represents one combination of byte transitions.
//
// We begin with:
//
//     [0,0,0,0,0,0,0,0]
//
// and expand neighbours by increasing one index.
//
// This is a standard k-best Cartesian-product enumeration technique.
//
// Crucially, only a small priority queue is retained.

#[derive(Clone, Debug)]
struct PartialCombination {
    indices: [usize; 8],
    weight: f64,
}

// BinaryHeap is a max-heap, so reverse the ordering to obtain a
// min-heap based on weight.
impl Eq for PartialCombination {}

impl PartialEq for PartialCombination {
    fn eq(&self, other: &Self) -> bool {
        self.weight == other.weight
            && self.indices == other.indices
    }
}

impl Ord for PartialCombination {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .weight
            .partial_cmp(&self.weight)
            .unwrap_or(Ordering::Equal)
            .then_with(|| self.indices.cmp(&other.indices))
    }
}

impl PartialOrd for PartialCombination {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ============================================================================
// Generate strongest F transitions
// ============================================================================

fn strongest_f_transitions(
    input_diff: u64,
    byte_transitions: &[Vec<ByteTransition>],
    limit: usize,
) -> Vec<FTransition> {
    // ---------------------------------------------------------------
    // Extract the eight input-byte differences.
    // ---------------------------------------------------------------

    let mut dx = [0usize; 8];

    for i in 0..8 {
        dx[i] =
            ((input_diff >> (8 * i)) & 0xff) as usize;
    }

    // ---------------------------------------------------------------
    // Zero-difference bytes have exactly one transition:
    //
    //     0 -> 0
    //
    // This means they do not contribute any branching.
    // ---------------------------------------------------------------

    let mut initial_indices = [0usize; 8];

    let mut initial_weight = 0.0;

    for i in 0..8 {
        if byte_transitions[dx[i]].is_empty() {
            return Vec::new();
        }

        initial_indices[i] = 0;

        initial_weight +=
            byte_transitions[dx[i]][0].weight;
    }

    // ---------------------------------------------------------------
    // Best-first Cartesian product.
    // ---------------------------------------------------------------

    let mut heap = BinaryHeap::new();

    heap.push(PartialCombination {
        indices: initial_indices,
        weight: initial_weight,
    });

    let mut visited =
        std::collections::HashSet::<[usize; 8]>::new();

    visited.insert(initial_indices);

    let mut result =
        Vec::<FTransition>::with_capacity(limit.min(256));

    while let Some(current) = heap.pop() {
        if result.len() >= limit {
            break;
        }

        // -----------------------------------------------------------
        // Convert byte transition indices into a 64-bit difference.
        // -----------------------------------------------------------

        let mut sbox_output = 0u64;

        for i in 0..8 {
            let transition =
                byte_transitions[dx[i]][current.indices[i]];

            sbox_output |=
                (transition.dy as u64) << (8 * i);
        }

        let output_diff =
            apply_diffusion(sbox_output);

        result.push(FTransition {
            output_diff,
            weight: current.weight,
        });

        // -----------------------------------------------------------
        // Generate neighbouring combinations.
        // -----------------------------------------------------------

        for byte_index in 0..8 {
            let old_index =
                current.indices[byte_index];

            let new_index =
                old_index + 1;

            if new_index >=
                byte_transitions[dx[byte_index]].len()
            {
                continue;
            }

            let mut next_indices =
                current.indices;

            next_indices[byte_index] =
                new_index;

            if !visited.insert(next_indices) {
                continue;
            }

            let old_weight =
                byte_transitions[dx[byte_index]]
                    [old_index]
                    .weight;

            let new_weight =
                byte_transitions[dx[byte_index]]
                    [new_index]
                    .weight;

            let next_weight =
                current.weight
                    - old_weight
                    + new_weight;

            heap.push(PartialCombination {
                indices: next_indices,
                weight: next_weight,
            });
        }
    }

    result
}

// ============================================================================
// Differential state
// ============================================================================

#[derive(Clone, Copy, Debug)]
struct DifferentialState {
    dl: u64,
    dr: u64,
    weight: f64,
}

// ============================================================================
// Candidate ordering
// ============================================================================

impl Eq for DifferentialState {}

impl PartialEq for DifferentialState {
    fn eq(&self, other: &Self) -> bool {
        self.dl == other.dl
            && self.dr == other.dr
            && self.weight == other.weight
    }
}

impl Ord for DifferentialState {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .weight
            .partial_cmp(&self.weight)
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for DifferentialState {
    fn partial_cmp(
        &self,
        other: &Self,
    ) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ============================================================================
// Retain strongest states
// ============================================================================
//
// We use a max-heap containing the CURRENT worst retained state.
//
// This allows us to process generated candidates without first creating
// an enormous vector and sorting it.
//
// Memory usage is therefore bounded by approximately BEAM_WIDTH states.

fn insert_into_beam(
    heap: &mut BinaryHeap<DifferentialState>,
    state: DifferentialState,
) {
    if heap.len() < BEAM_WIDTH {
        heap.push(state);
        return;
    }

    let worst =
        heap.peek()
            .expect("beam cannot be empty");

    // Because the heap is ordered with the weakest state as the
    // greatest element, replace it when the new state is better.
    if state.weight < worst.weight {
        heap.pop();
        heap.push(state);
    }
}

// ============================================================================
// Convert heap into sorted frontier
// ============================================================================

fn finalize_beam(
    heap: BinaryHeap<DifferentialState>,
) -> Vec<DifferentialState> {
    let mut result =
        heap.into_vec();

    result.sort_by(|a, b| {
        a.weight
            .partial_cmp(&b.weight)
            .unwrap_or(Ordering::Equal)
    });

    result
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    println!("============================================================");
    println!("HERRINGFISH DIFFERENTIAL WEIGHT PROFILE");
    println!("============================================================");
    println!();

    println!(
        "This experiment has NO 2^-35 weight cutoff."
    );

    println!(
        "It measures the best observed characteristic"
    );

    println!(
        "weight at each round using bounded beam search."
    );

    println!();

    println!("Rounds           : {}", TOTAL_ROUNDS);
    println!(
        "Start ΔL         : {:#018x}",
        START_DL
    );
    println!(
        "Start ΔR         : {:#018x}",
        START_DR
    );
    println!(
        "Beam width       : {}",
        BEAM_WIDTH
    );
    println!(
        "Max F transitions: {}",
        MAX_F_TRANSITIONS
    );
    println!(
        "Max results      : {}",
        MAX_RESULTS
    );

    println!();

    // ========================================================================
    // DDT
    // ========================================================================

    println!("Building S-box DDT...");

    let ddt =
        build_ddt();

    print_ddt_statistics(&ddt);

    println!();

    let byte_transitions =
        build_byte_transitions(&ddt);

    // ========================================================================
    // Initial state
    // ========================================================================

    let mut frontier =
        vec![DifferentialState {
            dl: START_DL,
            dr: START_DR,
            weight: 0.0,
        }];

    // Cache F-transition expansions by input difference.
    //
    // Multiple differential states can have the same ΔR.
    //
    // Without this cache, the same expensive Cartesian-product
    // calculation may be repeated many times.

    let mut f_cache:
        HashMap<u64, Vec<FTransition>>
        = HashMap::new();

    // ========================================================================
    // Profile
    // ========================================================================

    println!();

    for round in 0..TOTAL_ROUNDS {
        println!(
            "Round {:>2}: frontier = {}",
            round,
            frontier.len()
        );

        // --------------------------------------------------------------------
        // Global bounded beam.
        // --------------------------------------------------------------------

        let mut next_heap =
            BinaryHeap::<DifferentialState>::new();

        let mut generated =
            0usize;

        // --------------------------------------------------------------------
        // State deduplication.
        //
        // Keep the best weight encountered for each differential state.
        // This prevents thousands of identical states entering the beam.
        // --------------------------------------------------------------------

        let mut best_seen:
            HashMap<(u64, u64), f64>
            = HashMap::new();

        for current in frontier.iter() {
            // ---------------------------------------------------------------
            // Retrieve or construct F transitions.
            // ---------------------------------------------------------------

            let f_transitions =
                f_cache
                    .entry(current.dr)
                    .or_insert_with(|| {
                        strongest_f_transitions(
                            current.dr,
                            &byte_transitions,
                            MAX_F_TRANSITIONS,
                        )
                    });

            // ---------------------------------------------------------------
            // Feistel differential:
            //
            //     ΔL' = ΔR
            //
            //     ΔR' = ΔL XOR ΔF
            // ---------------------------------------------------------------

            for f_transition in f_transitions.iter() {
                let new_weight =
                    current.weight
                        + f_transition.weight;

                let new_dl =
                    current.dr;

                let new_dr =
                    current.dl
                        ^ f_transition.output_diff;

                let key =
                    (new_dl, new_dr);

                if let Some(old_weight) =
                    best_seen.get(&key)
                {
                    if *old_weight <= new_weight {
                        continue;
                    }
                }

                best_seen.insert(
                    key,
                    new_weight,
                );

                generated += 1;

                insert_into_beam(
                    &mut next_heap,
                    DifferentialState {
                        dl: new_dl,
                        dr: new_dr,
                        weight: new_weight,
                    },
                );
            }
        }

        // --------------------------------------------------------------------
        // Convert bounded heap into sorted frontier.
        // --------------------------------------------------------------------

        let next_frontier =
            finalize_beam(next_heap);

        println!(
            "Round {:>2}: generated = {}",
            round + 1,
            generated
        );

        if let Some(best) =
            next_frontier.first()
        {
            println!(
                "         best W   = {:.6}",
                best.weight
            );

            println!(
                "         best P   = {:.12e}",
                2.0_f64.powf(-best.weight)
            );

            println!(
                "         best ΔL  = {:#018x}",
                best.dl
            );

            println!(
                "         best ΔR  = {:#018x}",
                best.dr
            );
        }

        println!(
            "         retained = {}",
            next_frontier.len()
        );

        println!();

        if next_frontier.is_empty() {
            println!(
                "Search terminated: no states remain."
            );

            break;
        }

        frontier =
            next_frontier;
    }

    // ========================================================================
    // Final results
    // ========================================================================

    println!("============================================================");
    println!("PROFILE COMPLETE");
    println!("============================================================");

    println!();

    if frontier.is_empty() {
        println!("No states survived.");
        return;
    }

    println!(
        "Top {} final states:",
        frontier.len().min(MAX_RESULTS)
    );

    println!();

    for (index, state) in frontier
        .iter()
        .take(MAX_RESULTS)
        .enumerate()
    {
        println!(
            "#{:<3} W = {:>10.6}   P = {:>14.8e}",
            index + 1,
            state.weight,
            2.0_f64.powf(-state.weight)
        );

        println!(
            "      ΔL = {:#018x}",
            state.dl
        );

        println!(
            "      ΔR = {:#018x}",
            state.dr
        );

        println!();
    }

    println!("============================================================");
    println!("INTERPRETATION");
    println!("============================================================");
    println!();

    println!(
        "The reported weights are the best characteristics"
    );

    println!(
        "observed by this bounded beam search."
    );

    println!();

    println!(
        "They are NOT differential-hull probabilities."
    );

    println!(
        "Increasing BEAM_WIDTH and MAX_F_TRANSITIONS can"
    );

    println!(
        "improve coverage, but also increases runtime."
    );
}