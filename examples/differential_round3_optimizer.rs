//! HERRINGFISH ROUND-3 DIFFERENTIAL OPTIMIZER
//!
//! Target-aware branch-and-bound search for individual differential
//! characteristics over three Feistel rounds.
//!
//! Initial difference:
//!
//!     ΔL0 = 0
//!     ΔR0 = 1
//!
//! Feistel round:
//!
//!     ΔL' = ΔR
//!     ΔR' = ΔL XOR ΔF
//!
//! The optimizer searches for individual characteristics satisfying:
//!
//!     W <= target
//!
//! IMPORTANT:
//!
//! - This searches individual differential characteristics.
//! - It does NOT calculate differential hull probabilities.
//! - --beam bounds the retained Round-2 state set.
//! - --f-max bounds the retained F transitions per F expansion.
//! - --result-limit bounds retained final characteristics while preserving
//!   the best results by weight.
//! - A globally optimal result requires exhaustive coverage.
//!
//! Usage:
//!
//!     cargo run --release --example differential_round3_optimizer -- 37
//!
//! Example:
//!
//!     cargo run --release --example differential_round3_optimizer -- 37 \
//!         --beam 2000000 --f-max 32768 --result-limit 10000

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::env;

use herringfish::cipher::feistel_arx::{HERRINGFISH_SBOX_V02, diffuse};

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_BEAM: usize = 1_000_000;
const DEFAULT_F_MAX: usize = 256;
const DEFAULT_RESULT_LIMIT: usize = 10_000;

const BYTE_COUNT: usize = 8;
const BYTE_VALUES: usize = 256;

const INF: f64 = f64::INFINITY;
const EPS: f64 = 1e-12;

// ============================================================================
// Helpers
// ============================================================================

#[inline]
fn get_byte(x: u64, index: usize) -> u8 {
    ((x >> (index * 8)) & 0xff) as u8
}

#[inline]
fn set_byte(x: u64, index: usize, value: u8) -> u64 {
    let shift = index * 8;
    let mask = 0xffu64 << shift;

    (x & !mask) | ((value as u64) << shift)
}

#[inline]
fn weight_from_count(count: u16) -> f64 {
    if count == 0 {
        INF
    } else {
        8.0 - (count as f64).log2()
    }
}

#[inline]
fn probability_from_weight(weight: f64) -> f64 {
    2.0f64.powf(-weight)
}

// ============================================================================
// DDT
// ============================================================================

#[derive(Clone, Copy)]
struct ByteTransition {
    out: u8,
    weight: f64,
}

#[derive(Clone)]
struct Ddt {
    counts: [[u16; BYTE_VALUES]; BYTE_VALUES],

    transitions: Vec<Vec<ByteTransition>>,

    /// Minimum non-zero-output transition weight for every input byte
    /// difference.
    ///
    /// min_weight[0] = 0 because:
    ///
    ///     0 -> 0
    ///
    /// has probability 1.
    min_weight: [f64; BYTE_VALUES],

    /// Globally cheapest non-trivial S-box transition.
    global_min_weight: f64,
}

impl Ddt {
    fn build() -> Self {
        let mut counts = [[0u16; BYTE_VALUES]; BYTE_VALUES];

        for dx in 0..BYTE_VALUES {
            for x in 0..BYTE_VALUES {
                let y0 = HERRINGFISH_SBOX_V02[x];
                let y1 = HERRINGFISH_SBOX_V02[x ^ dx];

                let dy = (y0 ^ y1) as usize;

                counts[dx][dy] += 1;
            }
        }

        let mut transitions = vec![Vec::<ByteTransition>::new(); BYTE_VALUES];

        let mut min_weight = [INF; BYTE_VALUES];

        min_weight[0] = 0.0;

        for dx in 0..BYTE_VALUES {
            for dy in 0..BYTE_VALUES {
                let count = counts[dx][dy];

                if count == 0 {
                    continue;
                }

                let weight = weight_from_count(count);

                transitions[dx].push(ByteTransition {
                    out: dy as u8,
                    weight,
                });

                //
                // For non-zero input differences we only use non-zero
                // output differences for the minimum active-byte bound.
                //
                if dx != 0 && dy != 0 && weight < min_weight[dx] {
                    min_weight[dx] = weight;
                }
            }

            transitions[dx].sort_by(|a, b| {
                a.weight
                    .partial_cmp(&b.weight)
                    .unwrap_or(Ordering::Equal)
                    .then_with(|| a.out.cmp(&b.out))
            });
        }

        let global_min_weight = min_weight
            .iter()
            .copied()
            .filter(|w| w.is_finite() && *w > 0.0)
            .fold(INF, f64::min);

        Self {
            counts,
            transitions,
            min_weight,
            global_min_weight,
        }
    }

    fn print_statistics(&self) {
        let mut nonzero_entries = 0usize;

        let mut trivial_max = 0u16;

        let mut nontrivial_max = 0u16;
        let mut max_dx = 0usize;
        let mut max_dy = 0usize;

        for dx in 0..BYTE_VALUES {
            for dy in 0..BYTE_VALUES {
                let count = self.counts[dx][dy];

                if count != 0 {
                    nonzero_entries += 1;
                }

                if dx == 0 && dy == 0 {
                    trivial_max = trivial_max.max(count);
                } else if dx != 0 && count > nontrivial_max {
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

        println!("DDT nontrivial maximum    : {}", nontrivial_max);

        println!(
            "Maximum transition        : Δx = 0x{:02x}, Δy = 0x{:02x}",
            max_dx, max_dy
        );

        println!(
            "Maximum nontrivial P      : {:.10}",
            nontrivial_max as f64 / 256.0
        );

        println!(
            "Maximum nontrivial weight : {:.4}",
            weight_from_count(nontrivial_max)
        );

        if nontrivial_max <= 4 {
            println!("DDT acceptance             : PASS (max <= 4)");
        } else {
            println!("DDT acceptance             : FAIL (max > 4)");
        }

        println!("Global minimum byte weight : {:.6}", self.global_min_weight);
    }

    // ------------------------------------------------------------------------
    // Lower bounds
    // ------------------------------------------------------------------------

    /// Minimum possible weight of an F-function whose input difference
    /// is `input`, considering each byte independently.
    #[inline]
    fn f_input_lb(&self, input: u64) -> f64 {
        let mut weight = 0.0;

        for i in 0..BYTE_COUNT {
            let dx = get_byte(input, i) as usize;

            if dx != 0 {
                weight += self.min_weight[dx];
            }
        }

        weight
    }

    /// Minimum remaining F weight after `next_byte`.
    #[inline]
    fn remaining_f_lb(&self, input: u64, next_byte: usize) -> f64 {
        let mut weight = 0.0;

        for i in next_byte..BYTE_COUNT {
            let dx = get_byte(input, i) as usize;

            if dx != 0 {
                weight += self.min_weight[dx];
            }
        }

        weight
    }
}

// ============================================================================
// F-search statistics
// ============================================================================

#[derive(Default, Clone)]
struct FStats {
    recursive_nodes: u64,
    lower_bound_pruned: u64,
    target_pruned: u64,
    complete_transitions: u64,
    heap_rejected: u64,
    heap_evicted: u64,
    retained: u64,
    /// Number of F expansions where the configured retention cap discarded
    /// at least one otherwise viable transition.
    expansions_truncated: u64,
}

impl FStats {
    fn add(&mut self, other: &FStats) {
        self.recursive_nodes += other.recursive_nodes;
        self.lower_bound_pruned += other.lower_bound_pruned;
        self.target_pruned += other.target_pruned;
        self.complete_transitions += other.complete_transitions;
        self.heap_rejected += other.heap_rejected;
        self.heap_evicted += other.heap_evicted;
        self.retained += other.retained;
        self.expansions_truncated += other.expansions_truncated;
    }
}

// ============================================================================
// F transition
// ============================================================================

#[derive(Clone, Copy)]
struct FTransition {
    df: u64,
    weight: f64,
    /// An admissible ranking score for bounded retention.  It includes the
    /// current F weight and, where applicable, the cheapest possible next F.
    rank: f64,
}

impl PartialEq for FTransition {
    fn eq(&self, other: &Self) -> bool {
        self.weight == other.weight && self.df == other.df && self.rank == other.rank
    }
}

impl Eq for FTransition {}

impl PartialOrd for FTransition {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FTransition {
    fn cmp(&self, other: &Self) -> Ordering {
        //
        // BinaryHeap is a max-heap, so the naturally greatest (worst)
        // transition remains at the root and can be replaced cheaply.
        self.rank
            .partial_cmp(&other.rank)
            .unwrap_or(Ordering::Equal)
            .then_with(|| {
                self.weight
                    .partial_cmp(&other.weight)
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| self.df.cmp(&other.df))
    }
}

// ============================================================================
// F search
// ============================================================================

struct FSearch<'a> {
    ddt: &'a Ddt,

    /// F input difference.
    input: u64,

    /// Fixed XOR applied to the F output when constructing the next
    /// Feistel right difference.
    ///
    ///     next_dr = fixed_xor XOR df
    ///
    fixed_xor: u64,

    /// Weight accumulated before this F function.
    base_weight: f64,

    /// Maximum characteristic weight.
    target_weight: f64,

    /// Maximum retained F transitions.
    f_max: usize,

    /// Whether this F expansion is followed by another F-function whose
    /// minimum possible cost may be used as a lower bound.  This is true for
    /// rounds 1 and 2, and false when expanding the final (third) round.
    has_future_f: bool,

    stats: FStats,

    heap: BinaryHeap<FTransition>,

    /// True only if the F-transition cap actually discarded a viable leaf.
    limit_truncated: bool,
}

impl<'a> FSearch<'a> {
    fn new(
        ddt: &'a Ddt,
        input: u64,
        fixed_xor: u64,
        base_weight: f64,
        target_weight: f64,
        f_max: usize,
        has_future_f: bool,
    ) -> Self {
        Self {
            ddt,
            input,
            fixed_xor,
            base_weight,
            target_weight,
            f_max,
            has_future_f,
            stats: FStats::default(),
            heap: BinaryHeap::new(),
            limit_truncated: false,
        }
    }

    // ------------------------------------------------------------------------
    // Lower bound
    // ------------------------------------------------------------------------

    /// Computes a safe lower bound on the cost of the F-function after this
    /// one while the current F output is still partially assigned.
    ///
    /// This is important:
    ///
    ///     ΔR_next = fixed_xor XOR ΔF
    ///
    /// NOT simply:
    ///
    ///     ΔR_next = ΔF
    ///
    /// Therefore a known non-zero ΔF byte does NOT necessarily force
    /// an active Round-3 byte. It can cancel with `fixed_xor`.
    ///
    /// We only count a diffused output byte when all of its dependencies are
    /// known.  In particular, `pre_diff[i]` alone is not `diffuse(pre_diff)`
    /// at byte `i`.
    #[inline]
    fn partial_future_f_lb(&self, pre_diff: u64, assigned: &[bool; BYTE_COUNT]) -> f64 {
        let mut weight = 0.0;

        for i in 0..BYTE_COUNT {
            let dependency_1 = (i + 1) & 7;
            let dependency_3 = (i + 3) & 7;

            if !assigned[i] || !assigned[dependency_1] || !assigned[dependency_3] {
                continue;
            }

            let df_byte = get_byte(pre_diff, i)
                ^ get_byte(pre_diff, dependency_1)
                ^ get_byte(pre_diff, dependency_3);

            let next_byte = get_byte(self.fixed_xor, i) ^ df_byte;

            if next_byte != 0 {
                weight += self.ddt.global_min_weight;
            }
        }

        weight
    }

    /// Safe lower bound for the remainder of the search.
    #[inline]
    fn lower_bound(
        &self,
        next_byte: usize,
        current_f_weight: f64,
        pre_diff: u64,
        assigned: &[bool; BYTE_COUNT],
    ) -> f64 {
        let remaining_f = self.ddt.remaining_f_lb(self.input, next_byte);

        let future_f = if self.has_future_f {
            self.partial_future_f_lb(pre_diff, assigned)
        } else {
            0.0
        };

        self.base_weight + current_f_weight + remaining_f + future_f
    }

    #[inline]
    fn target_pruned(
        &mut self,
        next_byte: usize,
        current_f_weight: f64,
        pre_diff: u64,
        assigned: &[bool; BYTE_COUNT],
    ) -> bool {
        let lb = self.lower_bound(next_byte, current_f_weight, pre_diff, assigned);

        if lb > self.target_weight + EPS {
            self.stats.lower_bound_pruned += 1;
            return true;
        }

        false
    }

    // ------------------------------------------------------------------------
    // Heap
    // ------------------------------------------------------------------------

    fn retain(&mut self, transition: FTransition) {
        if self.f_max == 0 {
            self.stats.heap_rejected += 1;
            return;
        }

        if self.heap.len() < self.f_max {
            self.heap.push(transition);
            return;
        }

        let worst = self.heap.peek().copied();

        match worst {
            Some(worst) if transition.cmp(&worst) == Ordering::Less => {
                self.heap.pop();
                self.heap.push(transition);
                self.stats.heap_evicted += 1;
                self.limit_truncated = true;
            }

            _ => {
                self.stats.heap_rejected += 1;
                self.limit_truncated = true;
            }
        }
    }

    // ------------------------------------------------------------------------
    // Recursion
    // ------------------------------------------------------------------------

    fn recurse(
        &mut self,
        byte_index: usize,
        pre_diff: u64,
        current_weight: f64,
        assigned: &mut [bool; BYTE_COUNT],
    ) {
        self.stats.recursive_nodes += 1;

        if byte_index == BYTE_COUNT {
            self.stats.complete_transitions += 1;

            let df = diffuse(pre_diff);

            let next_dr = self.fixed_xor ^ df;

            let total_weight = self.base_weight + current_weight;

            //
            let future_f_lb = if self.has_future_f {
                self.ddt.f_input_lb(next_dr)
            } else {
                0.0
            };

            let final_lb = total_weight + future_f_lb;

            if final_lb > self.target_weight + EPS {
                self.stats.target_pruned += 1;
                return;
            }

            self.retain(FTransition {
                df,
                weight: current_weight,
                rank: current_weight + future_f_lb,
            });

            return;
        }

        let dx = get_byte(self.input, byte_index) as usize;

        let transition_count = self.ddt.transitions[dx].len();

        for transition_index in 0..transition_count {
            let transition = self.ddt.transitions[dx][transition_index];
            let next_weight = current_weight + transition.weight;

            if self.base_weight + next_weight > self.target_weight + EPS {
                continue;
            }

            let next_pre = set_byte(pre_diff, byte_index, transition.out);

            assigned[byte_index] = true;

            let prune = self.target_pruned(byte_index + 1, next_weight, next_pre, assigned);

            if !prune {
                self.recurse(byte_index + 1, next_pre, next_weight, assigned);
            }

            assigned[byte_index] = false;
        }
    }

    fn run(mut self) -> (Vec<FTransition>, FStats) {
        if self.f_max == 0 {
            return (Vec::new(), self.stats);
        }

        let mut assigned = [false; BYTE_COUNT];

        self.recurse(0, 0, 0.0, &mut assigned);

        let mut result = self.heap.into_vec();

        result.sort_by(|a, b| {
            a.weight
                .partial_cmp(&b.weight)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.df.cmp(&b.df))
        });

        self.stats.retained = result.len() as u64;

        if self.limit_truncated {
            self.stats.expansions_truncated += 1;
        }

        (result, self.stats)
    }
}

// ============================================================================
// Differential state
// ============================================================================

#[derive(Clone, Copy)]
struct DifferentialState {
    dl: u64,
    dr: u64,
    weight: f64,
}

impl DifferentialState {
    #[inline]
    fn probability(&self) -> f64 {
        probability_from_weight(self.weight)
    }
}

// ============================================================================
// Round-2 candidate
// ============================================================================

#[derive(Clone, Copy)]
struct Candidate {
    state: DifferentialState,
    predecessor: DifferentialState,
    /// Optimistic total characteristic weight after the final round.
    priority: f64,
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
            && self.state.weight == other.state.weight
            && self.state.dl == other.state.dl
            && self.state.dr == other.state.dr
    }
}

impl Eq for Candidate {}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is a max-heap, so the naturally greatest (worst)
        // optimistic completion score remains at the root.
        self.priority
            .partial_cmp(&other.priority)
            .unwrap_or(Ordering::Equal)
            .then_with(|| {
                self.state
                    .weight
                    .partial_cmp(&other.state.weight)
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| self.state.dr.cmp(&other.state.dr))
            .then_with(|| self.state.dl.cmp(&other.state.dl))
    }
}

// ============================================================================
// Configuration
// ============================================================================

struct Config {
    target_weight: f64,
    beam: usize,
    f_max: usize,
    result_limit: usize,
}

fn parse_args() -> Config {
    let mut args = env::args().skip(1);

    let target_weight = args
        .next()
        .expect("missing target weight")
        .parse::<f64>()
        .expect("invalid target weight");

    assert!(
        target_weight.is_finite() && target_weight >= 0.0,
        "target weight must be finite and non-negative"
    );

    let mut beam = DEFAULT_BEAM;

    let mut f_max = DEFAULT_F_MAX;

    let mut result_limit = DEFAULT_RESULT_LIMIT;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--beam" => {
                beam = args
                    .next()
                    .expect("missing value for --beam")
                    .parse::<usize>()
                    .expect("invalid --beam");
            }

            "--f-max" => {
                f_max = args
                    .next()
                    .expect("missing value for --f-max")
                    .parse::<usize>()
                    .expect("invalid --f-max");
            }

            "--result-limit" => {
                result_limit = args
                    .next()
                    .expect("missing value for --result-limit")
                    .parse::<usize>()
                    .expect("invalid --result-limit");
            }

            other => {
                panic!("unknown argument: {}", other);
            }
        }
    }

    assert!(beam > 0, "--beam must be greater than zero");
    assert!(f_max > 0, "--f-max must be greater than zero");
    assert!(result_limit > 0, "--result-limit must be greater than zero");

    Config {
        target_weight,
        beam,
        f_max,
        result_limit,
    }
}

// ============================================================================
// Round 1
// ============================================================================

fn generate_round1(
    ddt: &Ddt,
    dl0: u64,
    dr0: u64,
    config: &Config,
) -> (Vec<DifferentialState>, FStats) {
    //
    // Round:
    //
    //     ΔL1 = ΔR0
    //     ΔR1 = ΔL0 XOR ΔF1
    //
    let search = FSearch::new(ddt, dr0, dl0, 0.0, config.target_weight, config.f_max, true);

    let (transitions, stats) = search.run();

    let states = transitions
        .into_iter()
        .filter_map(|transition| {
            let weight = transition.weight;

            if weight > config.target_weight + EPS {
                return None;
            }

            Some(DifferentialState {
                dl: dr0,
                dr: dl0 ^ transition.df,
                weight,
            })
        })
        .collect();

    (states, stats)
}

// ============================================================================
// Round-2 lower bound
// ============================================================================

#[inline]
fn round2_candidate_lb(ddt: &Ddt, state: &DifferentialState) -> f64 {
    state.weight + ddt.f_input_lb(state.dr)
}

// ============================================================================
// Round 2
// ============================================================================

struct Round2Result {
    entries: Vec<Candidate>,

    stats: FStats,

    generated: u64,
    target_rejected: u64,
    beam_rejected: u64,
    beam_replacements: u64,

    lower_bound_viable: u64,
    lower_bound_impossible: u64,

    f_truncated: bool,
    beam_truncated: bool,
}

fn generate_round2(ddt: &Ddt, round1: &[DifferentialState], config: &Config) -> Round2Result {
    let mut beam = BinaryHeap::<Candidate>::new();

    let mut total_stats = FStats::default();

    let mut generated = 0u64;
    let mut target_rejected = 0u64;
    let mut beam_rejected = 0u64;
    let mut beam_replacements = 0u64;

    let mut lower_bound_viable = 0u64;
    let mut lower_bound_impossible = 0u64;

    let mut f_truncated = false;
    let mut beam_truncated = false;

    for (index, r1) in round1.iter().enumerate() {
        //
        // Round 2:
        //
        //     ΔL2 = ΔR1
        //     ΔR2 = ΔL1 XOR ΔF2
        //
        let search = FSearch::new(
            ddt,
            r1.dr,
            r1.dl,
            r1.weight,
            config.target_weight,
            config.f_max,
            true,
        );

        let (transitions, stats) = search.run();

        total_stats.add(&stats);

        generated += stats.complete_transitions;

        target_rejected += stats.target_pruned;

        if stats.expansions_truncated != 0 {
            f_truncated = true;
        }

        for transition in transitions {
            let r2 = DifferentialState {
                dl: r1.dr,
                dr: r1.dl ^ transition.df,
                weight: r1.weight + transition.weight,
            };

            if r2.weight > config.target_weight + EPS {
                target_rejected += 1;
                continue;
            }

            //
            // This is the lower bound for the COMPLETE
            // three-round characteristic from this Round-2
            // state.
            //
            let lb = round2_candidate_lb(ddt, &r2);

            if lb > config.target_weight + EPS {
                lower_bound_impossible += 1;
                continue;
            }

            lower_bound_viable += 1;

            let candidate = Candidate {
                state: r2,
                predecessor: *r1,
                priority: lb,
            };

            if beam.len() < config.beam {
                beam.push(candidate);
                continue;
            }

            let worst = beam.peek().copied();

            match worst {
                Some(worst) if candidate.cmp(&worst) == Ordering::Less => {
                    beam.pop();
                    beam.push(candidate);

                    beam_replacements += 1;
                    beam_truncated = true;
                }

                _ => {
                    beam_rejected += 1;
                    beam_truncated = true;
                }
            }
        }

        if (index + 1) % 100 == 0 || index + 1 == round1.len() {
            println!(
                "  expanded {:>6}/{:<6} | heap {:>8} | generated {:>13}",
                index + 1,
                round1.len(),
                beam.len(),
                generated
            );
        }
    }

    let mut entries = beam.into_vec();

    entries.sort_by(|a, b| {
        a.state
            .weight
            .partial_cmp(&b.state.weight)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.state.dr.cmp(&b.state.dr))
            .then_with(|| a.state.dl.cmp(&b.state.dl))
    });

    Round2Result {
        entries,

        stats: total_stats,

        generated,
        target_rejected,
        beam_rejected,
        beam_replacements,

        lower_bound_viable,
        lower_bound_impossible,

        f_truncated,
        beam_truncated,
    }
}

// ============================================================================
// Characteristic
// ============================================================================

#[derive(Clone)]
struct Characteristic {
    states: [DifferentialState; 4],
}

impl PartialEq for Characteristic {
    fn eq(&self, other: &Self) -> bool {
        self.states
            .iter()
            .zip(other.states.iter())
            .all(|(a, b)| a.dl == b.dl && a.dr == b.dr && a.weight == b.weight)
    }
}

impl Eq for Characteristic {}

impl PartialOrd for Characteristic {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Characteristic {
    fn cmp(&self, other: &Self) -> Ordering {
        // The max-heap keeps the worst retained characteristic at its root.
        let mut order = self.states[3]
            .weight
            .partial_cmp(&other.states[3].weight)
            .unwrap_or(Ordering::Equal)
            .then_with(|| self.states[3].dr.cmp(&other.states[3].dr))
            .then_with(|| self.states[3].dl.cmp(&other.states[3].dl));

        for (left, right) in self.states.iter().zip(other.states.iter()) {
            if order != Ordering::Equal {
                return order;
            }

            order = left
                .weight
                .partial_cmp(&right.weight)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.dl.cmp(&right.dl))
                .then_with(|| left.dr.cmp(&right.dr));
        }

        order
    }
}

struct Round3Result {
    characteristics: Vec<Characteristic>,
    stats: FStats,
    pruned: u64,
    generated: u64,
    results_truncated: bool,
}

fn retain_characteristic(
    results: &mut BinaryHeap<Characteristic>,
    characteristic: Characteristic,
    result_limit: usize,
    results_truncated: &mut bool,
) {
    if results.len() < result_limit {
        results.push(characteristic);
        return;
    }

    let worst = results.peek().expect("non-empty result heap");

    if characteristic.cmp(worst) == Ordering::Less {
        results.pop();
        results.push(characteristic);
    }

    *results_truncated = true;
}

// ============================================================================
// Round 3
// ============================================================================

fn run_round3(ddt: &Ddt, round2: &[Candidate], config: &Config) -> Round3Result {
    let mut results = BinaryHeap::new();

    let mut total_stats = FStats::default();

    let mut pruned = 0u64;
    let mut generated = 0u64;
    let mut results_truncated = false;

    for candidate in round2 {
        let r1 = candidate.predecessor;

        let r2 = candidate.state;

        //
        // Before expanding Round 3, establish whether the
        // Round-2 state can possibly satisfy the target.
        //
        let lb = round2_candidate_lb(ddt, &r2);

        if lb > config.target_weight + EPS {
            pruned += 1;
            continue;
        }

        //
        // Round 3:
        //
        //     ΔL3 = ΔR2
        //     ΔR3 = ΔL2 XOR ΔF3
        //
        let search = FSearch::new(
            ddt,
            r2.dr,
            r2.dl,
            r2.weight,
            config.target_weight,
            config.f_max,
            false,
        );

        let (transitions, stats) = search.run();

        total_stats.add(&stats);

        for transition in transitions {
            let r3 = DifferentialState {
                dl: r2.dr,
                dr: r2.dl ^ transition.df,
                weight: r2.weight + transition.weight,
            };

            if r3.weight > config.target_weight + EPS {
                continue;
            }

            let r0 = DifferentialState {
                dl: 0,
                dr: 1,
                weight: 0.0,
            };

            generated += 1;

            retain_characteristic(
                &mut results,
                Characteristic {
                    states: [r0, r1, r2, r3],
                },
                config.result_limit,
                &mut results_truncated,
            );
        }
    }

    let mut characteristics = results.into_vec();
    characteristics.sort();

    Round3Result {
        characteristics,
        stats: total_stats,
        pruned,
        generated,
        results_truncated,
    }
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let config = parse_args();

    println!("============================================================");
    println!("HERRINGFISH ROUND-3 DIFFERENTIAL OPTIMIZER");
    println!("============================================================");

    println!();
    println!("Target-aware branch-and-bound search for");
    println!("individual three-round differential characteristics.");

    println!();

    println!("Start ΔL              : 0x{:016x}", 0u64);

    println!("Start ΔR              : 0x{:016x}", 1u64);

    println!("Target weight         : W <= {:.6}", config.target_weight);

    println!(
        "Target probability    : {:e}",
        probability_from_weight(config.target_weight)
    );

    println!("Round-2 beam width    : {}", config.beam);

    println!("Maximum F transitions : {}", config.f_max);

    println!("Result retention limit : {}", config.result_limit);

    println!();

    println!("Building S-box DDT...");

    let ddt = Ddt::build();

    ddt.print_statistics();

    // ========================================================================
    // Round 1
    // ========================================================================

    println!();
    println!("============================================================");
    println!("ROUND 1");
    println!("============================================================");

    let (round1, r1_stats) = generate_round1(&ddt, 0, 1, &config);

    println!("Round 1 states          : {}", round1.len());

    println!("F transitions generated: {}", r1_stats.complete_transitions);

    println!("F transitions retained  : {}", r1_stats.retained);

    println!("F transitions rejected  : {}", r1_stats.heap_rejected);

    println!("F transitions evicted  : {}", r1_stats.heap_evicted);

    println!("F lower-bound pruned    : {}", r1_stats.lower_bound_pruned);

    println!("F target-pruned         : {}", r1_stats.target_pruned);

    println!(
        "F-transition truncation : {}",
        if r1_stats.expansions_truncated != 0 {
            "YES"
        } else {
            "NO"
        }
    );

    if let Some(best) = round1.first() {
        println!("Best W                  : {:.6}", best.weight);

        println!("Best P                  : {:.6e}", best.probability());

        println!("ΔL                      : 0x{:016x}", best.dl);

        println!("ΔR                      : 0x{:016x}", best.dr);
    }

    // ========================================================================
    // Round 2
    // ========================================================================

    println!();
    println!("============================================================");
    println!("ROUND 2");
    println!("============================================================");

    println!("Generating Round-2 states...");

    let round2 = generate_round2(&ddt, &round1, &config);

    println!();

    println!("States expanded             : {}", round1.len());

    println!("F transitions generated     : {}", round2.generated);

    println!(
        "Candidate states surviving target/LB: {}",
        round2.lower_bound_viable
    );

    println!(
        "Candidates rejected by target/LB    : {}",
        round2.target_rejected
    );

    println!(
        "Candidates rejected by beam         : {}",
        round2.beam_rejected
    );

    println!(
        "Beam replacements            : {}",
        round2.beam_replacements
    );

    println!("States retained              : {}", round2.entries.len());

    println!(
        "F recursive nodes visited    : {}",
        round2.stats.recursive_nodes
    );

    println!(
        "F branches lower-bound pruned: {}",
        round2.stats.lower_bound_pruned
    );

    println!(
        "F complete transitions       : {}",
        round2.stats.complete_transitions
    );

    println!(
        "F transitions heap-rejected  : {}",
        round2.stats.heap_rejected
    );

    println!(
        "F transitions heap-evicted  : {}",
        round2.stats.heap_evicted
    );

    println!(
        "F expansions truncated       : {}",
        round2.stats.expansions_truncated
    );

    println!(
        "Beam actually truncated      : {}",
        if round2.beam_truncated { "YES" } else { "NO" }
    );

    println!(
        "F limit actually saturated   : {}",
        if round2.f_truncated { "YES" } else { "NO" }
    );

    if let Some(best) = round2.entries.first() {
        let worst = round2.entries.last();

        println!("Best W                       : {:.6}", best.state.weight);

        println!(
            "Best P                       : {:.6e}",
            best.state.probability()
        );

        println!(
            "Worst retained W             : {:.6}",
            worst.map(|x| x.state.weight).unwrap_or(best.state.weight)
        );

        println!("ΔL                           : 0x{:016x}", best.state.dl);

        println!("ΔR                           : 0x{:016x}", best.state.dr);
    }

    println!();
    println!("Round-2 lower-bound diagnostics:");

    println!(
        "  Potentially viable         : {}",
        round2.lower_bound_viable
    );

    println!(
        "  Provably impossible        : {}",
        round2.lower_bound_impossible
    );

    if let Some(best) = round2.entries.first() {
        let r3_lb = ddt.f_input_lb(best.state.dr);

        println!("  Minimum Round-2 W          : {:.6}", best.state.weight);

        println!(
            "  Minimum W + Round-3 LB     : {:.6}",
            best.state.weight + r3_lb
        );
    }

    // ========================================================================
    // Round 3
    // ========================================================================

    println!();
    println!("============================================================");
    println!("ROUND 3 TARGETED SEARCH");
    println!("============================================================");

    println!();

    println!("Searching for W <= {:.6}...", config.target_weight);

    let round3 = run_round3(&ddt, &round2.entries, &config);

    println!();
    println!("============================================================");
    println!("ROUND-3 SEARCH COMPLETE");
    println!("============================================================");

    println!("Round-2 states considered       : {}", round2.entries.len());

    println!("Pruned by lower bound           : {}", round3.pruned);

    println!(
        "Round-2 states actually expanded: {}",
        round2.entries.len().saturating_sub(round3.pruned as usize)
    );

    println!(
        "F recursive nodes visited       : {}",
        round3.stats.recursive_nodes
    );

    println!(
        "F branches lower-bound pruned   : {}",
        round3.stats.lower_bound_pruned
    );

    println!(
        "F target-pruned                 : {}",
        round3.stats.target_pruned
    );

    println!(
        "F complete transitions          : {}",
        round3.stats.complete_transitions
    );

    println!(
        "F transitions retained          : {}",
        round3.stats.retained
    );

    println!(
        "F transitions heap-rejected     : {}",
        round3.stats.heap_rejected
    );

    println!(
        "F transitions heap-evicted     : {}",
        round3.stats.heap_evicted
    );

    println!(
        "F expansions truncated          : {}",
        round3.stats.expansions_truncated
    );

    println!("Characteristics generated       : {}", round3.generated);

    println!(
        "Characteristics retained        : {}",
        round3.characteristics.len()
    );

    // ========================================================================
    // Results
    // ========================================================================

    if !round3.characteristics.is_empty() {
        let display_count = round3.characteristics.len().min(25);

        println!();
        println!("Top {} Round-3 characteristics:", display_count);

        println!();

        for (index, characteristic) in round3
            .characteristics
            .iter()
            .take(display_count)
            .enumerate()
        {
            let final_state = characteristic.states[3];

            println!(
                "#{:<3} W = {:>10.6} P = {:.8e}",
                index + 1,
                final_state.weight,
                final_state.probability()
            );

            for (round, state) in characteristic.states.iter().enumerate() {
                println!(
                    "      r {}: ΔL = 0x{:016x}  ΔR = 0x{:016x}",
                    round, state.dl, state.dr
                );
            }

            println!();
        }

        let best = &round3.characteristics[0];

        println!("============================================================");
        println!("BEST OBSERVED CHARACTERISTIC");
        println!("============================================================");

        println!("Weight        : {:.6}", best.states[3].weight);

        println!("Probability   : {:.16e}", best.states[3].probability());

        println!("Target        : {:.6}", config.target_weight);

        println!(
            "Margin        : {:.6}",
            config.target_weight - best.states[3].weight
        );
    } else {
        println!();
        println!("============================================================");
        println!("RESULT: NO CHARACTERISTIC FOUND");
        println!("============================================================");

        println!();

        println!("No retained characteristic satisfies:");

        println!("    W <= {:.6}", config.target_weight);
    }

    // ========================================================================
    // Coverage
    // ========================================================================

    println!();
    println!("============================================================");
    println!("SEARCH COVERAGE");
    println!("============================================================");

    println!("Round-2 beam width       : {}", config.beam);

    println!("F transition limit       : {}", config.f_max);

    println!("Result retention limit   : {}", config.result_limit);

    println!(
        "Beam truncated           : {}",
        if round2.beam_truncated { "YES" } else { "NO" }
    );

    println!(
        "Round-2 F limit reached  : {}",
        if round2.f_truncated { "YES" } else { "NO" }
    );

    println!(
        "Round-3 F limit reached  : {}",
        if round3.stats.expansions_truncated != 0 {
            "YES"
        } else {
            "NO"
        }
    );

    println!(
        "Result limit reached     : {}",
        if round3.results_truncated {
            "YES"
        } else {
            "NO"
        }
    );

    println!();

    println!("SAFE PRUNING");

    println!("  Target lower bounds are safe.");

    println!("  Per-byte DDT minimums are safe.");

    println!("  Partial diffusion bounds only use fully known bytes.");

    println!("  Round-3 bounds account for ΔL XOR ΔF cancellation.");

    println!();

    println!("IMPORTANT");

    println!("This searches individual differential characteristics.");

    println!("It does NOT compute differential-hull probabilities.");

    println!();

    if round2.beam_truncated || round2.f_truncated || round3.stats.expansions_truncated != 0 {
        println!("RESULT STATUS: BOUNDED SEARCH");

        println!();

        println!("At least one configured search or retention limit restricted");

        println!("the candidate space.");

        println!();

        println!("The best characteristic found is therefore");

        println!("the best characteristic within the searched");

        println!("bounded candidate space.");

        println!();

        println!("A global optimum requires exhaustive coverage.");
    } else {
        println!("RESULT STATUS: EXHAUSTIVE WITHIN GENERATED STATE SPACE");

        println!();

        println!("No configured beam or F-transition limit");

        println!("truncated the search.");

        println!();

        println!("The target-bound recursion was therefore");

        println!("exhaustive over the generated differential");

        println!("state space.");

        if round3.results_truncated {
            println!();

            println!("The result list was truncated, but the retained top results");

            println!("still include the globally best characteristic from that search.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(target_weight: f64) -> Config {
        Config {
            target_weight,
            beam: 1_000,
            f_max: 256,
            result_limit: 100,
        }
    }

    #[test]
    fn final_round_does_not_charge_for_a_fourth_round() {
        let ddt = Ddt::build();
        let r2 = DifferentialState {
            dl: 0x0d00_0d00_0000_000d,
            dr: 0x0001_0000_0001_0000,
            weight: 25.0,
        };
        let candidate = Candidate {
            state: r2,
            predecessor: DifferentialState {
                dl: 0,
                dr: 1,
                weight: 0.0,
            },
            priority: 37.0,
        };

        let result = run_round3(&ddt, &[candidate], &config(37.0));

        assert!(
            !result.characteristics.is_empty(),
            "a final-round transition at the target weight must be retained"
        );
        assert!(result.characteristics[0].states[3].weight <= 37.0 + EPS);
    }

    #[test]
    fn partial_future_bound_waits_for_all_diffusion_dependencies() {
        let ddt = Ddt::build();
        let search = FSearch::new(&ddt, 0, 0, 0.0, INF, 1, true);
        let mut assigned = [false; BYTE_COUNT];
        let mut pre_diff = set_byte(0, 0, 1);

        assigned[0] = true;

        assert_eq!(search.partial_future_f_lb(pre_diff, &assigned), 0.0);

        pre_diff = set_byte(pre_diff, 1, 2);
        pre_diff = set_byte(pre_diff, 3, 4);
        assigned[1] = true;
        assigned[3] = true;

        assert_eq!(
            search.partial_future_f_lb(pre_diff, &assigned),
            ddt.global_min_weight
        );
    }

    #[test]
    fn exact_f_transition_capacity_is_not_reported_as_truncated() {
        let ddt = Ddt::build();
        let search = FSearch::new(&ddt, 0, 0, 0.0, 0.0, 1, false);

        let (transitions, stats) = search.run();

        assert_eq!(transitions.len(), 1);
        assert_eq!(stats.expansions_truncated, 0);
    }
}
