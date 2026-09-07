# Herringfish Concrete Security Margin Quantification – Summary

**Date:** 2026-08-15
**Construction:** Feistel ARX v0.2.3
**Parameters:** 128-bit block, 256-bit master key, 16 rounds (parameterisable 4/6/8/16)
**F-function:** `S[x⊕k]` with 8-bit S-box + intra-round diffusion `out[i]=in[i]⊕in[i+1]⊕in[i+3]`
**Key schedule:** SHAKE256 XOF with domain `HERRINGFISH-FEISTEL-KEY`
**S-box:** AES reference for baseline experiments

## Differential sampling

Methodology per `docs/specification/methodology_v0.1.md`:
For fixed Δ_in, sample N random plaintexts P_i, compute Δ_out,i = E_K(P_i) ⊕ E_K(P_i⊕Δ_in).
Empirical probability p̂(Δ_in→Δ_out) = count/N.
Reported p̂_max = max_{Δ_out} p̂.

Samples per input difference: 100 000
Input differences tested: 1-bit Hamming weight, 8 positions.

Results:

```
Rounds 4: max prob ≈ 0.000010 95% CI [0.000000, 0.000030]
Rounds 6: max prob ≈ 0.000010 95% CI [0.000000, 0.000030]
Rounds 8: max prob ≈ 0.000010 95% CI [0.000000, 0.000030]
```

All observed maxima sit at the sampling floor 1/N = 1e-5. No high-probability differential concentration detected under the tested model.

Interpretation: experimental observation consistent with uniform output difference distribution for the tested reduced-round range. No statistical evidence of a differential characteristic with probability ≫1e-5 within 4-8 rounds under the 100k-pair sampling methodology.

## Linear sampling

Maximum observed absolute bias for randomly sampled masks, N = 100 000.
Preliminary runs show bias decreasing with rounds, staying within sampling noise ~1.6e-3 for 8 rounds. Full mask enumeration not yet performed.

## S-box formalisation

Baseline AES S-box used for current experiments:

* Bijective: yes
* DDT max count = 4 → differential uniformity 4 → max probability 1/64 ≈ 0.015625
* LAT max bias count = 32 → max correlation 0.125

Acceptance criteria for SHAKE-derived S-box per spec:
* Bijective permutation of 0..255
* DDT_max ≤ 4
* |LAT_bias| ≤ 32
* Strict Avalanche and Bit Independence evaluated statistically

S-box generation method:

For v0.2 the S-box is frozen as an affine equivalent of the AES S-box.

```
S[x] = a * AES_SBOX[x] ⊕ b  over GF(2^8)
```

Affine parameters: `a = 0x11`, `b = 0x71`. Counter = 0.

This construction guarantees bijectivity and inherits AES S-box differential/linear properties: DDT_max = 4, LAT_max bias = 32.

Implementation in `src/cipher/feistel_arx.rs` as `HERRINGFISH_SBOX_V02`. Derivation code remains in `examples/sbox_formalise.rs` for research.

## Key schedule documentation

RustCrypto crate mapping:
* `shake` crate → SHAKE256 for key expansion and S-box generation
* `sha3` crate → fixed-length SHA-3 digests only

Domain separation:
* Round-key derivation: `HERRINGFISH-FEISTEL-KEY`
* S-box derivation: `HERRINGFISH-FEISTEL-SBOX`
* SPN key schedule: `HERRINGFISH-SPN-KEY`

Round keys derived as:
```
SHAKE256(domain || master_key) → 1024 bits → K1..K16, each 64 bits
```

Related-key Hamming distance tests on SHAKE schedule show ~64 bits average Hamming distance for 1-bit master key differences, consistent with pseudorandom behaviour. No exploitable correlation observed in sampled tests.

## Security margin statement

* Final construction: 16 rounds
* Currently tested reduced-round range: 4,6,8 rounds
* Empirical margin: ≥8 rounds beyond tested range
* This is an experimental margin relative to the tested attack model, not a formal security bound.

No weakness identified under the tested differential/linear sampling methodology for 4-8 rounds.

## Updated Results 2026-08-14

### Frozen S-box v0.2
* Domain: `HERRINGFISH-FEISTEL-SBOX`
* Counter: 0
* Affine parameters: `a = 0x11`, `b = 0x71`
* DDT_max = 4, LAT_max bias = 32
* Full permutation in `src/cipher/feistel_arx.rs` as `HERRINGFISH_SBOX_V02`
* Matrices: `docs/tables/ddt_matrix.txt`, `docs/tables/lat_matrix.txt`

### Extended differential sampling
Samples per Δ_in = 100 000

| Rounds | HW | max p̂ | 95% CI |
| -----: | --:| ----: | -----: |
| 4 | 1 | 0.000010 | [0.000000,0.000030] |
| 4 | 2 | 0.000010 | [0.000000,0.000030] |
| 4 | 4 | 0.000010 | [0.000000,0.000030] |
| 6 | 1 | 0.000010 | [0.000000,0.000030] |
| 6 | 2 | 0.000010 | [0.000000,0.000030] |
| 6 | 4 | 0.000010 | [0.000000,0.000030] |
| 8 | 1 | 0.000010 | [0.000000,0.000030] |
| 8 | 2 | 0.000010 | [0.000000,0.000030] |
| 8 | 4 | 0.000010 | [0.000000,0.000030] |
| 12 | 1 | 0.000010 | [0.000000,0.000030] |
| 12 | 2 | 0.000010 | [0.000000,0.000030] |
| 12 | 4 | 0.000010 | [0.000000,0.000030] |

All maxima at sampling floor 1/N. No high-probability concentration detected.

### Linear sampling
Samples = 20 000, trials = 20
* Rounds 4: max observed bias ≈ 0.01085
* Rounds 6: max observed bias ≈ 0.00975
* Rounds 8: max observed bias ≈ 0.00740
Bias decreasing with rounds, within sampling noise.

### Key schedule independence
* Average pairwise round-key Hamming distance ≈ 32.00 bits
* Related-key 1-bit diff: mean round-key Hamming = 32.04 bits, std = 0.97
Consistent with independent 64-bit keys.

## Implementation hardening and side-channel review

* Constant-time S-box module `src/cipher/sbox_ct.rs` implemented using `subtle::ConstantTimeEq` selection over 256 entries.
* `FeistelArx::encrypt_block_ct` / `decrypt_block_ct` added, using `f_function_ct` with constant-time S-box lookup.
* Correctness verified: CT output matches table-lookup output for all tested inputs.
* Benchmark `examples/bench_sbox_ct.rs` on release build:
  * Table lookup: ~10.9 M ops/s
  * Constant-time: ~6.6 k ops/s
  * Overhead factor ≈ 1 647×
* Overhead is expected for pedagogical selection-over-all implementation. Production use would require bitsliced or hardware-accelerated S-box.
* S-box table lookup remains secret-dependent and thus not constant-time in the reference implementation. The CT variant is provided for research and side-channel evaluation.

## Full-cipher statistical analysis v0.2.3

Example `examples/statistical_full_cipher.rs` with 100,000 samples:

* Average Hamming distance: 63.99 bits (ideal 64)
* Average bit flip probability: 0.4999 (ideal 0.5)
* SAC mean absolute deviation: 0.0011

Large-sample run `examples/statistical_full_cipher_large.rs` with 1,000,000 samples:

* Average Hamming distance: 64.00 bits (ideal 64)
* Average bit flip probability: 0.5000 (ideal 0.5)
* SAC mean absolute deviation: 0.0004

Observations are consistent with expected avalanche behavior under the tested sampling methodology. No statistical anomaly detected within the tested sample size.

Observation: Tool Complexity Boundary

Effective Search Depth: The hull_meet_in_middle tool is currently limited to finding hulls with probabilities
≥2sq-25.
Pruning Sensitivity: A threshold of −20.0 - -24.0 is too aggressive for the Herringfish v0.2 branching factor, causing total path loss (Probability Conservation Failure).
Complexity Wall: The state-space explosion occurs rapidly beyond cumulative probability, indicating that the S-box/Diffusion interaction provides high diffusion, making "narrow" differential trails difficult to track without massive memory resources.

Attempted large-scale state-space enumeration with --max-states 250M. The tool hit the safety limit in Round 2 due to exponential branching from
ΔR = ΔR=1. This confirms high diffusion properties but renders naive MITM expansion computationally infeasible for this construction. Future efforts will focus on targeted differential sampling and automated characteristic searching.

## Next steps
* Trail search and hull analysis for 6-8 rounds with increased budget and weight-3 output differences
* True 32-lane AVX2 S-box gather with full index widening completed; systematic Criterion benchmarks pending
* Formal side-channel review documented in `docs/side_channel_review_v0.2.md`
* Full-cipher statistical analysis confirmed with 1M samples; 5-10M sample runs planned for tighter confidence intervals
* KAT vectors for frozen S-box published

## Analysis mode semantics – best characteristic vs differential hull

The current meet-in-the-middle tooling implements a *best-characteristic* search:

```
P_state ← max_{C reaching state} P(C)
```

A differential hull requires summation over all characteristics:

```
P(ΔX→ΔY) = Σ_{C : ΔX→ΔY} P(C)
```

These are distinct quantities. Best characteristic is cheap and useful for finding strong trails. Differential hull is mathematically correct for hull analysis and is significantly more expensive.

Herringfish cryptanalysis tooling will expose three explicit modes:

* **best** – max P(C). Fastest. Used for trail discovery.
* **truncated/beam** – beam search with bounded width. Trade-off between coverage and cost.
* **hull** – Σ P(C). Correct hull value. Requires summing probabilities per intermediate state, not taking max.

The existing `examples/hull_meet_in_middle.rs` currently implements best-characteristic mode. Hull mode will be added with summed probabilities per state, precomputed top-K DDT tables, precomputed diffusion tables, and beam search.

This distinction is documented to avoid conflating best-characteristic results with differential hull claims.
