# Side-Channel Analysis and Implementation Hardening – Herringfish

**Version:** v0.2.6  
**Specification:** `docs/specification/feistel_arx_v0.2.md` §20.5, §26/27  
**Date:** 2026-08-19

## Project Status
Herringfish Feistel ARX v0.2 is an experimental research block cipher. Side-channel resistance is an implementation property, not guaranteed by the mathematical design. Current status: reference implementation is not constant-time; constant-time research variant exists.

## Architecture Overview
* Construction: 128-bit balanced Feistel, 256-bit master key, 16 rounds
* Round function: XOR → 8-bit S-box → linear diffusion `out[i]=in[i]⊕in[i+1]⊕in[i+3]`
* S-box: frozen `HERRINGFISH_SBOX_V02`, `a=0x11`, `b=0x71`
* Key schedule: SHAKE256 XOF with domain `HERRINGFISH-FEISTEL-KEY`
* Normative serialization: little-endian 64-bit halves

## Implementation Components
* Reference cipher: `src/cipher/feistel_arx.rs`
  * `encrypt_block`, `decrypt_block` using direct S-box table lookup
  * `read_u64` / `write_u64` use `u64::from_le_bytes` / `to_le_bytes`
* Constant-time variant: `src/cipher/sbox_ct.rs`
  * `sbox_ct_lookup` uses `subtle::ConstantTimeEq` selection over 256 entries
  * `encrypt_block_ct`, `decrypt_block_ct`, `f_function_ct`
* Key schedule: `src/cipher/shake_key_schedule.rs`, `src/cipher/key_schedule.rs`
* SIMD: `src/simd/avx2.rs` AVX2 diffusion benchmark

## Side-Channel Findings

### S-box Table Lookup
* Reference implementation indexes S-box with secret-dependent byte `x_i ⊕ k_i`
* Creates secret-dependent memory access → cache-timing vulnerability
* Test: `cipher::feistel_arx::tests::sbox_constant_time_matches_reference` verifies functional equivalence
* Benchmark `examples/bench_sbox_ct.rs`:
  * Table lookup ~10.9 M ops/s
  * Constant-time ~6.6 k ops/s
  * Overhead ~1 647×

### Constant-Time Variant
* Selection-over-all implementation eliminates secret-dependent memory access
* Uses `subtle` crate for constant-time equality
* Correctness tests:
  * `sbox_ct::tests::test_sbox_ct_correctness`
  * `sbox_ct::tests::test_sbox_apply_ct_correctness`
  * `feistel_arx::tests::normal_and_constant_time_match`
  * `feistel_arx::tests::normal_and_constant_time_decryption_match`
* Not optimized for production; provided for research evaluation

### Key Schedule
* SHAKE256 XOF via RustCrypto `shake` crate
* No secret-dependent branches in derivation
* Domain separation prevents cross-channel leakage between purposes
* Test: `tests/shake_schedule.rs` – deterministic derivation, key differentiation
* 100k sample key schedule independence test: average round-key Hamming distance ~64 bits for 1-bit master key difference

### SIMD / AVX2
* AVX2 diffusion benchmark exists, ~2.7× speedup
* Gather-based S-box access remains secret-dependent
* Requires bitsliced S-box or constant-time gather for resistance

### Review Documentation
* `docs/side_channel_review_v0.2.md` – detailed findings summary
* `docs/side_channel_review.md` – general review
* `docs/side_channel_shake_review.md` – SHAKE review

## Test Coverage
* Unit tests: 25 tests in `src/cipher/feistel_arx.rs` including constant-time equivalence
* Integration tests: `tests/roundtrip.rs`, `tests/shake_schedule.rs`
* Known-answer tests: `docs/tables/kat_vectors_v02.txt`
* Statistical tests: `examples/statistical_full_cipher_large.rs` 1M samples
* Performance tests: `examples/bench_sbox_ct.rs`, `examples/simd_benchmark.rs`
* Cryptanalysis tests: differential/linear hull tools, reduced-round analysis

## Recommendations
* Keep reference and CT variants clearly separated and documented
* Document that production use requires additional hardening
* Consider bitsliced S-box implementation for future versions
* Validate side-channel resistance via implementation review and testing, not assumption
* Do not use Herringfish to protect real-world secrets

## Reproducibility
Experiments should record: Herringfish version/tag, specification version, experiment parameters, number of samples, random seed, compiler version, OS, CPU architecture, CPU features, Cargo features, hardware configuration, execution time.

**Design it. Implement it. Test it. Break it. Improve it.**
