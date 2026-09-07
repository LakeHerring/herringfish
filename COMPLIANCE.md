# Herringfish Compliance and Standards Assessment

**Version:** v0.2.6  
**Git tag:** v0.2.6  
**Specification:** `docs/specification/feistel_arx_v0.2.md` §26/27 Normative Serialization  
**Date:** 2026-08-19

## Project Overview
Herringfish is an experimental symmetric-key cryptography research project focused on the design, implementation, testing and cryptanalysis of a novel block-cipher construction. Current construction is **Feistel ARX v0.2**: 128-bit balanced Feistel network, 256-bit master key, 16 rounds, 8-bit nonlinear S-box layer, XOR-based byte diffusion, SHAKE256-derived key schedule with domain separation.

**Status:** Experimental / Research – not production ready.

## Standards Mapping
* **Cryptographic primitives used**
  * SHAKE256 XOF – NIST FIPS 202 standardized
  * SHA3-256/512 – NIST FIPS 202 standardized, used only where fixed-length digests required
  * RustCrypto `shake` crate for XOF, `sha3` crate for fixed digests
* **Construction**
  * Feistel ARX v0.2 is a research prototype, not a NIST-approved or ISO standard algorithm
  * No FIPS validation, no Common Criteria certification, no ISO/IEC 18033 compliance
  * Not listed in NIST Cryptographic Algorithm Validation Program

## Architecture and Implementation
* Reference implementation: `src/cipher/feistel_arx.rs`
* Key schedule: `src/cipher/key_schedule.rs`, `src/cipher/shake_key_schedule.rs`
* Round function: `src/cipher/round.rs`
* Constant-time S-box: `src/cipher/sbox_ct.rs`
* SIMD exploration: `src/simd/avx2.rs`
* Specification: `docs/specification/feistel_arx_v0.2.md`
* Known-answer test vectors: `docs/tables/kat_vectors_v02.txt`, `kat_expanded_v02.txt`

Normative serialization finalized v0.2.6:
* Block = 16 bytes, two 64-bit little-endian halves
* Master key = 32-byte raw array
* Round keys = 64-bit little-endian from SHAKE256 XOF
* Byte ordering for S-box layer = little-endian per word

## Testing and Validation – v0.2.6 Results

**Test run:** `cargo test --all` 2026-08-19  
**Compiler:** rustc 1.97.1 2026-07-14  
**OS:** Windows_NT 10.0.26200 / MSYS2  
**CPU:** x86_64 AMD Ryzen 9 7950X

### Unit tests `src/lib.rs` – 25 passed
* `cipher::feistel_arx::tests::diffusion_zero` – ok
* `cipher::feistel_arx::tests::round_key_stream_prefix_property` – ok
* `cipher::feistel_arx::tests::diffusion_is_deterministic` – ok
* `cipher::feistel_arx::tests::round_key_derivation_changes_with_key` – ok
* `cipher::feistel_arx::tests::diffusion_is_invertible_as_byte_linear_map` – ok
* `cipher::feistel_arx::tests::round_key_derivation_is_deterministic` – ok
* `cipher::feistel_arx::tests::roundtrip` – ok
* `cipher::feistel_arx::tests::sbox_is_permutation` – ok
* `cipher::feistel_arx::tests::zero_input_difference_produces_zero_output_difference` – ok
* `simd::avx2::tests::test_diffusion_avx2_stability` – ok
* `cipher::feistel_arx::tests::nonzero_sbox_input_difference_cannot_produce_zero_for_permutation` – ok
* `cipher::feistel_arx::tests::sbox_ddt_row_is_key_independent` – ok
* `cipher::feistel_arx::tests::roundtrip_constant_time` – ok
* `cipher::sbox_ct::tests::test_sbox_ct_correctness` – ok
* `cipher::feistel_arx::tests::sbox_constant_time_matches_reference` – ok
* `cipher::feistel_arx::tests::differential_feistel_relation_is_correct` – ok
* `cipher::feistel_arx::tests::round_function_matches_definition` – ok
* `cipher::feistel_arx::tests::differential_key_cancellation_is_real` – ok
* `cipher::feistel_arx::tests::related_key_analysis` – ok, Average Hamming distance per round key: 32.0445
* `cipher::feistel_arx::tests::actual_round_matches_differential_model` – ok
* `cipher::sbox_ct::tests::test_sbox_apply_ct_correctness` – ok
* `cipher::feistel_arx::tests::random_roundtrip_many_round_counts` – ok
* `cipher::feistel_arx::tests::f_function_constant_time_matches_reference` – ok
* `cipher::feistel_arx::tests::normal_and_constant_time_match` – ok
* `cipher::feistel_arx::tests::normal_and_constant_time_decryption_match` – ok

### Integration tests
* `tests/roundtrip.rs` – 2 passed: `roundtrip_all_zero`, `roundtrip_random`
* `tests/shake_schedule.rs` – 2 passed: `shake_key_schedule_deterministic`, `shake_key_schedule_differs`

**Total:** 29 tests passed, 0 failed

### Additional validation
* Known-answer tests: KAT vectors for frozen S-box v0.2 with `a=0x11`, `b=0x71`, counter 0 – verified
* S-box validation: DDT_max = 4, LAT_max bias = 32, bijectivity verified
* Statistical analysis: `examples/statistical_full_cipher_large.rs` – 1M samples, avg Hamming distance 64.00 bits, bit flip probability 0.5000, SAC mean absolute deviation 0.0004
* Reduced-round analysis: differential sampling 100k pairs per input difference for 4/6/8/12 rounds, observed probabilities at sampling floor 1e-5
* Key schedule independence: 100k samples, average round-key Hamming distance ~64 bits for 1-bit master key difference
* Constant-time verification: `bench_sbox_ct.rs` – table lookup ~10.9 M ops/s vs CT ~6.6 k ops/s
* SIMD benchmark: AVX2 diffusion ~2.7× speedup vs scalar, example gated for x86_64

## Compliance Limitations
* No formal security proof
* No independent cryptanalysis
* No side-channel resistance in reference implementation
* No AEAD construction
* No formal security model
* No production hardening

## Intended Use
* Research, experimentation, education, benchmarking, cryptanalysis
* Must not be used to protect real-world secrets, production systems, passwords, financial data

## Future Compliance Path
To achieve production compliance, Herringfish would require:
* Independent cryptanalysis and public review
* Formal security model and proofs
* Constant-time, side-channel resistant implementation
* AEAD construction with misuse resistance
* Standards body submission and certification

**Design it. Implement it. Test it. Break it. Improve it.**
