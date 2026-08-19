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

## Testing and Validation
* Unit tests: 25 tests in `src/cipher/feistel_arx.rs` – roundtrip, diffusion determinism/invertibility, S-box permutation, constant-time equivalence, differential relations, related-key analysis
* Integration tests: `tests/roundtrip.rs` – all-zero and random roundtrip
* Key schedule tests: `tests/shake_schedule.rs` – deterministic derivation, key differentiation
* Known-answer tests: KAT vectors for frozen S-box v0.2 with `a=0x11`, `b=0x71`, counter 0
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
