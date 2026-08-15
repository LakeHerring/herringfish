# Herringfish v0.2 Side-Channel Review – Summary

**Date:** 2026-08-15
**Scope:** Reference implementation in `src/cipher/feistel_arx.rs`, constant-time variant `src/cipher/sbox_ct.rs`, key schedule via SHAKE256.

## Findings

### Table lookup S-box
* Reference implementation uses direct table lookup indexed by secret-dependent data.
* This creates secret-dependent memory access patterns and is vulnerable to cache-timing attacks.
* `src/cipher/sbox_ct.rs` provides a constant-time selection-over-all implementation using `subtle::ConstantTimeEq`.
* Benchmark: table lookup ~10.9 M ops/s vs constant-time ~6.6 k ops/s, overhead ~1 647×.

### Key schedule
* SHAKE256 XOF is used for round-key derivation with domain separation.
* No secret-dependent branches in the reference key schedule.
* SHAKE256 itself is implemented via RustCrypto `shake` crate, which is constant-time in software.

### AVX2 SIMD path
* AVX2 diffusion and S-box gather use data-independent memory access patterns for the gather table.
* Gather indices are derived from plaintext, so table access is secret-dependent. Mitigation requires bitsliced S-box or pre-computed tables with constant-time access.

### Assumptions and limits
* Constant-time properties are not assumed for the reference implementation.
* The CT variant is provided for research evaluation only and is not optimized for production.
* Side-channel resistance must be validated via implementation review and testing, not assumed.

## Recommendations
* Keep reference and CT variants clearly separated.
* Document that production use requires additional hardening.
* Consider bitsliced S-box implementation for future versions.
