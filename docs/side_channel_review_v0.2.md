# Herringfish v0.2 Side-Channel Review – Summary

> **Scope note (solo-arx branch):** this review covers the SHAKE256-based key
> schedule variant documented in the frozen v0.2 specification. On the
> solo-arx branch the key schedule is a self-contained ARX expansion
> (`src/cipher/arx_key_schedule.rs`) with no external primitives; the S-box
> and diffusion findings below are unchanged.

**Date:** 2026-08-15
**Scope:** Reference implementation in `src/cipher/feistel_arx.rs`, constant-time variant `src/cipher/sbox_ct.rs`, key schedule via SHAKE256 (canonical v0.2 spec; replaced by the ARX expansion on the solo-arx branch).

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

### F-function and intermediate-state leakage
* The round function `F(R, k) = D(S(R ⊕ k))` is a bijection in the round key: the key enters exactly once (per-byte XOR), `S` is a public permutation, and `D` is a public invertible linear map.
* Consequence: any channel that exposes round-1's F output or the post-round-1 half-state (verbose logging, debug flags, fault injection, an oracle that prints internal state) yields the first round key in a single chosen plaintext, exactly, via `k = R ⊕ S⁻¹(D⁻¹(F_leaked))`. Symmetrically, a leak of the pre-final-round state yields the last round key. This is a generic Feistel result — any round function that is a bijection in the round key hands that round's key to any F-output channel — and it holds for this F without search or carry ambiguity.
* The reference implementation (and the constant-time variant) emit only the final ciphertext; no intermediate state is printed, logged, or otherwise exposed (verified by source review). The threat is therefore conditional on a deployment introducing such a channel, not on the cipher math.
* Recovering a single round key (e.g. `rk1`) from a full 16-round instance does not trivially yield the 256-bit master key: the ARX key schedule is a forward-only stream, and schedule inversion is a separate open question.
* Motivating example: the `leakyFeistel` CTF exploit (NoamAdept/leakyFeistel) breaks a 4-round Feistel whose debug output leaks post-round-1 state and which reuses one key for all rounds; the same single-query key-inversion algebra applies to this F-function, but Herringfish's per-round distinct keys and absence of any debug channel neutralize the attack as implemented.

### Assumptions and limits
* Constant-time properties are not assumed for the reference implementation.
* The CT variant is provided for research evaluation only and is not optimized for production.
* Side-channel resistance must be validated via implementation review and testing, not assumed.

## Recommendations
* Keep reference and CT variants clearly separated.
* Document that production use requires additional hardening.
* Consider bitsliced S-box implementation for future versions.
* Never emit intermediate Feistel states (half-states or F outputs) in any build, debug mode, or logging path: because F is a bijection in the round key, such a channel recovers the corresponding round key in one chosen plaintext.
