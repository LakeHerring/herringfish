# Hash Usage and Key Expansion – Herringfish

**Version:** v0.2.6 (solo-arx branch)  
**Specification:** `docs/specification/feistel_arx_v0.2.md` §2, §12, §26/27  
**Date:** 2026-08-19 (updated for solo-arx branch)

## Project Context
Herringfish Feistel ARX v0.2 is an experimental symmetric-key block cipher research prototype. On the solo-arx branch **no hash function, XOF, or other external cryptographic primitive is used at all**. Round-key derivation is a self-contained ARX expansion built from rotations, XORs, 64-bit modular additions, and frozen constants. No proof-of-work, mining, or hash difficulty mechanism is part of the construction.

## Architecture Overview
* Block cipher: 128-bit balanced Feistel, 256-bit master key, 16 rounds
* Round function: XOR → 8-bit S-box → linear byte diffusion `out[i]=in[i]⊕in[i+1]⊕in[i+3]`
* S-box: frozen `HERRINGFISH_SBOX_V02`, affine parameters `a=0x11`, `b=0x71`, counter 0
* Key schedule: self-contained ARX expansion (rot/XOR/mod-add + 16 frozen constants)
* Normative serialization: little-endian 64-bit halves

## Key Expansion in v0.2.6 (solo-arx branch)
* 4×64-bit register seeded from the 256-bit master key
* Per round key: 2× `full_mix` (rotated neighbor XORs + modular additions + frozen constants) + 1× bijective rotr-XOR network
* Round key = XOR of all four register words
* Implementation: `src/cipher/arx_key_schedule.rs` (Feistel ARX), `src/cipher/key_schedule.rs` (SPN variant, same expansion)
* Design rationale and literature comparison: `docs/solo_arx_key_schedule.md`
* No `shake`, `sha3`, or any other external primitive is linked (see `Cargo.toml`)

Note: the frozen v0.2 specification documents the canonical SHAKE256-based variant
(`SHAKE256(HERRINGFISH-FEISTEL-KEY || master_key)` → 1024 bits). The solo-arx
branch differs only in the key schedule.

## Hash Difficulty
* No hash difficulty parameter defined
* No proof-of-work, mining, or target threshold
* No hash or XOF primitive is used for key expansion on this branch
* Key schedule output is deterministic, streaming (prefix property), and branch-free

## Testing Related to Key Expansion
* `tests/arx_schedule.rs`: deterministic derivation, key differentiation, prefix property, no-zero round-key stream, size invariants
* `src/cipher/arx_key_schedule::tests`: 11 unit tests including full key sensitivity and key avalanche (all 256 single-bit key flips within [26, 38] bits per round key)
* Key schedule independence test: 100k samples, average round-key Hamming distance ~32 of 64 bits (Feistel) / ~64 of 128 bits (SPN) for 1-bit master key difference
* Related-key analysis examples: `examples/related_key_analysis.rs`, `examples/related_key_hamming.rs`

## Why No Hash Difficulty
* Herringfish is a symmetric encryption primitive, not a consensus or mining scheme
* Adding difficulty would change security model and performance characteristics
* The key schedule derives structured key material by design, not to enforce computational work

## Research Considerations
If hash-based hardness is explored in future Herringfish variants:
* Explicitly specify iteration count, target, verification procedure
* Domain separation from key schedule
* Evaluate side-channel and performance implications
* Document reproducibility metadata: Herringfish version/tag, spec version, experiment parameters, samples, random seed, compiler, OS, CPU, features, Cargo features, hardware, execution time

## Current Status
* Hash/XOF primitives: None (solo-arx branch)
* Key expansion: self-contained ARX, implemented, tested
* Compliance: Research only

**Design it. Implement it. Test it. Break it. Improve it.**
