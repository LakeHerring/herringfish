# Hash Difficulty and XOF Usage – Herringfish

**Version:** v0.2.6  
**Specification:** `docs/specification/feistel_arx_v0.2.md` §2, §12, §26/27  
**Date:** 2026-08-19

## Project Context
Herringfish Feistel ARX v0.2 is an experimental symmetric-key block cipher research prototype. It uses SHAKE256 as an extendable-output function for key schedule derivation only. No proof-of-work, mining, or hash difficulty mechanism is part of the construction.

## Architecture Overview
* Block cipher: 128-bit balanced Feistel, 256-bit master key, 16 rounds
* Round function: XOR → 8-bit S-box → linear byte diffusion `out[i]=in[i]⊕in[i+1]⊕in[i+3]`
* S-box: frozen `HERRINGFISH_SBOX_V02`, affine parameters `a=0x11`, `b=0x71`, counter 0
* Key schedule: SHAKE256 XOF with domain separation `HERRINGFISH-FEISTEL-KEY`
* Normative serialization: little-endian 64-bit halves

## SHAKE256 Usage in v0.2.6
* Domain-separated derivation: `SHAKE256(domain || input)`
* Round-key derivation: `SHAKE256(HERRINGFISH-FEISTEL-KEY || master_key)` → 1024 bits → 16 × 64-bit round keys
* S-box derivation domain `HERRINGFISH-FEISTEL-SBOX` is reserved for future versions; v0.2 S-box is frozen constant
* Implementation: `src/cipher/shake_key_schedule.rs`, `src/cipher/key_schedule.rs`
* RustCrypto `shake` crate used, no custom iteration or difficulty adjustment

## Hash Difficulty
* No hash difficulty parameter defined
* No proof-of-work, mining, or target threshold
* SHAKE256 is used for pseudorandom expansion, not computational hardness tuning
* Key schedule output is deterministic and constant-time in XOF processing

## Testing Related to XOF
* `tests/shake_schedule.rs`: deterministic derivation, key differentiation
* `src/cipher/feistel_arx::tests::round_key_derivation_is_deterministic` – 25 unit tests pass
* Key schedule independence test: 100k samples, average round-key Hamming distance ~64 bits for 1-bit master key difference
* Related-key analysis example: `examples/related_key_analysis.rs`, `examples/related_key_hamming.rs`

## Why No Hash Difficulty
* Herringfish is a symmetric encryption primitive, not a consensus or mining scheme
* Adding difficulty would change security model and performance characteristics
* XOF is used to derive structured key material, not to enforce computational work

## Research Considerations
If hash-based hardness is explored in future Herringfish variants:
* Explicitly specify iteration count, target, verification procedure
* Domain separation from key schedule
* Evaluate side-channel and performance implications
* Document reproducibility metadata: Herringfish version/tag, spec version, experiment parameters, samples, random seed, compiler, OS, CPU, features, Cargo features, hardware, execution time

## Current Status
* Hash difficulty: Not applicable
* SHAKE256 XOF usage: Implemented, tested, normative
* Compliance: Research only

**Design it. Implement it. Test it. Break it. Improve it.**
