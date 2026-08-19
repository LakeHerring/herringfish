# Hash Difficulty – Herringfish

## Context
Herringfish Feistel ARX v0.2 uses SHAKE256 as an extendable-output function for key schedule and S-box derivation. It does not use a proof-of-work or hash difficulty mechanism.

## SHAKE256 Usage
* Domain-separated derivation: `SHAKE256(domain || input)`
* Round-key derivation: `HERRINGFISH-FEISTEL-KEY || master_key`
* S-box derivation: `HERRINGFISH-FEISTEL-SBOX || counter`
* Output is consumed as raw XOF bytes with no difficulty adjustment, no iteration count, and no target threshold.

## Hash Difficulty
* No hash difficulty parameter is defined for Herringfish.
* The construction does not provide a mining or proof-of-work function.
* SHAKE256 is used for pseudorandom expansion, not for computational hardness tuning.

## Research Notes
If hash-based hardness is required for future constructions, it should be:
* Explicitly specified with iteration count, target, and verification procedure
* Separated from key schedule via domain separation
* Evaluated for side-channel and performance implications

Current version: v0.2.6
Specification: `docs/specification/feistel_arx_v0.2.md`
