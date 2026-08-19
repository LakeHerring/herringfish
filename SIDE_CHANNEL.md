# Side-Channel Considerations – Herringfish

**Version:** v0.2.6
**Specification:** `docs/specification/feistel_arx_v0.2.md` §26/27

## Overview
Herringfish is an experimental research cipher. Side-channel resistance is an implementation property, not an automatic guarantee of the mathematical construction.

## Reference Implementation
* `src/cipher/feistel_arx.rs` uses direct table lookup for the S-box indexed by secret-dependent data.
* Table lookup creates secret-dependent memory access patterns vulnerable to cache-timing attacks.
* Round function uses XOR, S-box lookup, and linear diffusion. No secret-dependent branches in Feistel structure itself.

## Constant-Time Variant
* `src/cipher/sbox_ct.rs` provides a constant-time S-box via `subtle::ConstantTimeEq` selection over all 256 entries.
* `FeistelArx::encrypt_block_ct` / `decrypt_block_ct` use `f_function_ct` with constant-time S-box lookup.
* Correctness verified: CT output matches table-lookup output.
* Performance overhead ~1 647× vs table lookup in reference benchmarks.
* The CT variant is research-grade and not optimized for production.

## Key Schedule
* SHAKE256 XOF derivation uses RustCrypto `shake` crate.
* No secret-dependent branches in key schedule.
* SHAKE256 software implementation is constant-time in the underlying crate, but overall key schedule timing is dominated by XOF processing.

## SIMD / AVX2
* AVX2 diffusion benchmark exists in `src/simd/avx2.rs`.
* Gather-based S-box access remains secret-dependent. Bitsliced S-box or constant-time gather required for side-channel resistance.

## Findings Summary
* Reference implementation is not constant-time.
* Constant-time variant exists for research evaluation.
* Side-channel review documented in `docs/side_channel_review_v0.2.md` and `docs/side_channel_review.md`.

## Recommendations
* Keep reference and CT implementations clearly separated and documented.
* Production use requires additional hardening: constant-time S-box, constant-time diffusion, verified side-channel testing.
* Do not assume side-channel resistance from mathematical design alone.

## Disclaimer
Herringfish must not be used to protect real-world secrets. Side-channel evaluation is ongoing and incomplete.
