# Side-Channel Review – SHAKE Expansion and S-box Lookups

## Scope

Herringfish Feistel ARX v0.2 uses SHAKE256 XOF for round-key derivation with domain separation `HERRINGFISH-FEISTEL-KEY`. The S-box is frozen and currently implemented via table lookup in the reference implementation, with a constant-time selection variant available for research.

## SHAKE256 expansion

* Domain separation string is ASCII and fixed length. No secret-dependent branching in the XOF setup.
* SHAKE256 is a sponge construction with constant-time internal permutation Keccak-f[1600]. The Rust `shake` crate implements the permutation with no secret-dependent memory accesses.
* Key material is absorbed as a single block with a fixed domain separator. No key-dependent loop counts or variable-length parsing.
* Output is 1024 bits for 16 round keys, derived via `finalize_xof_into`. The output generation is data-independent once the state is initialized.

Potential concerns:
* The XOF output is used directly to form round keys. No additional whitening or key-schedule mixing is performed beyond the sponge.
* Related-key tests show average Hamming distance ≈64 bits, consistent with pseudorandom behaviour, but formal related-key security is not claimed.

Mitigations / recommendations:
* Keep domain separator fixed and public.
* Ensure the XOF is called with a fixed output length to avoid variable-time finalisation.
* Consider adding a small key-schedule mixing step if related-key security is desired.

## S-box lookups

Reference implementation:
* `f_function` uses direct table indexing `sbox[(x_byte ^ k_byte) as usize]`.
* Index is secret-dependent via `x_byte ^ k_byte`. This creates potential cache-timing leakage on CPUs with data caches.

Constant-time variant:
* `src/cipher/sbox_ct.rs` implements selection over all 256 entries using `subtle::ConstantTimeEq`.
* `FeistelArx::encrypt_block_ct` / `decrypt_block_ct` use `f_function_ct`.
* Correctness verified; benchmark shows ~1.7k× overhead vs table lookup.

Recommendation:
* For research and side-channel evaluation, the CT variant is available.
* For production, a bitsliced S-box or hardware AES-NI style implementation would be required to achieve practical constant-time performance.
* The reference implementation should be explicitly marked as non-constant-time.

## Overall assessment

* SHAKE expansion appears free of obvious secret-dependent timing in the RustCrypto implementation.
* S-box lookup is the dominant side-channel risk in the current reference implementation.
* No formal side-channel evaluation has been performed; the CT variant provides a baseline for future measurement.

## Next steps

* Measure cache-timing leakage of table lookup on target hardware.
* Evaluate bitsliced S-box performance.
* Formal review of SHAKE XOF usage for nonce misuse and domain separation.
