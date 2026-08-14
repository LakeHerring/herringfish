# Side-Channel Review – Herringfish Feistel ARX v0.2

## Scope
Review of SHAKE-derived key expansion and S-box lookup implementation for timing and cache leakage.

## Findings

### Key Schedule
* SHAKE256 XOF is data-dependent in input: master key and domain string.
* Current RustCrypto `shake` implementation uses constant-time sponge absorb/squeeze for fixed-length inputs, but overall key expansion runs once per key setup.
* Round keys are derived sequentially; no secret-dependent branches observed in reference implementation.
* Recommendation: Ensure `finalize_xof_into` runs in constant time w.r.t. output length; avoid early exit on zero bytes.

### S-box Layer
* Reference implementation uses byte-indexed lookup: `sbox[(x_byte ^ k_byte) as usize]`.
* Lookup table access is secret-dependent via `x_byte ^ k_byte`.
* On CPUs with cache-timing side channels, S-box lookups can leak key material via access patterns.
* Current prototype is not constant-time for S-box access.

### Mitigations
* Implement S-box via bitsliced or pre-computed constant-time table with masking.
* Use `core::arch` intrinsics or `subtle` crate to avoid secret-dependent memory access.
* Consider using AES-NI style T-tables with constant-time indexing, or generate S-box as affine-transformed AES S-box and use vectorized lookup.
* Separate key schedule from encryption hot path; pre-compute round keys before timing-sensitive operations.

### Diffusion Layer
* Linear diffusion `out[i]=in[i]⊕in[i+1]⊕in[i+3]` is constant-time; no branches.

### Recommendations
* Audit with `cargo audit` and `cargo bench` for secret-dependent branches.
* Add constant-time tests using `subtle` comparisons.
* Document side-channel assumptions in specification.

Status: Open – requires implementation changes and formal testing.
