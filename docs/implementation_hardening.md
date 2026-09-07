# Implementation Hardening – Herringfish Feistel ARX v0.2

## Current risks

* **Secret-dependent S-box lookup**: `sbox[(x_byte ^ k_byte) as usize]` accesses memory based on secret key material.
* **SHAKE expansion**: key schedule runs once, but `finalize_xof_into` must be constant-time w.r.t. output length.
* **Branching**: current reference implementation contains no secret-dependent branches, but future optimizations may introduce them.

## Recommendations

### Constant-time S-box
* Replace table lookup with bitsliced or pre-computed constant-time implementation.
* Use `subtle::ConstantTimeEq` for comparisons.
* Avoid secret-dependent array indexing.

### Key schedule
* Ensure SHAKE256 XOF runs with fixed output length.
* Pre-compute round keys before timing-sensitive operations.

### Testing
* Add constant-time tests using `subtle` and statistical timing analysis.
* Document side-channel assumptions in spec.

## Status
Open – requires implementation changes and formal testing.
