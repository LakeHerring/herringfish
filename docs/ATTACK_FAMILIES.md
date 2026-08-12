# Herringfish Attack Families

Herringfish is a Rust-native laboratory for mathematical cryptanalysis.

## Core attack families

- Differential cryptanalysis
- Linear cryptanalysis
- Algebraic attacks
- Meet-in-the-middle attacks
- Collision analysis
- Preimage analysis
- Discrete logarithm attacks
- Integer factorization
- Lattice attacks
- LLL/BKZ reduction
- LWE/Module-LWE attacks
- Polynomial and finite-field attacks
- Reduced-round cryptanalysis
- Statistical and probability analysis

## Principles

Herringfish distinguishes between:

Generic security
≠
Best published attack
≠
Herringfish reproduction
≠
Herringfish experimental result

For example, successfully attacking a 5-round reduced Keccak construction does not mean SHA3-256 has been broken. Herringfish should report exactly what was attacked, the parameters used, the complexity, and the result.

## Workflow

1. Identify possible primitives based on digest characteristics.
2. Verify candidate algorithms against known input/output when available.
3. Expose the underlying construction.
4. Determine which mathematical attack families apply.
5. Analyze reduced-round or reduced-parameter versions.
6. Compare experimental results with published cryptanalysis.
7. Estimate attack complexity and security margins.
8. Clearly distinguish known attacks, Herringfish experiments, and generic security estimates.

## Overall goal

Make Herringfish a Rust-native laboratory for mathematical cryptanalysis:
- Implement the mathematics behind cryptographic algorithms
- Implement attacks against that mathematics
- Reproduce known cryptanalytic results where possible
- Experimentally measure the security margin of modern cryptographic constructions
