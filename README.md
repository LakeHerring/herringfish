Architecture
src/
├── attack/
│   ├── hash/
│   ├── symmetric/
│   ├── public_key/
│   ├── lattice/
│   └── pqc/
│
├── math/
│   ├── bigint/
│   ├── finite_field/
│   ├── polynomial/
│   ├── matrix/
│   ├── lattice/
│   ├── ntt/
│   └── probability/
│
└── primitives/
    ├── hash/
    ├── symmetric/
    ├── asymmetric/
    └── pqc/

# herringfish

Mathematical Cryptanalysis & Cryptographic Attack Framework. Herringfish is not primarily a password cracker or hash-cracking utility. It is a mathematical cryptanalysis framework.

Herringfish is a Rust-based cryptanalytic research framework for studying the mathematical foundations and security properties of modern cryptographic algorithms.

Rather than focusing primarily on password cracking or hash lookup attacks, Herringfish implements mathematical and structural attack techniques against cryptographic primitives and their underlying constructions.

Primitive → Mathematical Model → Attack → Analysis → Result
Goals

Herringfish aims to provide a unified environment for:

Mathematical cryptanalysis
Cryptographic attack research
Reduced-round analysis
Algebraic attacks
Differential and linear cryptanalysis
Lattice-based attacks
Number-theoretic attacks
Finite-field and polynomial attacks
Complexity estimation
Cryptographic primitive analysis
Experimental attacks against reduced/toy instances

The project is intended for research, education, validation, and experimentation.

## Overview

`herringfish` is a research-oriented toolkit for mathematical cryptanalysis of hash functions. It focuses on the internal structures of SHA-2, SHA-3 and SHAKE rather than black-box collision search.

Supported families:
- **SHA2** – SHA-256, SHA-512 variants
- **SHA3** – Keccak-f permutation, SHA3-256/512
- **SHAKE** – SHAKE128, SHAKE256 extendable-output functions

Modules:
- `primitives` – Reference implementations and differential/linear hooks for SHA-256 compressor, Keccak-f, SHA3/SHAKE
- `attack` – Differential, Linear, Algebraic attack scaffolding with a common `Attack` trait
- `math` – Combinatorics, DDT construction, Keccak χ DDT, linear algebra utilities, probability helpers

## Building

```bash
cargo build --release
```

The release profile enables LTO, opt-level 3, strip and single codegen unit for crypto hot paths.

## CLI usage

```bash
cargo run -- --family SHA3 --attack differential --rounds 6
cargo run -- --family SHA2 --attack differential --rounds 16
cargo run -- --ddt
cargo run -- --keccak-chi-ddt
```

Options:
- `--family <SHA2|SHA3|SHAKE>`
- `--attack <differential|linear|algebraic>`
- `--rounds <n>` default 4
- `--ddt` compute DDT for PRESENT S-box
- `--keccak-chi-ddt` print Keccak χ DDT summary
- `--help`

## Project layout

```
src/
  primitives/  sha2.rs sha256.rs sha3.rs shake.rs keccak.rs
  attack/      differential.rs linear.rs algebraic.rs mod.rs
  math/        combinatorics.rs ddt.rs keccak_chi_ddt.rs linear_algebra.rs probability.rs
scripts/       update_acvp_vectors.sh / .ps1
tests/vectors/ ACVP test vectors
```

## Development notes

- The current implementation contains reduced-round demonstrators and placeholders for full round analysis. Replace placeholders with real Keccak-f / SHA-256 round analysis for production research.
- Warnings are tracked; see `cargo check` output.
- ACVP vectors can be refreshed with `scripts/update_acvp_vectors.sh`.

The architecture deliberately separates three concerns:

primitives

Implementations and mathematical representations of cryptographic primitives.

Examples:

SHA-2
SHA-3
SHAKE
AES
RSA
ECC
ML-KEM
ML-DSA
math

Reusable mathematical machinery used by both primitives and attacks.

Examples:

Arbitrary-precision arithmetic
Modular arithmetic
Polynomial arithmetic
Finite fields
Matrices and vectors
NTT
Lattice operations
Probability and statistical analysis
attack

Cryptanalytic algorithms operating against the mathematical representations exposed by the primitives.

Examples:

Differential cryptanalysis
Linear cryptanalysis
Algebraic attacks
Meet-in-the-middle
Birthday attacks
Discrete logarithm attacks
Integer factorization
LLL/BKZ lattice attacks
LWE/Module-LWE attacks
Cryptographic Scope

Herringfish is designed to eventually cover several major families of cryptography.

Family	Examples	Attack areas
Hash functions	SHA-224/256/384/512	Collision, preimage, structural, reduced-round
SHA-3 family	SHA3, SHAKE	Keccak permutation, differential, structural
Symmetric	AES and related primitives	Differential, linear, algebraic
RSA	RSA variants	Factorization, algebraic/parameter attacks
ECC	ECDSA, ECDH	Discrete logarithms, subgroup attacks
Lattice/PQC	ML-KEM, ML-DSA	LWE, Module-LWE, lattice reduction
Finite-field crypto	DH, DSA	Discrete logarithms
General constructions	Various	Algebraic and combinatorial analysis
Mathematical Attack Model

A central design principle is that Herringfish should not treat cryptographic algorithms as opaque black boxes.

For example, ML-KEM can be represented as:

ML-KEM
   │
   ▼
Module-LWE
   │
   ▼
Polynomial Ring
   │
   ▼
Lattice Representation
   │
   ▼
Lattice Reduction
   │
   ├── LLL
   ├── BKZ
   └── Enumeration
   │
   ▼
Attack Complexity

Similarly, SHA-3 can be analyzed through its underlying Keccak construction:

SHA-3
  │
  ▼
Keccak-f
  │
  ├── θ
  ├── ρ
  ├── π
  ├── χ
  └── ι
  │
  ▼
Reduced / Full Round Analysis
  │
  ▼
Cryptanalytic Attack

This allows attacks to operate on the mathematical structure of the primitive, rather than merely treating the primitive as a function that accepts bytes and returns bytes.

Attack Results

An important objective is to distinguish between successfully recovering a secret and demonstrating the cost of an attack.

An attack may therefore produce results such as:

Attack Result
├── Target
├── Parameters
├── Attack type
├── Data complexity
├── Time complexity
├── Memory complexity
├── Success probability
├── Required mathematical assumptions
├── Recovered information
└── Experimental results

For example, an ML-KEM attack may determine that a particular lattice reduction parameter is required without actually recovering a real-world ML-KEM-768 secret.

Likewise, a SHA-256 experiment may demonstrate a structural attack against a reduced-round construction without claiming that full SHA-256 has been broken.

Design Philosophy

Herringfish follows several principles:

Mathematics first

Cryptographic security ultimately depends on mathematical assumptions. Herringfish therefore exposes those mathematical structures rather than hiding them behind high-level APIs.

Research before optimization

Correct mathematical models and reproducible experiments take priority over raw performance. Performance optimizations—including SIMD and parallel execution—are introduced where they meaningfully improve cryptanalytic workloads.

Reduced instances are first-class targets

Many cryptanalytic techniques cannot practically be demonstrated against full-strength modern primitives. Reduced-round and toy parameter sets are therefore legitimate and important targets.

Reproducibility

Attack parameters, complexity estimates, intermediate mathematical structures, and results should be reproducible.

Rust-native

The framework is written in Rust with an emphasis on:

Type safety
Memory safety
Deterministic computation
Parallelism
SIMD acceleration
Cross-platform execution
Current Development

Herringfish is currently under active development.

Current work includes:

 Cryptanalysis framework architecture
 Mathematical core
 Modular arithmetic
 Polynomial arithmetic
 Matrix/vector infrastructure
 NTT infrastructure
 SHA-2 primitives
 SHA-3 primitives
 SHAKE primitives
 Differential cryptanalysis framework
 Algebraic attack framework
 Lattice infrastructure
 LLL
 BKZ
 LWE analysis
 Module-LWE analysis
 ML-KEM analysis
 ML-DSA analysis
 RSA/factorization attacks
 Discrete-log attacks
 Comprehensive benchmarks
 Reproducible attack reports


## License

MIT

## Compliance

See [COMPLIANCE.md](COMPLIANCE.md). Research use only.

## Side-channel considerations

See [SIDE_CHANNEL.md](SIDE_CHANNEL.md).

## Attack Families & Principles

See [docs/ATTACK_FAMILIES.md](docs/ATTACK_FAMILIES.md) for the full list of supported attack families and design principles.

Herringfish distinguishes between:
- Generic security
- Best published attack
- Herringfish reproduction
- Herringfish experimental result

## How to use Herringfish for a digest

Given a digest such as `02208b9403a87df9f4ed6b2ee2657efaa589026b4cce9accc8e8a5bf3d693c86`:

1. **Identify possible primitives** – Use `examples/identify_hash.rs` to infer candidate families from length. 32 bytes → SHA-256 / SHA3-256 / SHAKE truncated.
2. **Verify candidate algorithms** – If a candidate message is known, recompute `H(message)` and compare. Verification is feasible; inversion is not.
3. **Expose the underlying construction** – Map the primitive to its mathematical model: Merkle-Damgård compression for SHA-2, Keccak sponge with θ,ρ,π,χ,ι for SHA-3/SHAKE.
4. **Determine applicable attack families** – See `docs/ATTACK_FAMILIES.md`. For hash functions: differential, linear, algebraic, meet-in-the-middle, collision/preimage analysis, reduced-round cryptanalysis, statistical/probability analysis.
5. **Analyze reduced-round / reduced-parameter versions** – Use `attack/hash/experiments` for reduced-round differential trails and `math/finite_field/ddt` for DDT analysis.
6. **Compare with published cryptanalysis** – `HASH_DIFFICULTY.md` summarizes best public results for SHA-2/SHA-3/SHAKE.
7. **Estimate attack complexity and security margins** – Combine experimental results with published bounds. Distinguish generic security from best known attacks.
8. **Report clearly** – State target, parameters, attack type, data/time/memory complexity, success probability, assumptions, and whether the result is reproduction or new experiment.

This workflow ensures Herringfish is used as a mathematical laboratory, not a brute-force hash cracker.
