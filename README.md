# Herringfish

**Herringfish** explores a hybrid symmetric-key construction combining ideas from classical block ciphers, modern permutation-based cryptography, and sponge-derived cryptographic material.

Inspired by the naming tradition of algorithms such as **Blowfish**, Herringfish is intended to be more than a software library: the long-term goal is to develop a complete, independently testable cryptographic primitive with a clearly defined specification, reference implementation, test vectors, performance characteristics, and documented security analysis.

> ⚠️ **Experimental cryptography**
>
> Herringfish is a research project and must **not** be used to protect real-world secrets, production systems, passwords, financial information, or other sensitive data.
>
> A new cipher should be considered insecure until it has undergone extensive public cryptanalysis and independent review.

---

## Project Goals

The primary goals of Herringfish are:

* Design a novel symmetric-key cryptographic algorithm.
* Develop a formally documented cipher specification.
* Implement the reference algorithm in Rust.
* Explore multiple candidate cipher constructions.
* Analyze resistance against known cryptanalytic techniques.
* Build automated cryptanalysis and testing tools.
* Provide deterministic test vectors and known-answer tests.
* Develop portable and constant-time implementations.
* Investigate SIMD acceleration.
* Benchmark the algorithm across different platforms.
* Study reduced-round variants and potential weaknesses.
* Eventually design an authenticated-encryption construction around the primitive.

The project is deliberately designed around the principle:

> **Design it, implement it, test it, and then try to break it.**

---

# Herringfish Cipher

The final Herringfish construction has not been frozen yet.

The project will explore different cryptographic constructions before committing to a final design.

Potential construction families include:

* Feistel networks
* Lai–Massey constructions
* Substitution-permutation networks
* ARX constructions
* Hybrid constructions
* Dedicated permutation-based designs

The final design will be selected based on cryptographic properties rather than implementation convenience.

## Target Properties

The initial design targets are:

| Property                     | Target                         |
| ---------------------------- | ------------------------------ |
| Cipher type                  | Symmetric-key cipher           |
| Key size                     | 256 bits                       |
| Block size                   | 128 bits                       |
| Architecture                 | TBD                            |
| Number of rounds             | TBD through analysis           |
| Security target              | High classical security margin |
| Constant-time implementation | Required                       |
| SIMD implementation          | Planned                        |
| AEAD construction            | Planned                        |
| Reference implementation     | Rust                           |

These values are **design targets, not security claims**.

The actual security of Herringfish will depend on the final construction and the results of cryptanalysis.

---

# Design Philosophy

Herringfish is being developed differently from a conventional software-only cryptography project.

The algorithm should be treated as a mathematical object first and an implementation second.

The development process is therefore:

```text
Cryptographic Design
        │
        ▼
Mathematical Specification
        │
        ▼
Reference Implementation
        │
        ▼
Known-Answer Tests
        │
        ▼
Statistical Testing
        │
        ▼
Cryptanalysis
        │
        ▼
Optimization
        │
        ▼
Independent Review
        │
        ▼
Final Specification
```

Performance optimization should never be allowed to obscure the security properties of the underlying construction.

---

# Cryptanalysis

A major component of Herringfish is the ability to attack the algorithm itself.

The project includes research tooling for investigating potential weaknesses.

Planned and experimental analysis includes:

### Differential Cryptanalysis

Investigate how differences propagate through the cipher.

Areas of interest include:

* Differential characteristics
* Differential probabilities
* Differential trails
* Difference distribution tables
* Reduced-round attacks
* High-probability characteristics

### Linear Cryptanalysis

Investigate statistical relationships between:

* plaintext bits
* ciphertext bits
* key bits
* intermediate states

Planned tooling includes linear approximation tables and bias analysis.

### Avalanche Analysis

Measure how a single input-bit change affects the resulting ciphertext.

For an idealized cipher, changing one input bit should rapidly influence approximately half of the output bits.

Measurements will include:

* Avalanche score
* Bit independence
* Per-round diffusion
* Hamming-distance distributions

### Related-Key Analysis

Investigate whether carefully related keys produce exploitable relationships between ciphertexts.

This is particularly important for evaluating the key schedule.

### Reduced-Round Analysis

Herringfish will be tested with fewer rounds than the proposed full construction.

For example:

```text
Herringfish
├── 1 round
├── 2 rounds
├── 3 rounds
├── ...
├── N-1 rounds
└── N rounds
```

A healthy design should demonstrate a meaningful security margin between the number of rounds required for practical cryptanalysis and the number used by the final cipher.

### Statistical Analysis

The project will investigate:

* Output distributions
* Bit frequencies
* Correlations
* χ² tests
* Hamming-weight distributions
* Serial correlations
* Bias propagation
* Randomness characteristics

Statistical randomness tests cannot prove cryptographic security, but they can reveal obvious structural problems.

---

# Brute-Force Analysis

Brute-force experiments are useful for validating the practical cost of exhaustive search and for testing the project's attack infrastructure.

The project may use GPU acceleration for controlled experiments.

For example:

```text
Known plaintext
      │
      ▼
Candidate key
      │
      ▼
Herringfish encryption
      │
      ▼
Compare ciphertext
      │
      ├── No match → next candidate
      │
      └── Match → candidate key
```

Brute-force experiments are primarily intended for:

* Reduced key sizes
* Reduced-round variants
* Benchmarking
* Attack-framework validation
* Educational demonstrations

A full 256-bit key search is computationally infeasible with conventional hardware.

---

# Implementation

The reference implementation is written in **Rust**.

Rust is used because it provides:

* Memory safety
* Strong type guarantees
* Excellent performance
* Cross-platform support
* Low-level control
* Good support for constant-time implementation techniques
* A strong ecosystem for cryptographic software

The reference implementation will prioritize:

1. Correctness
2. Deterministic behavior
3. Testability
4. Constant-time operation
5. Portability
6. Performance

Optimization comes after correctness and security analysis.

---

# SIMD

Herringfish is intended to support hardware acceleration where practical.

Potential implementation targets include:

### x86-64

* AVX2
* AVX-512
* AES-related instruction sets where applicable
* Other relevant SIMD extensions

### ARM

* NEON
* ARM cryptographic extensions where applicable

### GPU

Experimental GPU implementations may be used for:

* Cryptanalysis
* Large-scale statistical testing
* Brute-force experiments
* Performance research

GPU implementations are not intended to replace the portable reference implementation.

---

# Constant-Time Implementation

Cryptographic operations should avoid data-dependent timing behavior.

The implementation will therefore attempt to avoid:

* Secret-dependent branches
* Secret-dependent memory access
* Secret-dependent lookup tables
* Unnecessary allocations
* Other observable timing differences

Constant-time behavior will be treated as an implementation requirement rather than an optional optimization.

---

# Test Vectors

Every stable version of the Herringfish specification should eventually have deterministic test vectors.

A test vector should contain information such as:

```text
Key
Plaintext
Ciphertext
```

For example:

```text
Key:
0000000000000000000000000000000000000000000000000000000000000000

Plaintext:
00000000000000000000000000000000

Ciphertext:
<TBD>
```

The actual vectors will be generated only after the cipher construction has been sufficiently stabilized.

Test vectors will be used for:

* Rust implementation testing
* Cross-platform validation
* SIMD validation
* Regression testing
* Independent implementations
* Future interoperability testing

---

# Testing Strategy

Herringfish will use several levels of testing.

## Unit Tests

Individual components will be tested independently:

* Key schedule
* Round function
* S-boxes
* Permutations
* Mixing functions
* Encryption
* Decryption

## Known-Answer Tests

Known inputs must always produce known outputs.

## Round-Trip Tests

The fundamental property:

```text
decrypt(encrypt(P, K), K) == P
```

must hold for all valid inputs.

## Differential Tests

Compare implementations and intermediate states to detect unintended differences.

## Statistical Tests

Large numbers of generated ciphertexts will be analyzed for obvious statistical weaknesses.

## SIMD Equivalence Tests

SIMD implementations must produce exactly the same results as the portable reference implementation.

```text
Reference implementation
          │
          ├──── identical ────► AVX2
          │
          ├──── identical ────► AVX-512
          │
          └──── identical ────► ARM/other implementations
```

---

# Project Structure

The project is expected to evolve toward a structure similar to:

```text
herringfish/
│
├── src/
│   ├── cipher/
│   │   ├── mod.rs
│   │   ├── key_schedule.rs
│   │   ├── round.rs
│   │   ├── encrypt.rs
│   │   └── decrypt.rs
│   │
│   ├── aead/
│   │
│   ├── cryptanalysis/
│   │   ├── differential.rs
│   │   ├── linear.rs
│   │   ├── avalanche.rs
│   │   ├── related_key.rs
│   │   └── statistics.rs
│   │
│   ├── math/
│   │
│   ├── simd/
│   │
│   └── lib.rs
│
├── tests/
│   ├── vectors/
│   ├── known_answer.rs
│   ├── differential.rs
│   └── avalanche.rs
│
├── benchmarks/
│
├── examples/
│
├── docs/
│   └── specification/
│
├── Cargo.toml
└── README.md
```

The exact structure may change as the algorithm develops.

---

# Performance

Performance benchmarking will be part of the project, but performance will not be used as evidence of cryptographic security.

Benchmarks will measure:

* Encryption throughput
* Decryption throughput
* Key setup
* Key schedule cost
* Small-message performance
* Large-buffer throughput
* SIMD acceleration
* CPU scaling
* GPU performance where applicable

Results should distinguish between:

```text
Portable reference implementation
            │
            ├── Scalar
            │
            ├── SIMD
            │
            └── Hardware-specific optimized versions
```

---

# Security Model

Herringfish will eventually need to define a formal security model.

Potential goals include resistance against:

* Known-plaintext attacks
* Chosen-plaintext attacks
* Chosen-ciphertext attacks
* Differential cryptanalysis
* Linear cryptanalysis
* Related-key attacks
* Integral attacks
* Impossible differential attacks
* Statistical attacks
* Structural attacks
* Meet-in-the-middle attacks where applicable
* Algebraic attacks
* Side-channel attacks at the implementation level

The final security claims will be based on analysis rather than assumptions.

---

# Post-Quantum Considerations

Herringfish is primarily a **symmetric-key algorithm**.

It is therefore fundamentally different from public-key post-quantum algorithms such as:

* ML-KEM
* ML-DSA
* SLH-DSA

However, quantum attacks remain relevant.

In particular, Grover's algorithm reduces the generic exhaustive-search complexity of an idealized `n`-bit key from approximately:

```text
2^n
```

to:

```text
2^(n/2)
```

This is one reason a 256-bit key is an interesting target for a modern experimental cipher.

This does **not** mean Herringfish automatically provides 128-bit post-quantum security. The final security level depends on the complete construction.

---

# Design Questions

Before freezing the Herringfish specification, several questions need to be answered experimentally.

### 1. What primitive?

Possible candidates:

* Feistel
* SPN
* ARX
* Lai–Massey
* Hybrid

### 2. What block size?

Potential choices:

* 64-bit
* 128-bit
* 256-bit

A 128-bit block is currently the preferred target.

### 3. What key size?

The current target is:

```text
256 bits
```

### 4. How many rounds?

The number of rounds should be determined by cryptanalysis and security margin rather than arbitrary selection.

### 5. How should nonlinear components be constructed?

Potential approaches include:

* Fixed S-boxes
* Generated S-boxes
* Algebraic constructions
* Multiple S-boxes
* Key-independent S-boxes

### 6. How should diffusion work?

The design should achieve rapid diffusion while remaining efficient on modern processors.

### 7. How should the key schedule work?

The key schedule must avoid introducing structural weaknesses or exploitable related-key relationships.

---

# Development Principles

Herringfish follows several principles.

### Security before performance

A fast insecure cipher is still insecure.

### Simplicity before complexity

Every component should have a clear cryptographic justification.

### Measure instead of assume

Cryptographic properties should be tested experimentally whenever possible.

### Attack our own design

The project should actively search for weaknesses rather than attempting to prove that none exist.

### Reproducibility

Experiments should be deterministic and reproducible whenever practical.

### Independent verification

A future implementation should be possible without depending on the Rust reference implementation.

---

# Current Status

**Status: Experimental / Research**

The Herringfish algorithm is currently under development.

The specification is **not frozen**.

The following areas are under active development:

* [ ] Final cipher construction
* [ ] Key schedule
* [ ] Round function
* [ ] Nonlinear layer
* [ ] Diffusion layer
* [ ] Round-count analysis
* [ ] Reference implementation
* [ ] Known-answer test vectors
* [ ] Differential analysis
* [ ] Linear analysis
* [ ] Avalanche analysis
* [ ] Statistical analysis
* [ ] Reduced-round attacks
* [ ] SIMD implementation
* [ ] Performance benchmarks
* [ ] AEAD construction
* [ ] Formal specification
* [ ] Independent cryptanalysis

---

# Research Status

A successful implementation of Herringfish does **not** imply that Herringfish is cryptographically secure.

New cryptographic algorithms routinely contain weaknesses that are not apparent during initial development.

The intended lifecycle is:

```text
Prototype
   ↓
Testing
   ↓
Cryptanalysis
   ↓
Revision
   ↓
Cryptanalysis
   ↓
Public review
   ↓
Revision
   ↓
Independent analysis
   ↓
Specification freeze
```

A cipher should not be considered mature simply because it passes its own test suite.

---

# Contributing

Contributions involving cryptographic analysis are especially valuable.

Useful contributions include:

* Cryptanalytic attacks
* Differential characteristics
* Linear approximations
* Statistical analysis
* Performance improvements
* SIMD implementations
* Independent implementations
* Test vectors
* Mathematical analysis
* Documentation
* Reproducible experiments

Finding a weakness is considered a **successful research result**, not a failure of the project.

---

# Disclaimer

Herringfish is experimental cryptographic research software.

It has not been subjected to the level of public scrutiny, peer review, formal analysis, or cryptanalysis required to establish confidence in a production cryptographic algorithm.

**Do not use Herringfish to protect real-world data.**

The project is intended for research, experimentation, education, benchmarking, and cryptographic analysis.

---

# License

MIT License

Copyright © 2026

See [`LICENSE`](LICENSE) for the complete license text.

---

## Herringfish

**Design it. Implement it. Test it. Break it. Improve it.**
