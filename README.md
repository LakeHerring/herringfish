# Herringfish

[![Latest Release](https://img.shields.io/github/v/release/LakeHerring/herringfish?display_name=tag&sort=semver)](https://github.com/LakeHerring/herringfish/releases/latest)
[![CI](https://github.com/LakeHerring/herringfish/actions/workflows/rust.yml/badge.svg)](https://github.com/LakeHerring/herringfish/actions/workflows/rust.yml)
[![License](https://img.shields.io/github/license/LakeHerring/herringfish)](https://github.com/LakeHerring/herringfish/blob/main/LICENSE)

> Experimental symmetric-key cryptography research project...

# Herringfish

**Herringfish** is an experimental symmetric-key cryptography research project focused on the design, implementation, testing, and cryptanalysis of a novel block-cipher construction.

The current construction, **Herringfish Feistel ARX v0.2**, is a 128-bit balanced Feistel network using an 8-bit nonlinear S-box layer, ARX-based processing, XOR-based diffusion, and a SHAKE256-derived key schedule.

The long-term objective is to develop a complete, independently testable cryptographic primitive with:

* A clearly defined mathematical specification
* A portable reference implementation
* Deterministic test vectors
* Known-answer tests
* Reproducible cryptanalytic experiments
* Performance benchmarks
* Constant-time implementation techniques
* SIMD implementations
* Public cryptanalysis
* Independent review

> [!WARNING]
> **Experimental cryptography**
>
> Herringfish is a research project and **must not be used to protect real-world secrets, production systems, passwords, financial information, or other sensitive data**.
>
> Herringfish has not undergone the level of independent cryptanalysis and public review required for a production cryptographic primitive.
>
> For real-world cryptographic applications, use established and extensively analyzed constructions such as AES-GCM or ChaCha20-Poly1305.

The guiding principle of the project is:

> **Design it. Implement it. Test it. Break it. Improve it.**

---

# Project Goals

The primary goals of Herringfish are:

* Design and investigate a novel symmetric-key block cipher.
* Develop a precise mathematical specification.
* Implement a portable reference implementation in Rust.
* Explore and evaluate alternative construction strategies.
* Analyze resistance against known cryptanalytic techniques.
* Build automated cryptanalysis and attack tooling.
* Provide deterministic test vectors and known-answer tests.
* Investigate constant-time implementation techniques.
* Develop portable implementations across major CPU architectures.
* Investigate SIMD acceleration.
* Benchmark implementations across different platforms.
* Study reduced-round variants and potential weaknesses.
* Develop reproducible cryptographic experiments.
* Eventually investigate an authenticated-encryption construction around the primitive.

The project deliberately treats the cipher as a **mathematical object first and a software implementation second**.

---

# Herringfish Feistel ARX v0.2

The current Herringfish construction is **Feistel ARX v0.2**, an experimental balanced Feistel block cipher.

The v0.2 construction combines:

* A 128-bit block size
* A 256-bit master key
* 16 Feistel rounds
* An 8-bit nonlinear S-box
* ARX-based processing
* XOR-based byte diffusion
* SHAKE256-derived round keys
* Domain-separated key derivation

The current design is documented in:

```text
docs/specification/feistel_arx_v0.2.md
```

and the current Rust implementation is located at:

```text
src/cipher/feistel_arx.rs
```

The v0.2 construction is a **research prototype**. Its parameters are currently frozen for evaluation, but the construction may change as cryptanalysis progresses.

Freezing parameters for an evaluation version does not imply that the design has been proven secure.

---

## Target Properties

| Property                 | v0.2                                                |
| ------------------------ | --------------------------------------------------- |
| Primitive                | Symmetric-key block cipher                          |
| Construction             | Balanced Feistel                                    |
| Block size               | 128 bits                                            |
| Master key               | 256 bits                                            |
| Feistel halves           | 64 bits each                                        |
| Rounds                   | 16                                                  |
| Nonlinear layer          | 8-bit S-box                                         |
| Diffusion                | XOR-based byte mixing                               |
| Key schedule             | SHAKE256 XOF                                        |
| Reference implementation | Rust                                                |
| SIMD                     | Planned                                             |
| AEAD                     | Planned                                             |
| Security goal            | Investigate a substantial classical security margin |

These are **design parameters and research targets**, not established security guarantees.

A 256-bit key does not automatically provide 256-bit cryptographic security. Likewise, statistical testing, avalanche testing, or successful known-answer tests do not establish cryptographic security.

The actual security of Herringfish depends on the complete construction and the results of cryptanalysis.

---

# What Herringfish Is — and Is Not

Herringfish is currently:

* An experimental cryptographic research project.
* A concrete block-cipher prototype.
* A reference implementation and research platform.
* A framework for testing cryptographic hypotheses.
* A platform for developing cryptanalytic tooling.

Herringfish is **not** currently:

* A standardized cipher.
* A NIST-approved cryptographic primitive.
* A production-ready encryption algorithm.
* Independently cryptanalyzed.
* Proven secure.
* A replacement for AES or ChaCha20.
* An AEAD scheme.
* Guaranteed to provide 256-bit security merely because the key is 256 bits.

Finding a weakness in Herringfish is considered a **successful research result**.

---

# Design Philosophy

Herringfish follows a research-oriented development process.

The algorithm should be understood mathematically before implementation details and performance optimizations are considered.

The intended development lifecycle is:

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
Reduced-Round Analysis
        │
        ▼
Optimization
        │
        ▼
Public Review
        │
        ▼
Independent Analysis
        │
        ▼
Specification Freeze
```

Performance optimization must never obscure the security properties or mathematical behavior of the construction.

---

# Cryptanalysis

A central purpose of Herringfish is to **attack the cipher itself**.

The project includes research tooling intended to identify structural weaknesses, statistical biases, insufficient diffusion, weak key scheduling, and other potential attack surfaces.

Cryptanalysis is divided into several areas.

## Differential Cryptanalysis

Differential analysis investigates how input differences propagate through the construction.

Areas of investigation include:

* Difference distribution tables
* Differential probabilities
* Differential characteristics
* Differential trails
* Reduced-round characteristics
* High-probability characteristics
* Differential distinguishers
* Key-dependent differential behavior

S-box DDT measurements describe properties of the nonlinear component. They do **not**, by themselves, establish resistance of the complete cipher.

---

## Linear Cryptanalysis

Linear analysis investigates statistical relationships between plaintext, ciphertext, key, and intermediate-state bits.

Areas of investigation include:

* Linear approximation tables
* Linear biases
* Linear characteristics
* Reduced-round approximations
* Bias propagation
* Potential linear distinguishers

S-box LAT measurements are useful component-level information but do not establish full-cipher security.

---

## Avalanche Analysis

Avalanche analysis measures how changes to input bits propagate through the cipher.

Measurements include:

* Avalanche scores
* Hamming-distance distributions
* Per-round diffusion
* Bit independence
* Input/output bit dependencies
* Diffusion speed

For an idealized cipher, a one-bit input difference should eventually affect approximately half of the output bits.

Avalanche behavior is useful for identifying obvious structural problems but is **not a proof of cryptographic security**.

---

## Related-Key Analysis

Related-key analysis investigates whether controlled relationships between keys produce exploitable relationships between ciphertexts or internal states.

This is particularly relevant to the key schedule.

The objective is to identify:

* Weak key relationships
* Predictable round-key relationships
* Structural key dependencies
* Differential behavior across related keys
* Potential related-key distinguishers

Statistical observations of round keys should not be interpreted as proof that the key schedule is cryptographically secure.

---

## Reduced-Round Analysis

Reduced-round versions of Herringfish are evaluated to investigate how security develops as the number of rounds increases.

For example:

```text
Herringfish
├── 1 round
├── 2 rounds
├── 3 rounds
├── ...
├── 14 rounds
├── 15 rounds
└── 16 rounds
```

Reduced-round experiments may include:

* Exhaustive search
* Differential characteristics
* Linear approximations
* Statistical distinguishers
* Structural analysis
* Automated characteristic searches

The objective is to determine whether the full-round configuration provides a meaningful security margin.

Resistance of a reduced-round variant does not establish security of the full construction, and successful attacks against reduced-round variants do not necessarily apply to the full cipher.

---

## Statistical Analysis

Statistical testing is used to identify obvious structural biases.

Experiments may include:

* Output distributions
* Bit frequencies
* Correlations
* χ² tests
* Hamming-weight distributions
* Serial correlations
* Bias propagation
* Randomness testing
* Per-round statistical measurements

Statistical tests can reveal structural problems, but **random-looking output does not prove cryptographic security**.

---

# Brute-Force Analysis

Brute-force experiments are primarily intended to validate attack infrastructure and measure the practical cost of exhaustive search.

The general model is:

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

Controlled brute-force experiments may use:

* Reduced key sizes
* Reduced-round variants
* GPU acceleration
* Known-answer test vectors
* Attack-framework validation

A generic exhaustive search over a 256-bit key space has approximately:

```text
2^256
```

possible keys and is computationally infeasible with conventional hardware.

The existence of brute-force tooling should therefore not be interpreted as an expectation that the full 256-bit key space can be searched.

---

# Implementation

The reference implementation is written in **Rust**.

Rust provides:

* Memory safety
* Strong type guarantees
* High performance
* Cross-platform support
* Low-level control
* A strong ecosystem for cryptographic software
* Useful facilities for implementing security-sensitive code

The implementation prioritizes:

1. Correctness
2. Deterministic behavior
3. Testability
4. Portability
5. Constant-time implementation techniques
6. Performance

Optimization follows correctness and cryptographic analysis.

---

# Constant-Time Implementation

Cryptographic implementations should avoid secret-dependent observable behavior.

Herringfish implementations are therefore designed to avoid:

* Secret-dependent branches
* Secret-dependent memory access
* Secret-dependent table lookups where practical
* Unnecessary allocations in cryptographic operations
* Other avoidable timing dependencies

Constant-time behavior is an **implementation goal and requirement**, not an automatically established property.

A source-code implementation that appears constant-time must still be evaluated through implementation review and appropriate side-channel testing.

In particular, the S-box implementation must be evaluated carefully because table-based implementations can introduce cache-based side channels when indexed by secret-dependent values.

---

# SIMD and Hardware Acceleration

Herringfish is intended to support hardware acceleration where practical.

## x86-64

Potential targets include:

* AVX2
* AVX-512
* Other relevant x86-64 SIMD extensions

## ARM

Potential targets include:

* NEON
* ARM cryptographic extensions where applicable

## GPU

Experimental GPU implementations may be used for:

* Cryptanalysis
* Large-scale statistical testing
* Brute-force experiments
* Attack-framework development
* Performance research

GPU implementations are research and acceleration tools and are not intended to replace the portable reference implementation.

SIMD implementations must produce results identical to the reference implementation.

---

# Test Vectors

Stable specification versions should provide deterministic test vectors.

A basic block-cipher test vector contains:

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

The repository currently contains v0.2 known-answer vectors at:

```text
docs/tables/kat_vectors_v02.txt
```

Test vectors are used for:

* Reference implementation testing
* Regression testing
* Cross-platform validation
* SIMD equivalence testing
* Independent implementations
* Reproducible research

---

# Testing Strategy

Herringfish uses several layers of testing.

## Unit Tests

Individual components are tested independently where practical:

* Key schedule
* Round function
* S-box
* Diffusion layer
* Mixing functions
* Encryption
* Decryption

## Known-Answer Tests

Known inputs must produce deterministic expected outputs.

## Round-Trip Tests

The fundamental Feistel correctness property is:

```text
decrypt(encrypt(P, K), K) == P
```

for all valid inputs.

Passing round-trip tests demonstrates functional consistency, not cryptographic security.

## Differential Tests

Independent implementations and internal states can be compared to detect unintended differences.

## Statistical Tests

Large numbers of generated outputs can be analyzed for obvious statistical weaknesses.

## SIMD Equivalence Tests

Optimized implementations must produce exactly the same results as the reference implementation.

```text
Reference implementation
          │
          ├──── identical ────► AVX2
          │
          ├──── identical ────► AVX-512
          │
          └──── identical ────► ARM / other implementations
```

---

# Project Structure

The repository structure is intentionally evolving as the research project develops.

The current cipher implementation is centered around:

```text
herringfish/
│
├── src/
│   ├── cipher/
│   │   ├── mod.rs
│   │   └── feistel_arx.rs
│   │
│   ├── cryptanalysis/
│   ├── math/
│   ├── simd/
│   └── lib.rs
│
├── tests/
│   └── vectors/
│
├── benchmarks/
├── examples/
│
├── docs/
│   ├── specification/
│   └── tables/
│
├── Cargo.toml
└── README.md
```

The exact structure may change as additional cryptanalysis, SIMD, AEAD, and benchmarking components are implemented.

---

# Performance

Performance benchmarking is an engineering objective, not evidence of cryptographic security.

Future benchmarks will measure:

* Encryption throughput
* Decryption throughput
* Key setup
* Key-schedule cost
* Small-message performance
* Large-buffer throughput
* SIMD acceleration
* CPU scaling
* GPU performance where applicable

Results should distinguish between:

```text
Reference implementation
        │
        ├── Scalar
        │
        ├── SIMD
        │
        └── Hardware-specific implementations
```

Benchmark results should include sufficient information to make experiments reproducible, including compiler version, target architecture, relevant feature flags, and hardware where practical.

---

# Security Model

A formal security model remains a future objective.

For the **block cipher primitive**, areas of analysis include:

* Differential cryptanalysis
* Linear cryptanalysis
* Related-key attacks
* Integral attacks
* Impossible differential attacks
* Statistical distinguishers
* Structural attacks
* Meet-in-the-middle attacks where applicable
* Algebraic attacks
* Other relevant generic or structural attacks

Security properties such as chosen-plaintext and chosen-ciphertext security depend on how a block cipher is composed into an encryption mode or authenticated-encryption construction.

Future AEAD research will therefore separately evaluate:

* Confidentiality
* Integrity
* Forgery resistance
* Nonce handling
* Misuse resistance
* Chosen-plaintext security
* Chosen-ciphertext security

Side-channel resistance is an implementation-level property and requires separate analysis.

---

# Post-Quantum Considerations

Herringfish is a **symmetric-key primitive** and is therefore fundamentally different from post-quantum public-key algorithms such as:

* ML-KEM
* ML-DSA
* SLH-DSA

Quantum computing is nevertheless relevant to symmetric cryptography.

For an idealized `n`-bit key, Grover's algorithm provides a quadratic reduction in generic exhaustive-search complexity, approximately:

```text
2^n → 2^(n/2)
```

A 256-bit key therefore provides a theoretical generic-search target corresponding to approximately 128 bits of quantum brute-force complexity under the simplified Grover model.

This **does not establish 128-bit post-quantum security for Herringfish**.

The actual quantum security of a concrete cipher would depend on the complete construction and any applicable quantum cryptanalytic techniques.

---

# Design Decisions

Herringfish Feistel ARX v0.2 is the current frozen research configuration.

## Primitive

A balanced Feistel network with two 64-bit halves.

## Block Size

The block size is:

```text
128 bits
```

The size was selected as a modern block-cipher research target.

## Key Size

The master key is:

```text
256 bits
```

The key size is a design parameter and does not by itself establish 256-bit security.

## Round Count

The v0.2 research configuration uses:

```text
16 rounds
```

The round count is a current design choice. Reduced-round analysis is being used to investigate diffusion, distinguishers, attacks, and potential security margin.

## Nonlinear Component

The round function uses an 8-bit S-box.

For v0.2, the S-box is frozen for evaluation and is specified as an affine-equivalent transformation of the AES S-box.

Current recorded parameters:

```text
S-box counter: 0
a:             0x11
b:             0x71
DDT maximum:   4
LAT maximum:   32
```

The exact mathematical transformation is defined by the v0.2 specification.

Component-level DDT and LAT properties do not establish security of the complete cipher.

## Diffusion

The round function uses XOR-based byte mixing to provide intra-round diffusion.

The diffusion layer is being evaluated through:

* Avalanche measurements
* Hamming-distance analysis
* Per-round diffusion analysis
* Statistical experiments
* Reduced-round analysis

Claims regarding complete-cipher diffusion remain subject to continued analysis.

## Key Schedule

The v0.2 key schedule uses the SHAKE256 extendable-output function with domain separation.

Conceptually:

```text
SHAKE256(
    HERRINGFISH-FEISTEL-KEY ||
    master_key
)
```

The v0.2 construction derives:

```text
1024 bits
```

of round-key material for 16 rounds.

The exact encoding, domain-separation string, byte ordering, and round-key extraction procedure are defined in the formal specification.

Preliminary statistical analysis of generated round-key material is used to search for obvious structural behavior. Such testing does not constitute a proof of key-schedule security.

---

# Development Principles

Herringfish follows several core principles.

## Security Before Performance

A fast insecure cipher is still insecure.

## Simplicity Before Complexity

Every component should have a clear mathematical and cryptographic justification.

## Measure Instead of Assume

Cryptographic properties should be tested experimentally whenever practical.

## Attack Our Own Design

The project actively searches for weaknesses rather than assuming that the construction is secure.

## Reproducibility

Experiments should be deterministic and reproducible whenever practical.

## Independent Verification

A future implementation should be possible without depending on the Rust reference implementation.

## Honest Negative Results

A successful attack, distinguisher, bias, or structural weakness is valuable research information.

---

# Reproducibility

Cryptanalytic experiments should record sufficient information for independent reproduction.

Where applicable, experiments should record:

* Herringfish version or Git tag
* Specification version
* Experiment parameters
* Number of samples
* Random seed
* Compiler version
* Operating system
* CPU architecture
* Relevant CPU features
* Cargo features
* Hardware configuration
* Execution time

Research results should distinguish between **observed experimental results** and **security conclusions**.

---

# Specification and Validation Status

| Component                        | Status                              |
| -------------------------------- | ----------------------------------- |
| Cipher construction              | Feistel ARX v0.2 research prototype |
| Specification                    | v0.2 draft                          |
| S-box                            | Frozen for v0.2 evaluation          |
| Key schedule                     | Implemented                         |
| Round function                   | Implemented                         |
| Reference implementation         | Implemented                         |
| Known-answer vectors             | Available                           |
| S-box DDT                        | Computed                            |
| S-box LAT                        | Computed                            |
| Avalanche analysis               | Preliminary                         |
| Full-cipher statistical analysis | Ongoing                             |
| Reduced-round analysis           | Ongoing                             |
| Reduced-round attack tooling     | Available                           |
| SIMD implementation              | Partial – AVX2 diffusion benchmark, example gated for x86_64 |
| Performance benchmarks           | Preliminary – S-box CT, AVX2 diffusion |

| AEAD construction                | Not implemented                     |
| Independent cryptanalysis        | Not yet performed                   |
| Production use                   | **Not recommended**                 |

---

# Current Status

**Status: Experimental / Research — Herringfish Feistel ARX v0.2.2**

The current v0.2 configuration is frozen for cryptographic evaluation while analysis continues. Tag `v0.2.2` is the latest release.

Current S-box evaluation parameters:

```text
S-box counter: 0
a:             0x11
b:             0x71
DDT maximum:   4
LAT maximum:   32
```

Current research status:

* [x] Feistel ARX v0.2 construction
* [x] 128-bit block design
* [x] 256-bit master-key design
* [x] 16-round configuration
* [x] SHAKE256-derived key schedule
* [x] Round function
* [x] 8-bit nonlinear S-box
* [x] XOR-based diffusion layer
* [x] Reference implementation — `src/cipher/feistel_arx.rs`
* [x] Known-answer test vectors — `docs/tables/kat_vectors_v02.txt`
* [x] S-box DDT computation
* [x] S-box LAT computation
* [x] Preliminary linear analysis
* [x] Preliminary avalanche analysis
* [x] Reduced-round evaluation
* [x] Reduced-round attack tooling
* [x] Constant-time S-box implementation – `src/cipher/sbox_ct.rs`
* [x] Key-schedule independence tests – formalised with 100k samples
* [x] Meet-in-the-middle hull analysis tooling
* Formal specification — v0.2 draft
* [~] Full-cipher statistical analysis
* [~] Full-cipher cryptanalysis
* [~] SIMD implementation – partial: AVX2 diffusion benchmark exists, S-box gather/bitslicing
* [~] Performance benchmarks – preliminary: S-box CT, AVX2 diffusion; systematic benchmarking suite pending

* [ ] AEAD construction
* [ ] Independent cryptanalysis
* [ ] Independent implementation
* [ ] Public security review

The `[~]` state indicates work that is actively being developed or evaluated.

---

# Research Status

A successful implementation of Herringfish does **not** imply that Herringfish is cryptographically secure.

Likewise:

* Passing unit tests does not establish security.
* Passing known-answer tests does not establish security.
* Good avalanche behavior does not establish security.
* Random-looking statistical output does not establish security.
* Strong S-box DDT/LAT properties do not establish full-cipher security.
* Reduced-round resistance does not establish full-round security.
* A 256-bit key does not automatically provide 256-bit security.
* Avoiding obvious timing leaks does not establish complete side-channel resistance.

New cryptographic algorithms frequently contain weaknesses that are not apparent during initial development.

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
Public Review
   ↓
Revision
   ↓
Independent Analysis
   ↓
Specification Freeze
```

**Current phase:** Prototype → Testing → Cryptanalysis. Reduced-round evaluation and hull analysis are active; formal specification and public review are pending.

Herringfish should not be considered mature merely because it passes its own test suite.

---

# Contributing

Contributions involving cryptographic analysis are especially valuable.

Useful contributions include:

* Cryptanalytic attacks
* Differential characteristics
* Linear approximations
* Statistical analysis
* Reduced-round analysis
* Key-schedule analysis
* Mathematical analysis
* Performance research
* SIMD implementations
* Independent implementations
* Test vectors
* Reproducible experiments
* Documentation

### Reporting Weaknesses

If you identify a weakness in Herringfish, please document:

* The affected version
* The affected component
* Attack assumptions
* Required resources
* Number of rounds affected
* Complexity
* Memory requirements
* Success probability
* Reproduction steps
* Any available proof or experimental evidence

A weakness is considered a **successful research result**, not a failure of the project.

---

# Disclaimer

Herringfish is experimental cryptographic research software.

It has not been subjected to the level of public scrutiny, peer review, formal analysis, or independent cryptanalysis required to establish confidence in a production cryptographic algorithm.

**Do not use Herringfish to protect real-world data.**

The project is intended for:

* Cryptographic research
* Experimentation
* Education
* Benchmarking
* Cryptanalysis
* Algorithm development
* Reproducible security research

For production cryptography, use established and independently analyzed algorithms and constructions appropriate to the application.

---

# License

Herringfish is released under the MIT License.

Copyright © 2026.

See [`LICENSE`](LICENSE) for the complete license text.

---

## Herringfish

**Design it. Implement it. Test it. Break it. Improve it.**
