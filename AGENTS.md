# AGENTS.md — Herringfish

## Project Overview

Herringfish is an **experimental symmetric-key cryptography research project** written primarily in Rust.

The project exists to design, implement, test, benchmark, and **attack our own cryptographic constructions**.

The governing principle is:

> **Design it. Implement it. Test it. Break it. Improve it.**

Herringfish is research software, not production cryptography. A successful attack, distinguisher, bias, structural weakness, or failed design hypothesis is a valuable research result.

Never describe experimental results as proof of security.

---

# 1. Core Development Philosophy

Agents working on this repository must follow these principles:

### Security before performance

Do not optimize an implementation at the expense of making the mathematical construction harder to understand or validate.

### Mathematical correctness before software elegance

The cipher should first be understood as a mathematical construction.

When changing cryptographic behavior:

1. Define the mathematical change.
2. Update the specification.
3. Update the reference implementation.
4. Update tests and vectors.
5. Update cryptanalysis tooling.
6. Benchmark only after correctness is established.

### Measure instead of assume

Do not infer cryptographic security from:

* good avalanche scores
* random-looking output
* passing statistical tests
* strong S-box DDT/LAT values
* high performance
* successful round-trip tests

These are useful measurements, not security proofs.

### Attack our own design

Assume that weaknesses may exist.

When investigating a construction, actively attempt to find:

* differential trails
* linear approximations
* integral properties
* impossible differentials
* meet-in-the-middle attacks
* algebraic structure
* structural distinguishers
* related-key weaknesses
* weak diffusion
* weak key-schedule behavior
* unexpected invariant or symmetry
* reduced-round attacks
* implementation-level side channels

Do not alter an experiment merely to make the cipher look stronger.

### Reproducibility

Cryptographic experiments must be reproducible whenever practical.

Record:

* Git commit/tag
* specification version
* parameters
* random seed
* number of samples
* compiler version
* operating system
* CPU architecture
* relevant CPU features
* Cargo features
* hardware configuration
* execution time

Separate **observed results** from **interpretation** and from **security claims**.

---

# 2. Current Main Construction

The current main construction is:

**Herringfish Feistel ARX v0.2**

Current research parameters:

* Block size: 128 bits
* Master key: 256 bits
* Feistel structure: balanced
* Feistel halves: 64 bits
* Rounds: 16
* Nonlinear component: 8-bit S-box
* Diffusion: XOR-based byte mixing
* Key schedule: SHAKE256 XOF with domain separation
* Reference implementation: Rust

The formal specification is the authoritative source for exact mathematical behavior.

Primary locations:

```text
docs/specification/feistel_arx_v0.2.md
src/cipher/feistel_arx.rs
```

Do not silently change the construction while claiming compatibility with v0.2.

If a change affects the cipher definition, treat it as a construction/specification change rather than an implementation refactor.

---

# 3. Important Distinction: Construction vs Implementation

Always distinguish between:

```text
cryptographic construction
        ↓
mathematical specification
        ↓
reference implementation
        ↓
optimized implementations
        ↓
cryptanalysis tooling
```

The reference implementation is not the definition of the cipher.

The mathematical specification is authoritative.

If implementation and specification disagree:

**stop and investigate the discrepancy.**

Do not simply modify tests to match the implementation.

---

# 4. Repository Organization

The repository currently centers around:

```text
src/
├── cipher/
│   ├── mod.rs
│   └── feistel_arx.rs
├── cryptanalysis/
├── math/
├── simd/
└── lib.rs

tests/
└── vectors/

benchmarks/
examples/

docs/
├── specification/
└── tables/
```

The structure may evolve as cryptanalysis and alternative constructions are added.

Follow the existing organization rather than introducing new top-level directories without a clear reason.

---

# 5. Specifications Are Normative

When modifying cryptographic behavior:

1. Update the relevant specification.
2. Explicitly document serialization and byte ordering.
3. Define exact arithmetic and bit operations.
4. Define round ordering.
5. Define endianness.
6. Define key derivation and round-key extraction.
7. Define inversion/decryption behavior.
8. Update known-answer vectors.
9. Update the implementation.
10. Add regression tests.

Avoid ambiguous prose such as:

> "mix the bytes"

Prefer an exact mathematical definition.

Every transformation should be implementable independently from the specification.

---

# 6. Serialization and Test Vectors

Stable versions must use deterministic test vectors.

A standard block-cipher vector consists of:

```text
Key
Plaintext
Ciphertext
```

Current v0.2 vectors are located at:

```text
docs/tables/kat_vectors_v02.txt
```

Never regenerate vectors merely because an implementation changed.

First determine whether:

* the implementation is wrong,
* the specification is wrong,
* or the construction intentionally changed.

If the construction changes, version the construction appropriately.

---

# 7. Reference Implementation Rules

The reference implementation should prioritize:

* clarity
* correctness
* portability
* deterministic behavior
* easy independent verification

Avoid prematurely introducing architecture-specific optimizations into the reference implementation.

Optimized implementations must produce **bit-for-bit identical results** to the reference implementation.

This applies to:

* scalar implementations
* AVX2
* AVX-512
* ARM/NEON
* GPU implementations
* future implementations

---

# 8. Cryptanalysis Is a First-Class Component

Cryptanalysis is not an optional feature of the project.

It is one of the primary purposes of the repository.

When implementing an attack, distinguish clearly between:

```text
component property
reduced-round result
full-round result
distinguisher
key-recovery attack
generic attack
practical attack
theoretical attack
```

Do not describe an attack against a component as an attack against the full cipher.

For example:

> DDT max = 4

does **not** imply that the complete cipher is resistant to differential cryptanalysis.

Likewise:

> 1,000,000 samples showed good avalanche behavior

does **not** establish cryptographic security.

---

# 9. Differential Cryptanalysis

Differential work may include:

* DDT computation
* differential probabilities
* characteristics
* trails
* reduced-round searches
* high-probability trails
* distinguishers
* key-dependent differential behavior

When implementing differential tooling:

* define the difference operator explicitly
* document state representation
* document byte order
* document round boundaries
* make reduced-round counts explicit
* provide deterministic test cases
* record computational complexity

Avoid calling an observed characteristic an "attack" until it actually provides a meaningful cryptanalytic advantage.

---

# 10. Linear Cryptanalysis

Linear analysis may include:

* LAT generation
* linear biases
* approximations
* characteristics
* reduced-round attacks
* bias propagation
* distinguishers

Always distinguish:

```text
S-box LAT property
```

from:

```text
full-cipher linear resistance
```

---

# 11. Meet-in-the-Middle / MITM Research

Meet-in-the-middle research is allowed and encouraged when structurally applicable.

For MITM experiments:

* define exactly what state is being matched
* document the split point
* define the forward and backward computations
* distinguish time complexity from memory complexity
* account for false positives
* verify recovered candidates against independent plaintext/ciphertext pairs
* use deterministic test cases wherever possible

When exploring huge search spaces, first investigate reductions from:

* symmetry
* partial-state matching
* differential constraints
* key equivalence
* invariant bits
* meet points
* algebraic constraints
* independent verification

Do not assume an attack is practical simply because the search space is smaller than exhaustive key search.

Report actual estimated work factors.

---

# 12. Reduced-Round Variants

Reduced-round versions are valuable research tools.

Common analysis targets include:

```text
1 round
2 rounds
3 rounds
...
14 rounds
15 rounds
16 rounds
```

When creating reduced-round tooling:

* keep the round parameter explicit
* never silently substitute reduced rounds for the full construction
* label output with the round count
* avoid extrapolating reduced-round security directly to the full cipher

A break at 4 rounds is useful research.

A failure to break 12 rounds is not evidence that 16 rounds is secure.

---

# 13. S-Box Work

The v0.2 S-box is frozen for evaluation.

Current recorded parameters include:

```text
S-box counter: 0
a:             0x11
b:             0x71
DDT maximum:   4
LAT maximum:   32
```

The exact mathematical definition is governed by the specification.

Do not replace or mutate the v0.2 S-box in-place during experiments that are supposed to measure v0.2.

For alternative S-box experiments:

* create an explicit experimental variant
* record parameters
* preserve the original construction
* label all measurements with the variant

---

# 14. Key Schedule

The v0.2 key schedule uses SHAKE256 with domain separation.

Conceptually:

```text
SHAKE256(
    HERRINGFISH-FEISTEL-KEY ||
    master_key
)
```

The construction derives 1024 bits of round-key material for 16 rounds.

Exact:

* encoding
* domain separation
* byte order
* extraction order

must follow the formal specification.

Do not replace the key schedule merely because another scheme appears statistically attractive.

Key-schedule modifications require dedicated cryptanalysis.

---

# 15. `solo-arx` Research Direction

The repository may contain experimental branches/variants that intentionally remove dependencies and simplify the construction.

The `solo-arx` work is an experimental direction intended to investigate a more self-contained ARX-based construction without the normal SHAKE/SHA3-derived machinery.

When working on `solo-arx`:

* do not assume v0.2 compatibility
* explicitly identify what was removed
* document all changed primitives
* maintain independent test vectors
* compare security properties against the baseline
* keep experimental results separate from v0.2 results

"no dependency" refers to the construction's research objective and should not be interpreted as "automatically secure" or "better".

The purpose of `solo-arx` is experimentation.

---

# 16. Determinism

Prefer deterministic experiments.

When randomness is required:

* expose the seed
* record the seed
* make the seed overrideable
* provide a known default for reproducibility where appropriate

A cryptanalytic result that cannot be reproduced is substantially less useful.

---

# 17. Testing Requirements

At minimum, cryptographic changes should consider:

### Unit tests

Test:

* S-box
* inverse S-box where applicable
* key schedule
* round function
* diffusion
* mixing functions
* encryption
* decryption

### Known-answer tests

Verify exact deterministic outputs.

### Round-trip tests

The fundamental property is:

```text
decrypt(encrypt(P, K), K) == P
```

for valid inputs.

### Differential tests

Compare:

* independent implementations
* reference implementation
* optimized implementation
* intermediate states when useful

### SIMD equivalence

Optimized implementations must exactly match the reference implementation.

### Regression tests

Any discovered bug or cryptanalytic observation that could regress should receive a dedicated test where practical.

---

# 18. Statistical Testing

Statistical experiments may investigate:

* output distributions
* bit frequencies
* correlations
* χ² statistics
* Hamming weights
* serial correlations
* avalanche
* SAC
* bit independence
* per-round diffusion

Statistical testing detects certain classes of obvious problems.

It does not prove security.

Always state the tested construction and sample count.

---

# 19. Side-Channel Awareness

Implementations intended to be constant-time must be treated carefully.

Particular attention is required for:

* secret-dependent memory accesses
* lookup tables
* S-box indexing
* branches depending on secret data
* compiler transformations
* architecture-specific behavior

An implementation that "looks constant-time" is not automatically constant-time.

When practical, combine source review with appropriate measurement/testing.

Do not make unqualified claims such as:

> "This implementation is side-channel safe."

Prefer:

> "This implementation avoids secret-dependent branches in the reviewed code path; additional side-channel analysis is still required."

---

# 20. SIMD and Hardware Acceleration

Hardware acceleration is useful for:

* performance
* statistical experiments
* brute-force experiments
* cryptanalytic search
* attack frameworks

Potential targets include:

* AVX2
* AVX-512
* ARM NEON
* other relevant SIMD architectures
* GPU acceleration

GPU code is primarily a research/acceleration tool.

Never replace the portable reference implementation with a hardware-specific implementation.

---

# 21. Benchmarking

Benchmarking is an engineering measurement, not a security measurement.

Measure separately where appropriate:

* encryption throughput
* decryption throughput
* key setup
* key-schedule cost
* small-message performance
* bulk throughput
* SIMD speedup
* CPU scaling
* GPU acceleration

Benchmarks should identify:

* compiler
* optimization level
* CPU
* architecture
* CPU features
* Cargo features
* implementation variant

Do not compare benchmark numbers obtained from materially different environments without identifying the differences.

---

# 22. Dependencies

The project is fundamentally cryptographic research code.

Before introducing a dependency:

* determine whether it is actually needed
* consider whether it affects portability
* consider whether it hides important mathematical behavior
* document why it is required
* avoid unnecessary dependencies in experimental low-level primitives

For "no dependency" experimental branches, preserve that property unless there is a compelling research reason to change it.

---

# 23. Cargo / Rust Workflow

Use standard Cargo tooling unless the repository documents a more specific workflow.

Typical commands:

```bash
cargo check
cargo test
cargo test --all-features
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

For examples:

```bash
cargo run --example <name>
```

For benchmarks, use the repository's established benchmark workflow.

Do not skip tests because a change appears mathematically obvious.

---

# 24. Documentation Changes

Any cryptographic behavior change should update documentation.

At minimum consider:

* formal specification
* README
* test vectors
* experiment documentation
* attack documentation
* benchmark documentation

Documentation should distinguish:

```text
implemented
tested
measured
hypothesized
not yet tested
broken
```

Never turn a hypothesis into a fact simply by writing it in documentation.

---

# 25. Research Notes and Negative Results

Keep negative results.

Do not remove an experiment merely because it failed.

Useful results include:

* attack failed
* attack complexity was too high
* characteristic probability was too low
* diffusion was stronger than expected
* a proposed optimization provided no benefit
* a candidate attack produced false positives
* a construction was weaker than expected

Negative results help establish the research history and avoid repeating experiments.

---

# 26. Versioning Experimental Constructions

When a modification changes the cryptographic primitive:

Do not hide it behind a normal refactor.

Clearly identify it as one of:

* implementation bug fix
* specification clarification
* compatible optimization
* experimental variant
* construction change
* new cipher version

If ciphertext compatibility changes, treat that as a cryptographic compatibility break.

---

# 27. Commit and Change Discipline

Prefer small, logically isolated commits.

Examples:

```text
fix reference diffusion implementation
add reduced-round differential test
add MITM state matcher
document v0.2 serialization
add AVX2 equivalence test
record statistical experiment
```

Avoid commits that mix:

```text
cipher redesign
formatting
benchmark changes
unrelated cleanup
```

unless there is a compelling reason.

For cryptographic code, reviewability matters.

---

# 28. Agent Rules for Cryptographic Changes

Before changing a cryptographic primitive, an agent should answer internally:

1. What mathematical object is changing?
2. Is the formal specification affected?
3. Are the known-answer vectors affected?
4. Is backward compatibility affected?
5. Which tests prove implementation correctness?
6. Which experiments evaluate the cryptographic consequences?
7. Does the change alter the attack surface?
8. Is the result being measured or merely assumed?

If these questions cannot be answered, do not present the change as cryptographically validated.

---

# 29. Working With Experiments

Every substantial experiment should have a clear identity.

Prefer a structure such as:

```text
Experiment:
Construction:
Version:
Round count:
Parameters:
Input conditions:
Samples:
Seed:
Platform:
Compiler:
Result:
Interpretation:
Security significance:
```

Separate:

### Observation

What happened.

### Explanation

Why we currently think it happened.

### Security conclusion

What, if anything, the result actually demonstrates.

Do not collapse these into one statement.

---

# 30. Research Honesty

This project deliberately investigates an unproven cipher.

Therefore:

**Finding a weakness is not failure.**

A successful cryptanalytic attack may be one of the most valuable outcomes of the project.

Agents must never:

* conceal weaknesses
* tune tests to produce favorable results
* remove inconvenient data
* call statistical resemblance "security"
* call a benchmark "cryptographic strength"
* claim independent validation that has not occurred
* describe Herringfish as production-safe

Use precise language.

Prefer:

> "No attack was found within the tested bounds."

not:

> "The cipher is secure."

---

# 31. Production Safety

Herringfish is experimental.

Do not recommend it for protecting:

* passwords
* financial data
* authentication secrets
* production network traffic
* real-world sensitive information
* production encryption systems

For production cryptography, recommend established, independently analyzed constructions such as:

* AES-GCM
* ChaCha20-Poly1305

---

# 32. Final Review Checklist

Before completing a significant cryptographic change, verify:

```text
[ ] Mathematical behavior is clearly defined
[ ] Specification is updated if needed
[ ] Reference implementation is correct
[ ] Existing known-answer tests still have a clear status
[ ] New test vectors exist where required
[ ] Round-trip tests pass
[ ] Regression tests exist for fixed bugs
[ ] Optimized implementations match the reference
[ ] Cryptanalytic consequences were considered
[ ] Experimental results are reproducible
[ ] Seeds and parameters are recorded
[ ] Documentation distinguishes observations from conclusions
[ ] No unsupported security claim was introduced
```

---

# 33. Prime Directive

When uncertain, prioritize this order:

```text
Correct mathematics
        ↓
Correct specification
        ↓
Correct reference implementation
        ↓
Reproducible tests
        ↓
Cryptanalysis
        ↓
Independent verification
        ↓
Optimization
```

The goal is not to prove that Herringfish is good.

The goal is to determine **what Herringfish actually is**.

Design it.

Implement it.

Test it.

Break it.

Improve it.
