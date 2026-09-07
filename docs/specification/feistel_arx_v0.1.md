# Herringfish Feistel ARX Prototype v0.1

**Status:** Experimental research prototype
**Version:** 0.1
**Primitive:** Symmetric-key block cipher
**Construction:** Feistel network with ARX round function
**Security status:** Unvalidated / Experimental

---

## 1. Overview

Herringfish Feistel ARX v0.1 is an experimental 128-bit block cipher based on a balanced Feistel network.

The construction combines:

* A 128-bit block divided into two 64-bit halves.
* A 256-bit master key.
* 16 Feistel rounds.
* An ARX-based round function.
* SHAKE256-derived round keys.
* Domain separation for key derivation.

The purpose of this prototype is to provide a concrete construction for cryptanalytic experimentation.

This version is **not intended for production cryptographic use**.

The design should be evaluated through differential, linear, statistical, related-key, and structural analysis before any security claims are made.

---

# 2. Parameters

| Parameter             |                           Value |
| --------------------- | ------------------------------: |
| Cipher family         |                         Feistel |
| Block size            |                        128 bits |
| Half-block size       |                         64 bits |
| Master key size       |                        256 bits |
| Number of rounds      |                              16 |
| Round function        |                             ARX |
| Key derivation        |                        SHAKE256 |
| Key-derivation domain |       `HERRINGFISH-FEISTEL-KEY` |
| Endianness            |        To be formally specified |
| Padding               | Not applicable to the primitive |

The cipher operates on a 128-bit block represented as two 64-bit words:

```text
B = L₀ || R₀
```

where:

* `L₀` is the 64-bit left half.
* `R₀` is the 64-bit right half.

---

# 3. Notation

The following notation is used throughout this specification.

| Notation    | Meaning                                   |   |               |
| ----------- | ----------------------------------------- | - | ------------- |
| `⊕`         | Bitwise XOR                               |   |               |
| `+`         | Addition modulo `2^64`                    |   |               |
| `ROTL_n(x)` | 64-bit left rotation of `x` by `n` bits   |   |               |
| `           |                                           | ` | Concatenation |
| `K`         | 256-bit master key                        |   |               |
| `K_i`       | Round key for round `i`                   |   |               |
| `L_i`       | Left 64-bit Feistel half after round `i`  |   |               |
| `R_i`       | Right 64-bit Feistel half after round `i` |   |               |

All arithmetic in the ARX function is performed modulo `2^64`.

---

# 4. Key Schedule

The 256-bit master key is expanded into the round-key material using SHAKE256.

The key-derivation function uses the domain-separation string:

```text
HERRINGFISH-FEISTEL-KEY
```

Conceptually:

```text
SHAKE256(
    domain_separator ||
    master_key
)
```

The resulting XOF output is divided into the required round-key material.

For 16 rounds, the construction requires:

```text
16 × 64 bits = 1024 bits
```

of round-key material.

Therefore, the prototype requires at least:

```text
128 bytes
```

of SHAKE256 output for the round keys.

The resulting values are:

```text
K₁, K₂, ..., K₁₆
```

where each `K_i` is 64 bits.

### Key Schedule Domain Separation

The literal domain string:

```text
HERRINGFISH-FEISTEL-KEY
```

is part of the v0.1 construction.

Future Herringfish constructions should use distinct domain-separated strings for different purposes, such as:

```text
HERRINGFISH-FEISTEL-KEY
HERRINGFISH-FEISTEL-CONST
HERRINGFISH-SBOX
HERRINGFISH-AEAD
```

if those components are introduced.

---

# 5. Round Function

The Herringfish v0.1 round function operates on a 64-bit state word `x` and a 64-bit round key `k`.

The function is defined as:

```text
t = x ⊕ k
t = t + ROTL₁₃(k)
t = ROTL₇(t)
t = t ⊕ ROTL₃(k)
t = t + x
t = ROTL₁₁(t)

F(x, k) = t
```

All additions are modulo `2^64`.

In mathematical notation:

```text
t₀ = x ⊕ k

t₁ = t₀ + ROTL₁₃(k)

t₂ = ROTL₇(t₁)

t₃ = t₂ ⊕ ROTL₃(k)

t₄ = t₃ + x

F(x,k) = ROTL₁₁(t₄)
```

The final assignment is intentional: the result of `ROTL₁₁(t)` forms the output of the round function.

---

# 6. Feistel Round

For round `i`, where:

```text
1 ≤ i ≤ 16
```

the Feistel transformation is:

```text
Lᵢ = Rᵢ₋₁

Rᵢ = Lᵢ₋₁ ⊕ F(Rᵢ₋₁, Kᵢ)
```

Therefore:

```text
(Lᵢ, Rᵢ)
=
(Rᵢ₋₁,
 Lᵢ₋₁ ⊕ F(Rᵢ₋₁, Kᵢ))
```

The Feistel structure guarantees that the transformation remains invertible provided that the round function itself is deterministic.

The round function does **not** need to be independently invertible.

---

# 7. Encryption

Encryption begins with:

```text
B = L₀ || R₀
```

The block is processed through 16 Feistel rounds:

```text
(L₀, R₀)
      │
      ▼
Round 1
      │
      ▼
Round 2
      │
     ...
      │
      ▼
Round 16
      │
      ▼
(L₁₆, R₁₆)
```

Unless otherwise specified, the v0.1 ciphertext representation is:

```text
C = L₁₆ || R₁₆
```

A future specification revision may introduce a final swap or whitening operation, but such a change would constitute a new cipher version.

---

# 8. Decryption

The Feistel structure permits decryption using the same round function with the round keys applied in reverse order.

Starting with:

```text
C = L₁₆ || R₁₆
```

the inverse rounds are performed using:

```text
K₁₆, K₁₅, ..., K₂, K₁
```

For each inverse round:

```text
Rᵢ₋₁ = Lᵢ

Lᵢ₋₁ = Rᵢ ⊕ F(Lᵢ, Kᵢ)
```

The implementation must satisfy:

```text
Decrypt(Encrypt(P, K), K) = P
```

for every valid 128-bit plaintext `P` and 256-bit key `K`.

---

# 9. Design Rationale

## 9.1 Feistel Structure

The Feistel architecture was selected because it provides a straightforward invertible block-cipher construction.

The round function does not need to be invertible, reducing implementation requirements while retaining reversible encryption.

The structure also provides a well-understood basis for cryptanalytic comparison with established Feistel ciphers.

---

## 9.2 ARX Round Function

The round function combines:

* XOR
* Modular addition
* Bit rotation

These operations form an ARX construction.

The intention is to provide:

* Nonlinear behavior through modular addition.
* Bit diffusion through rotations.
* Efficient implementation on general-purpose processors.
* Good compatibility with SIMD-oriented implementations.
* Avoidance of traditional lookup-table S-boxes in the core round function.

The cryptographic effectiveness of this combination remains an open research question.

---

## 9.3 SHAKE256 Key Derivation

SHAKE256 is used to derive round-key material from the 256-bit master key.

The rationale is to provide a deterministic expansion mechanism with a large output domain while separating key derivation from the round function.

The SHAKE-derived schedule must itself be analyzed for:

* Related-key properties.
* Key diffusion.
* Statistical properties.
* Repeated or correlated round keys.
* Potential structural weaknesses.
* Interactions between the key schedule and the ARX round function.

Using SHAKE256 does **not** automatically make the resulting cipher secure.

---

# 10. Known-Answer Test

The initial prototype includes the following known-answer test.

### Input

**Key:**

```text
0000000000000000000000000000000000000000000000000000000000000000
```

**Plaintext:**

```text
00000000000000000000000000000000
```

**Expected ciphertext:**

```text
3d23bdc047f3bc60f483dbfc7627a4c2
```

This vector is designated:

```text
HERRINGFISH-FEISTEL-ARX-V0.1-KAT-0001
```

The test vector must be treated as normative for the v0.1 implementation.

If an implementation produces a different ciphertext, at least one of the following must be investigated:

* Key parsing
* Endianness
* SHAKE input construction
* SHAKE output extraction
* Round-key ordering
* Feistel ordering
* Rotation implementation
* Modular addition
* Final block serialization
* Implementation error

---

# 11. Security Analysis Plan

The v0.1 construction is intentionally considered an **unproven experimental cipher**.

The first analysis phase should investigate:

## 11.1 Avalanche Analysis

Measure the effect of changing:

* One plaintext bit.
* One key bit.
* Multiple plaintext bits.
* Multiple key bits.

Measure diffusion after every round.

The expected behavior is rapid propagation of changes through the state.

---

## 11.2 Differential Analysis

Analyze reduced-round versions first.

Investigate:

* Difference propagation.
* Differential probabilities.
* High-probability characteristics.
* Differential trails.
* Differential distribution behavior.
* Whether useful characteristics survive many rounds.

The initial targets should include:

```text
1–4 rounds
5–8 rounds
9–12 rounds
13–16 rounds
```

rather than immediately assuming the full 16-round construction is secure.

---

## 11.3 Linear Analysis

Investigate:

* Linear approximations.
* Correlations.
* Bias propagation.
* Reduced-round linear characteristics.
* Potential linear hull effects.

---

## 11.4 Related-Key Analysis

The SHAKE-derived key schedule must be analyzed independently.

Important questions include:

* Can related master keys produce useful relationships between round keys?
* Does a one-bit master-key difference rapidly affect all round keys?
* Are there structural relationships between consecutive round keys?
* Does SHAKE output introduce exploitable relationships?

---

## 11.5 Structural Analysis

Investigate:

* Weak keys.
* Equivalent keys.
* Fixed points.
* Symmetries.
* Complementation properties.
* Slide attacks.
* Invariant structures.
* Rotational properties.
* Differential properties caused by ARX operations.

---

# 12. Security Margin

The 16-round configuration should not be considered secure merely because no immediate attack is known.

The primary objective is to determine the security margin:

```text
Rounds broken by best known attack
                  │
                  ▼
             Security gap
                  │
                  ▼
              16 rounds
```

For example, if a practical attack reaches 12 rounds, the remaining four-round margin may be insufficient.

Conversely, if the best known attack reaches only 6 rounds, the construction may have a substantially larger margin.

The actual significance must be determined through cryptanalytic analysis.

---

# 13. Comparison Prototype

Herringfish Feistel ARX v0.1 should eventually be compared against alternative constructions.

A proposed comparison candidate is an SPN-based Herringfish prototype.

The comparison should consider:

| Property                | Feistel ARX    | SPN Prototype  |
| ----------------------- | -------------- | -------------- |
| Block size              | 128-bit        | TBD            |
| Key size                | 256-bit        | TBD            |
| Nonlinearity            | ARX            | TBD            |
| Diffusion               | Feistel + ARX  | TBD            |
| Key schedule            | SHAKE256       | TBD            |
| SIMD suitability        | To be measured | To be measured |
| Differential resistance | To be analyzed | To be analyzed |
| Linear resistance       | To be analyzed | To be analyzed |
| Performance             | To be measured | To be measured |
| Security margin         | TBD            | TBD            |

The comparison should be based on measured cryptographic properties rather than subjective preference.

---

# 14. Next Research Steps

The immediate research roadmap is:

1. Implement the v0.1 reference construction.
2. Verify the known-answer test.
3. Implement independent encryption/decryption round-trip tests.
4. Verify SHAKE256 key expansion independently.
5. Generate large sets of ciphertext samples.
6. Measure avalanche behavior after every round.
7. Measure diffusion and bit independence.
8. Perform reduced-round differential analysis.
9. Perform reduced-round linear analysis.
10. Analyze the SHAKE-derived key schedule.
11. Search for weak or related keys.
12. Benchmark the scalar implementation.
13. Investigate SIMD implementations.
14. Develop an SPN comparison prototype.
15. Compare the cryptanalytic security margins.

---

# 15. Versioning

Herringfish prototypes use semantic research versions.

For example:

```text
Herringfish Feistel ARX v0.1
Herringfish Feistel ARX v0.2
Herringfish Feistel ARX v0.3
```

A change to any cryptographically significant parameter constitutes a new prototype version.

Examples include:

* Round count.
* Block size.
* Key size.
* Round function.
* Rotation constants.
* Key schedule.
* Domain separation.
* State representation.
* Final transformation.

Known-answer tests must be version-specific.

---

# 16. Security Disclaimer

Herringfish Feistel ARX v0.1 is an experimental cryptographic construction.

Passing the known-answer test, demonstrating good avalanche behavior, or producing statistically random-looking ciphertext does **not** establish cryptographic security.

The construction has not undergone sufficient independent cryptanalysis to justify production use.

The prototype is intended for:

* Cryptographic research.
* Algorithm design.
* Cryptanalysis.
* Benchmarking.
* Educational experimentation.
* Implementation testing.

It must not be used to protect real-world secrets.

---

# 17. Research Objective

The purpose of Herringfish Feistel ARX v0.1 is not to demonstrate that a new cipher can be made to work.

The purpose is to determine **how well the construction survives attempts to break it**.

The central research loop is:

```text
Design
  ↓
Implement
  ↓
Test
  ↓
Measure
  ↓
Attack
  ↓
Analyze
  ↓
Revise
  ↓
Attack again
```

A successful attack is therefore a useful result.

The ultimate objective is to develop a cipher whose security properties are supported by substantial analysis rather than assumption.

> **Design it. Implement it. Test it. Break it. Improve it.**
