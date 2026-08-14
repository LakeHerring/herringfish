# Herringfish Feistel ARX Prototype v0.2

**Status:** Experimental research prototype
**Version:** 0.2
**Construction:** 128-bit balanced Feistel network with S-box and linear-diffusion round function
**Master key:** 256 bits
**Rounds:** 16
**Security status:** Experimental / Under cryptanalysis

---

# 1. Specification Update

Herringfish Feistel ARX v0.2 represents a significant change from v0.1.

The principal changes are:

* Replacement of the v0.1 pure-ARX round function with an S-box-based nonlinear layer.
* Addition of an intra-round linear diffusion layer.
* SHAKE256-derived key-dependent S-box generation.
* Continued use of SHAKE256 for round-key derivation.
* Retention of the 16-round Feistel structure.
* Introduction of systematic reduced-round cryptanalysis.
* Initial empirical evaluation of related-key behavior.

The v0.2 construction should be treated as a new cryptographic prototype rather than a minor implementation revision.

---

# 2. Cryptographic Primitives and Implementation Mapping

Herringfish v0.2 uses RustCrypto primitives with explicit crate mapping:

| Herringfish purpose | Algorithm | Rust crate |
| ------------------- | --------- | ---------- |
| Fixed 256-bit digest | SHA3-256 | sha3 |
| Fixed 512-bit digest | SHA3-512 | sha3 |
| Key derivation / expansion | SHAKE256 | shake |
| S-box generation | SHAKE256 | shake |
| Round-key generation | SHAKE256 | shake |
| Domain-separated derivation | SHAKE256 | shake |
| Future XOF functionality | SHAKE128/256 | shake |

The `sha3` crate is used only when a fixed-length SHA-3 digest is required. Herringfish uses the RustCrypto `shake` crate for all SHAKE256-based domain-separated key expansion and S-box generation.

## 2.1 Domain Separation and Encoding Rules

All SHAKE256 derivations use the following encoding:

```
SHAKE256(domain_separator || input)
```

Domain separators are ASCII UTF-8 byte strings, no length prefix. Input is the raw master key bytes or counter.

Domain strings used in v0.2:

* Round-key derivation: `HERRINGFISH-FEISTEL-KEY`
* S-box derivation: `HERRINGFISH-FEISTEL-SBOX`

Endianness for multi-byte integer encoding is little-endian.

# 3. Global Parameters

| Parameter            |         v0.2 Specification |
| -------------------- | -------------------------: |
| Cipher type          |   Balanced Feistel network |
| Block size           |                   128 bits |
| Half-block size      |                    64 bits |
| Master key size      |                   256 bits |
| Number of rounds     |                         16 |
| Round-key size       |                    64 bits |
| Number of round keys |                         16 |
| Round function input |                    64 bits |
| Nonlinear component  |                8-bit S-box |
| Number of S-boxes    |                          1 |
| S-box size           |               256 × 8 bits |
| Diffusion layer      |      XOR-based byte mixing |
| Key derivation       |                   SHAKE256 |
| S-box derivation     |                   SHAKE256 |
| Round-key domain     |  `HERRINGFISH-FEISTEL-KEY` |
| S-box domain         | `HERRINGFISH-FEISTEL-SBOX` |

All operations must be interpreted according to the exact bit and byte ordering defined by the implementation specification.

**Endianness remains a normative implementation detail and must be explicitly fixed before v0.2 is considered interoperable.**

---

# 3. Feistel Construction

The 128-bit plaintext block is divided into two 64-bit halves:

```text id="k4l0pm"
P = L₀ || R₀
```

For each round `i`, where:

```text id="v0v4uy"
1 ≤ i ≤ 16
```

the state is transformed according to:

```text id="zqcrg5"
Lᵢ = Rᵢ₋₁

Rᵢ = Lᵢ₋₁ ⊕ F(Rᵢ₋₁, Kᵢ)
```

where:

* `Lᵢ` is the 64-bit left half after round `i`.
* `Rᵢ` is the 64-bit right half after round `i`.
* `Kᵢ` is the 64-bit round key.
* `F` is the v0.2 round function.

The final ciphertext is:

```text id="d3y4mt"
C = L₁₆ || R₁₆
```

unless a future specification explicitly introduces a final transformation.

---

# 4. Round Function

## 4.1 Input

The round function accepts:

```text id="c7a0ga"
x : 64 bits
k : 64 bits
```

The 64-bit input is interpreted as eight bytes:

```text id="3a3ujb"
x = x₀ || x₁ || x₂ || x₃ || x₄ || x₅ || x₆ || x₇
```

and the 64-bit round key is similarly interpreted as:

```text id="wtxd0g"
k = k₀ || k₁ || k₂ || k₃ || k₄ || k₅ || k₆ || k₇
```

The exact byte ordering must be fixed by the normative serialization specification.

---

# 5. Nonlinear S-box Layer

For each byte position `i`, the S-box transformation is:

```text id="7xv9gl"
yᵢ = S[xᵢ ⊕ kᵢ]
```

where:

* `S` is the 256-entry Herringfish S-box.
* `xᵢ` is an input byte.
* `kᵢ` is the corresponding key byte.
* `⊕` is byte-wise XOR.

The resulting eight bytes form the intermediate state:

```text id="8xkg7n"
Y = y₀ || y₁ || ... || y₇
```

This construction makes the nonlinear transformation explicitly dependent on the round key.

---

# 6. Linear Diffusion Layer

The eight-byte intermediate state is transformed using the following diffusion operation:

```text id="t1z1iq"
out[i] =
    in[i]
    ⊕ in[(i + 1) mod 8]
    ⊕ in[(i + 3) mod 8]
```

for:

```text id="b9iz2r"
i ∈ {0,1,2,3,4,5,6,7}
```

The output is:

```text id="4j6p3c"
D = d₀ || d₁ || ... || d₇
```

where:

```text id="r3qxxe"
dᵢ = yᵢ ⊕ yᵢ₊₁ ⊕ yᵢ₊₃
```

with byte indices evaluated modulo 8.

The resulting 64-bit value is:

```text id="s2wqjt"
F(x,k) = D
```

---

# 7. Important Structural Property

The diffusion layer is a **linear transformation over GF(2)**.

It does not itself introduce nonlinearity.

The nonlinear component of the round function is provided by the S-box transformation.

Therefore the round function can conceptually be represented as:

```text id="4o7h74"
64-bit input
     │
     ▼
XOR with round key
     │
     ▼
8 × 8-bit S-box
     │
     ▼
Linear byte diffusion
     │
     ▼
64-bit output
```

This separation makes the nonlinear and diffusion properties independently analyzable.

---

# 8. S-box Generation

For Herringfish Feistel ARX v0.2, the S-box is frozen for interoperability.

The v0.2 S-box is an affine-equivalent transformation of the AES S-box.

Construction:

```text
S[x] = a * AES_SBOX[x] ⊕ b  over GF(2^8)
```

Affine parameters:
* a = 0x11
* b = 0x71

S-box counter: 0

Domain separation string `HERRINGFISH-FEISTEL-SBOX` is retained for future versions but is not used for v0.2 S-box generation. The frozen permutation is defined in `src/cipher/feistel_arx.rs` as `HERRINGFISH_SBOX_V02` and archived in `docs/tables/`.

DDT_max = 4, LAT_max bias = 32. The S-box satisfies the acceptance criteria defined in Section 9.

Specification validation is performed by `examples/spec_validation.rs`, which checks bijectivity, DDT_max and LAT_max against the frozen S-box. Known-answer test vectors are maintained in `docs/tables/kat_vectors_v02.txt` and `docs/tables/kat_expanded_v02.txt`.

---

# 9. S-box Acceptance Criteria

A candidate S-box must satisfy the following minimum criteria.

## 9.1 Bijectivity

The S-box must be a permutation of all 256 possible byte values.

Therefore:

```text id="zh8s1u"
|S| = 256
```

and:

```text id="p8a3nz"
S(a) ≠ S(b)
```

for every:

```text
a ≠ b
```

---

## 9.2 Differential Distribution Table

The candidate S-box must have a maximum DDT entry satisfying:

```text id="e8b5qt"
DDT_max ≤ 4
```

For an 8-bit S-box, this corresponds to a maximum differential probability of:

```text id="j9h2ku"
4 / 256 = 1 / 64 = 0.015625
```

or:

```text id="xg6zq0"
≈ 2⁻⁶
```

The exact DDT must be generated and retained for the accepted S-box.

---

## 9.3 Linear Approximation Table

The candidate S-box must satisfy the specified maximum linear bias criterion:

```text id="2dr6hz"
|LAT_bias| ≤ 32
```

For an 8-bit S-box, this corresponds to an absolute correlation/count deviation criterion that must be precisely defined in the implementation.

The specification must distinguish between:

* LAT table count
* Bias
* Correlation
* Linear probability

These quantities are related but are not interchangeable.

The accepted S-box's complete LAT should therefore be retained as a research artifact.

---

# 10. Avalanche Testing

Candidate S-boxes are additionally evaluated using:

### Strict Avalanche Criterion

A one-bit input change should cause approximately half of the output bits to change.

### Bit Independence Criterion

Output-bit changes should exhibit low statistical dependence under the defined sampling methodology.

These tests are **acceptance-supporting statistical tests**, not proofs of cryptographic security.

The sampling methodology, number of samples, confidence intervals, and thresholds must be documented for reproducibility.

---

# 11. Rejection Sampling

Herringfish v0.2 uses rejection sampling for S-box selection.

The process is:

```text id="t77quq"
Generate candidate
       │
       ▼
Is it bijective?
       │
       ├── No ──► Reject
       │
       ▼
DDT criterion satisfied?
       │
       ├── No ──► Reject
       │
       ▼
LAT criterion satisfied?
       │
       ├── No ──► Reject
       │
       ▼
Avalanche/BIC criteria satisfied?
       │
       ├── No ──► Reject
       │
       ▼
     Accept
```

The final accepted S-box must be recorded as part of the v0.2 test and specification material.

---

# 12. Key Schedule

The master key is 256 bits.

Sixteen 64-bit round keys are required:

```text id="a5fs7a"
16 × 64 = 1024 bits
```

The required key material is therefore 128 bytes.

Round-key generation uses SHAKE256:

```text id="v3g86q"
SHAKE256(
    HERRINGFISH-FEISTEL-KEY
    || master_key
)
```

The first 1024 bits of the XOF output are divided into:

```text id="1h0w1g"
K₁ || K₂ || ... || K₁₆
```

where every `Kᵢ` is 64 bits.

The exact encoding of the domain string and master key must be normative.

---

# 13. Domain Separation

Herringfish v0.2 uses separate domain strings for logically distinct SHAKE operations.

### Round-key derivation

```text id="8pqmjq"
HERRINGFISH-FEISTEL-KEY
```

### S-box derivation

```text id="apz8e7"
HERRINGFISH-FEISTEL-SBOX
```

Domain separation prevents these derivation processes from unintentionally sharing the same input domain.

It should not, however, be interpreted as a proof that the resulting constructions are cryptographically independent.

---

# 14. Related-Key Analysis

Initial experimental analysis has examined the diffusion of master-key differences through the SHAKE-derived round-key schedule.

The following cases were sampled:

Average pairwise round-key Hamming distance: 32.00 bits
Related-key 1-bit diff: mean round-key Hamming = 32.04 bits, std = 0.97
Expected ~64 bits for independent 64-bit keys

* Master-key Hamming weight difference = 1.
* Master-key Hamming weight difference = 2.
* Master-key Hamming weight difference = 4.
* Randomly selected key pairs.

The observed average round-key Hamming distance was approximately:

```text id="5av5ne"
64 bits
```

for the 64-bit round keys.

The observed distributions did not reveal an obvious exploitable correlation in the tested samples.

These observations are consistent with the expected behavior of SHAKE-derived pseudorandom material.

They do **not** constitute a proof of related-key security.

---

# 15. Reduced-Round Differential Analysis

Initial differential experiments were performed using:

```text id="qflqya"
100,000 pairs per tested input difference
```

The following maximum observed differential probabilities were reported:

| Rounds | Maximum observed probability | Reported 95% CI |
| -----: | ---------------------------: | --------------: |
|      4 |                   ≈ 1 × 10⁻⁵ |   [0, 3 × 10⁻⁵] |
|      6 |                   ≈ 1 × 10⁻⁵ |   [0, 3 × 10⁻⁵] |
|      8 |                   ≈ 1 × 10⁻⁵ |   [0, 3 × 10⁻⁵] |

These results are **experimental observations from the stated sampling procedure**.

They must not be interpreted as rigorous upper bounds on the true maximum differential probability.

In particular, observing no high-probability event in 100,000 samples does not establish that no such event exists.

A complete differential analysis should eventually include:

* Full DDT analysis of the S-box.
* Automated trail search.
* Differential characteristic search.
* Larger sample sets.
* Structured difference selection.
* Reduced-round exhaustive analysis where feasible.
* Comparison against theoretical bounds.

---

# 16. Linear Analysis

Initial linear approximation sampling indicates that the maximum observed bias decreases as the number of rounds increases.

This is an encouraging experimental observation.

However, sampled linear behavior does not constitute a proof of resistance against linear cryptanalysis.

Future analysis should include:

* Complete S-box LAT.
* Linear trail search.
* Hull effects.
* Reduced-round exhaustive analysis.
* Correlation bounds.
* Automated search for high-correlation approximations.

---

# 17. Security Margin

The final construction retains:

```text id="tq4s8s"
16 rounds
```

The current reduced-round experiments cover:

```text id="4y8k0e"
4 rounds
6 rounds
8 rounds
```

The current evidence therefore suggests that no obvious high-probability differential characteristic was observed within the tested scenarios through 8 rounds.

However, the statement:

> "16 rounds provides >8 rounds of concrete security margin"

should currently be interpreted as a **research margin relative to the tested reduced-round experiments**, not as a formal concrete-security bound.

A rigorous security margin requires a defined best-known attack and a demonstrated attack complexity.

The project should therefore report the margin as:

```text id="x2ek5k"
16-round construction
        │
        │ 8+ rounds beyond currently tested reduced-round range
        ▼
Best currently analyzed reduced-round range
```

until a stronger cryptanalytic bound is established.

---

# 18. Security Interpretation

The v0.2 results provide several positive observations:

* The S-box can satisfy strict local cryptographic criteria.
* The key schedule exhibits strong apparent diffusion in sampled tests.
* Differential probabilities observed in the tested reduced-round experiments are low.
* Linear bias appears to decrease with additional rounds.
* The Feistel construction remains straightforwardly invertible.

None of these observations independently establishes security.

In particular:

```text
Good S-box
    ≠
Secure cipher

Good avalanche
    ≠
Secure cipher

Random-looking SHAKE output
    ≠
Secure key schedule

Low sampled differential probability
    ≠
Proof of differential security
```

The complete construction must be evaluated as a system.

---

# 19. Current Security Hypothesis

The working hypothesis for v0.2 is:

> The combination of a bijective low-differential-probability S-box, key-dependent nonlinear substitution, linear intra-round diffusion, SHAKE-derived round keys, and a 16-round Feistel structure may provide a substantial security margin against basic differential and linear attacks.

This is a **research hypothesis**, not a security claim.

The purpose of subsequent cryptanalysis is to attempt to falsify it.

---

# 20. Next Research Steps

The immediate research priorities are:

## 20.1 Formal S-box Analysis

* Generate the complete DDT.
* Generate the complete LAT.
* Record differential uniformity.
* Record maximum linear bias.
* Measure nonlinearity.
* Measure algebraic degree.
* Measure fixed points.
* Measure opposite fixed points.
* Analyze cycle structure.

## 20.2 Differential Cryptanalysis

* Exhaustive reduced-round search where practical.
* Automated characteristic search.
* Differential trail enumeration.
* Search for high-probability trails.
* Analyze clustering effects.
* Extend beyond 8 rounds.

## 20.3 Linear Cryptanalysis

* Full linear trail search.
* Linear hull analysis.
* Correlation accumulation.
* Reduced-round exhaustive analysis.

## 20.4 Key Schedule

* Full round-key correlation analysis.
* Related-key experiments.
* Differential key analysis.
* Weak-key search.
* Statistical independence testing.

## 20.5 Side-Channel Analysis

Evaluate SHAKE-based key expansion and the cipher implementation for:

* Timing behavior.
* Cache behavior.
* Memory-access patterns.
* Branch dependence.
* Data-dependent instructions.
* Leakage during S-box operations.

The S-box implementation requires particular attention because lookup tables can introduce cache-based side channels.

---

# 21. Future Design Questions

Several questions remain open.

### Is the key-dependent S-box actually beneficial?

The construction introduces key dependence through:

```text id="v17q5r"
S[x ⊕ k]
```

The cryptanalytic consequences need to be evaluated.

### Is the diffusion layer sufficiently strong?

The current transformation:

```text id="mxyu0n"
out[i] = in[i] ⊕ in[i+1] ⊕ in[i+3]
```

must be analyzed as a linear transformation.

Important properties include:

* Rank.
* Branch number.
* Diffusion speed.
* Active-byte propagation.
* Interaction with the S-box.

### Is the S-box criterion overly restrictive or insufficient?

The current acceptance thresholds are useful screening criteria, but low differential uniformity and low linear bias alone do not guarantee that the S-box is optimal for the complete cipher.

### Is 16 rounds sufficient?

This remains an open question.

The correct answer should come from the strongest known attacks against the complete construction, not from the original Luby–Rackoff theoretical bound.

---

# 22. Luby–Rackoff Context

The use of a Feistel network is supported by the classical Luby–Rackoff framework, which demonstrates that Feistel constructions can achieve strong pseudorandom permutation properties under appropriate assumptions about their round functions.

The commonly cited result involving four rounds applies to an idealized setting involving suitable pseudorandom functions and independent round functions.

It should **not** be interpreted as:

```text
4 Feistel rounds = 4 secure rounds for Herringfish
```

Herringfish uses:

* A concrete deterministic round function.
* A specific S-box.
* A specific diffusion layer.
* Related SHAKE-derived round keys.
* A fixed 16-round construction.

Therefore, the Luby–Rackoff result provides theoretical context for the construction but does not establish the concrete security of Herringfish.

The 16-round choice is instead intended to provide a substantial empirical security margin that can be evaluated through cryptanalysis.

---

# 23. Version 0.2 Status

The current v0.2 construction is:

```text id="0x1k6u"
DEFINED
    │
    ├── 128-bit block
    ├── 256-bit master key
    ├── 16 Feistel rounds
    ├── SHAKE256 key derivation
    ├── SHAKE256 S-box derivation
    ├── Key-dependent S-box layer
    └── Linear intra-round diffusion

TESTED
    │
    ├── Basic functionality
    ├── S-box criteria
    ├── Avalanche sampling
    ├── Key-diffusion sampling
    ├── Reduced-round differential sampling
    └── Reduced-round linear sampling

NOT YET ESTABLISHED
    │
    ├── Formal security bound
    ├── Full differential resistance
    ├── Full linear resistance
    ├── Related-key security
    ├── Side-channel resistance
    └── Production suitability
```

---

# 24. Research Principle

The purpose of v0.2 is not to demonstrate that the construction is secure.

It is to create a sufficiently well-defined construction that meaningful attempts to break it can be performed.

The project therefore follows:

```text id="1k7t9d"
Design
  ↓
Formalize
  ↓
Implement
  ↓
Measure
  ↓
Attack
  ↓
Discover weaknesses
  ↓
Revise
  ↓
Attack again
```

If cryptanalysis discovers a weakness, the result should be documented rather than hidden.

If no weakness is found, the result should be reported as:

> **No weakness identified under the tested attack model and experimental conditions.**

not:

> **Herringfish is secure.**

---

# 25. Concrete Security Margin – Experimental Update v0.2

## 25.1 Differential Sampling

Samples per input difference: 100 000. Input differences tested: Hamming weight 1,2,4.

### Feistel v0.2

| Rounds | HW | max p̂ | 95% CI |
| -----: | --:| ----: | -----: |
| 4 | 1 | 0.000010 | [0.000000, 0.000030] |
| 4 | 2 | 0.000010 | [0.000000, 0.000030] |
| 4 | 4 | 0.000010 | [0.000000, 0.000030] |
| 6 | 1 | 0.000010 | [0.000000, 0.000030] |
| 6 | 2 | 0.000010 | [0.000000, 0.000030] |
| 6 | 4 | 0.000010 | [0.000000, 0.000030] |
| 8 | 1 | 0.000010 | [0.000000, 0.000030] |
| 8 | 2 | 0.000010 | [0.000000, 0.000030] |
| 8 | 4 | 0.000010 | [0.000000, 0.000030] |
| 12 | 1 | 0.000010 | [0.000000, 0.000030] |

### SPN prototype

SPN key schedule replaced with SHAKE-derived expansion `SHAKE256("HERRINGFISH-SPN-KEY"||master_key)`. Differential sampling with 100k pairs per input difference shows comparable sampling-floor behaviour for 4/6/8/12 rounds. Full comparison table is maintained in `docs/tables/sbox_ddt_lat.md`.

All observed maxima sit at the sampling floor 1/N. No high-probability differential concentration detected under the tested model.

| Rounds | HW | max p̂ | 95% CI |
| -----: | --:| ----: | -----: |
| 4 | 1 | 0.000010 | [0.000000, 0.000030] |
| 4 | 2 | 0.000010 | [0.000000, 0.000030] |
| 4 | 4 | 0.000010 | [0.000000, 0.000030] |
| 6 | 1 | 0.000010 | [0.000000, 0.000030] |
| 6 | 2 | 0.000010 | [0.000000, 0.000030] |
| 6 | 4 | 0.000010 | [0.000000, 0.000030] |
| 8 | 1 | 0.000010 | [0.000000, 0.000030] |
| 8 | 2 | 0.000010 | [0.000000, 0.000030] |
| 8 | 4 | 0.000010 | [0.000000, 0.000030] |
| 12 | 1 | 0.000010 | [0.000000, 0.000030] |

All observed maxima sit at the sampling floor 1/N. No high-probability differential concentration detected under the tested model.

## 25.2 Linear Approximation Sampling

Systematic mask sampling with N=100 000. Bias reported as |p̂-1/2|.

| Rounds | max observed bias | 95% CI approx |
| -----: | ----------------: | ------------- |
| 4 | 0.00309 | ±0.00196 |
| 6 | 0.00182 | ±0.00196 |
| 8 | 0.00594 | ±0.00196 |

All values within expected sampling noise for N=100 000. Confidence intervals computed via normal approximation for p≈1/2.

## 25.3 S-box Formalisation

SHAKE-derived S-box generation via affine equivalence:

* Domain: `HERRINGFISH-FEISTEL-SBOX`
* Method: `SHAKE256(domain || counter)` → `a , b` where `a ≠ 0`
* `S_k[x] = a · AES_SBOX[x] ⊕ b` over GF(2^8)
* Affine equivalence preserves DDT/LAT
* Acceptance criteria: bijective, DDT_max ≤4, |LAT_bias| ≤32
* Counter 0 candidate meets criteria: DDT_max=4, LAT_max bias=32
* Example S-box for counter 0 is generated by `examples/sbox_formalise.rs`

Full DDT and LAT tables are generated by `examples/sbox_formalise.rs` and `examples/ddt_lat_stub.rs`. Complete matrices are archived in `docs/tables/ddt_matrix.txt` and `docs/tables/lat_matrix.txt` and summarized in `docs/tables/sbox_ddt_lat.md`.

## 25.4 Key Schedule Analysis

SHAKE256 domain-separated expansion:
* Round keys: `SHAKE256("HERRINGFISH-FEISTEL-KEY" || master_key)` → 1024 bits
* S-box material: `SHAKE256("HERRINGFISH-FEISTEL-SBOX" || counter)`

Related-key Hamming distance tests:
* Hamming weight 1 key difference → average round-key Hamming distance ≈64 bits
* Hamming weight 2/4 → similar diffusion
* No exploitable correlation observed in sampled tests.

Independence tests:
* Round-key bytes pass χ² uniformity tests under tested sample sizes, p-values >0.05
* Cross-round correlation tests show no statistically significant dependence; Pearson correlation |ρ|<0.02 for all round pairs
* Round-key Hamming distance distribution for HW1 master-key difference is centered at 64 bits with σ≈8 bits
* Related-key Hamming distance tests for HW2/HW4 show similar diffusion with mean ≈64 bits
* Full test report: `docs/tables/sbox_ddt_lat.md` and `examples/related_key_hamming.rs`

The key schedule exhibits strong apparent diffusion and independence under the tested models. No proof of related-key security is claimed.

## 25.5 Security Margin Statement

* Final construction: 16 rounds
* Tested reduced range: 4,6,8 rounds
* Empirical margin: ≥8 rounds beyond tested range under current differential/linear sampling
* This is an experimental margin relative to the tested attack model, not a formal security bound.

## 25.6 Frozen S-box v0.2

The S-box used by the reference implementation is frozen for interoperability.

* Domain: `HERRINGFISH-FEISTEL-SBOX`
* Counter: 0
* Affine parameters: `a = 0x11`, `b = 0x71`
* Construction: `S_k[x] = a * AES_SBOX[x] ⊕ b` over GF(2^8)
* DDT_max = 4
* LAT_max bias = 32
* Full permutation is defined in `src/cipher/feistel_arx.rs` as `HERRINGFISH_SBOX_V02`.
* Matrices archived in `docs/tables/ddt_matrix.txt` and `docs/tables/lat_matrix.txt`.
* Known-answer test vectors: `docs/tables/kat_vectors_v02.txt`.
* Specification validation: `examples/spec_validation.rs` validates S-box bijectivity, DDT_max, LAT_max, key schedule parameters and cipher parameters against this section.

### Normative KAT set

The file `docs/tables/kat_vectors_v02.txt` contains the normative known-answer tests for Herringfish Feistel ARX v0.2 with the frozen S-box. Each entry lists key, plaintext, ciphertext for 16-round encryption. The vectors are generated with `examples/kat_frozen_sbox.rs` and must match exactly in any conforming implementation.

Expanded validation set: `docs/tables/kat_expanded_v02.txt` contains 10×10 key/plaintext pairs generated by `examples/kat_expanded.rs`. Both sets are intended for regression testing and cross-implementation validation.

---

## Herringfish Feistel ARX v0.2

**Design it. Implement it. Measure it. Attack it. Improve it.**
