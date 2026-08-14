# Herringfish

**Herringfish** is an experimental symmetric-key cryptography research project centered on a 128-bit balanced Feistel block cipher with 256-bit master key, nonlinear S-box processing, ARX-based diffusion, and a SHAKE256-derived key schedule.

The current construction is Herringfish Feistel ARX v0.2, an experimental research prototype rather than a production cryptographic primitive.

> ⚠️ Experimental cryptography
>
> Herringfish is a research project and must not be used to protect real-world secrets, production systems, passwords, financial information, or other sensitive data.
>
> A new cipher should be considered insecure until it has undergone extensive public cryptanalysis and independent review.

---

## Project Goals

* Design and document a symmetric-key cryptographic algorithm.
* Implement a reference algorithm in Rust.
* Explore candidate cipher constructions and select based on cryptanalysis.
* Analyze resistance against known cryptanalytic techniques.
* Build automated cryptanalysis and testing tools.
* Provide deterministic test vectors and known-answer tests.
* Develop portable implementations with constant-time design goals.
* Investigate SIMD acceleration and benchmark across platforms.
* Study reduced-round variants and potential weaknesses.
* Eventually design an authenticated-encryption construction around the primitive.

Development principle: Design it, implement it, test it, and then try to break it.

---

# Current Status

**Status: Experimental / Research – Feistel ARX v0.2 prototype**

Specification is experimental. S-box is frozen for v0.2 evaluation. S-box counter 0, affine parameters a=0x11, b=0x71, DDT_max=4, LAT_max=32. Tag v0.2.1.

### Specification status

| Artifact | Status |
|---|---|
| Cipher construction | v0.2 research prototype |
| Specification | Draft |
| S-box | Frozen for v0.2 |
| Key schedule | Frozen for v0.2 |
| Test vectors | Available |
| Reference implementation | Available |
| Reduced-round analysis | Preliminary |
| Statistical analysis | Ongoing |
| Independent cryptanalysis | Not yet performed |
| AEAD | Not implemented |
| Production use | Not recommended |

### Prototype properties

| Property | Value |
|---|---|
| Cipher type | Symmetric-key block cipher |
| Key size | 256 bits |
| Block size | 128 bits |
| Architecture | Balanced Feistel ARX v0.2 |
| Rounds | 16 |
| Security goal | Investigate a substantial classical security margin |
| Constant-time design goal | Required |
| SIMD | Planned |
| AEAD | Planned |
| Reference implementation | Rust |

The 256-bit key size is a design parameter, not evidence of 256-bit security. A 256-bit key does not automatically make the cipher 256-bit secure.

### Security claims

Herringfish currently makes no claim of proven or established cryptographic security.

* 256-bit key size does not imply 256-bit security.
* Passing statistical tests does not establish cryptographic security.
* Passing known-answer tests establishes implementation correctness, not security.
* S-box DDT/LAT properties do not establish full-cipher resistance to differential or linear cryptanalysis.
* Reduced-round resistance does not establish full-round security.
* Constant-time coding practices do not by themselves establish side-channel resistance.
* A successful attack against Herringfish is considered valuable research data.

### What Herringfish is not

* Not a standardized cipher
* Not a NIST-approved primitive
* Not independently cryptanalyzed
* Not suitable for production cryptography
* Not a replacement for AES, ChaCha20, or established AEAD schemes
* Not claimed to provide 256-bit cryptographic security merely because it has a 256-bit key

For production applications, established and extensively analyzed constructions such as AES-GCM and ChaCha20-Poly1305 should be preferred.

---

# Herringfish Cipher

Herringfish v0.2 is a concrete Feistel ARX prototype with frozen S-box parameters under active research.

The design is documented in `docs/specification/feistel_arx_v0.2.md` and implemented in `src/cipher/feistel_arx.rs`. The final construction remains subject to further cryptanalysis and may evolve in future versions.

## Design decisions

### Primitive

Feistel network with balanced 128-bit block and 64-bit halves.

### Block size

128-bit block selected for modern use cases.

### Key size

256-bit master key.

### Rounds

16 rounds selected as the current v0.2 research configuration. Reduced-round analysis is being used to investigate the resulting security margin.

### Nonlinear component

8-bit S-box layer. v0.2 uses a frozen affine-equivalent transformation of the AES S-box.

The v0.2 S-box is defined as an affine-equivalent transformation of the AES S-box with affine parameters a=0x11 and b=0x71 under the construction's specified byte transformation.

S-box counter: 0
DDT maximum: 4
LAT maximum: 32

Full permutation is defined in `src/cipher/feistel_arx.rs` as `HERRINGFISH_SBOX_V02`.

### Diffusion

Intra-round linear diffusion via XOR-based byte mixing achieves rapid avalanche and full diffusion within the Feistel round function.

### Key schedule

SHAKE256 XOF with domain separation. Round keys are derived as SHAKE256(domain_separator || master_key) producing 1024 bits for 16 rounds.

Domain separator for round-key derivation is `HERRINGFISH-FEISTEL-KEY`. Output is little-endian encoded into 64-bit round keys.

Preliminary statistical testing of generated round keys has not identified obvious non-random structure.

### ARX definition

The "ARX" designation refers specifically to the use of addition, rotation, and XOR operations within the round function. The nonlinear S-box layer is an additional component and is not itself considered part of the ARX primitive.

### Constant-time

Implementations are designed to avoid secret-dependent timing behavior. Constant-time properties must be validated through implementation review and appropriate side-channel testing; the reference implementation should not be assumed to be constant-time merely because it avoids obvious branches.

The reference S-box implementation uses table lookup indexed by secret-dependent data. This can create cache side channels. Constant-time S-box implementation is a hardening goal.

---

# Cryptanalysis

The project includes research tooling for investigating potential weaknesses.

### Block-cipher analysis

Differential cryptanalysis
Linear cryptanalysis
Integral cryptanalysis
Impossible differential
Related-key analysis
Algebraic attacks
Meet-in-the-middle where applicable
Structural attacks

### Construction and mode analysis

CPA security
CCA security
Forgery resistance
Nonce misuse resistance
Authentication security

### Analysis in progress

S-box differential analysis – DDT computed
S-box linear analysis – LAT computed
Full-cipher differential analysis – preliminary sampling
Full-cipher linear analysis – preliminary sampling
Avalanche analysis – examples exist
Statistical analysis – sampling in progress
Reduced-round attack tooling – exhaustive and characteristic searches

Reduced-round resistance does not establish full-round security.

---

# Reproducibility

Cryptanalytic experiments should record:

* Herringfish version/tag
* Specification version
* Experiment parameters
* Number of samples
* Random seed where applicable
* Hardware/software environment
* Compiler version
* Relevant Cargo features

---

# Project structure

src/
├── cipher/
│   ├── mod.rs
│   └── feistel_arx.rs
tests/
examples/
docs/
└── lib.rs

Structure will evolve as research progresses.

---

# Development principles

Security before performance. Simplicity before complexity. Every component must have a clear cryptographic justification. Performance optimization must not obscure security properties.

---

# Contributing

Contributions involving cryptographic analysis are especially valuable.

Useful contributions include cryptanalytic attacks, differential characteristics, linear approximations, statistical analysis, performance improvements, SIMD implementations, independent implementations, test vectors, mathematical analysis, documentation, and reproducible experiments.

---

# License

See LICENSE file.
