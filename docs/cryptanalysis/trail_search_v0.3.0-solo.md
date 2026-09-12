# Exact Multi-Round Trail Search — Herringfish Feistel ARX v0.2 (solo-arx)

**Experiment identity**

| Field | Value |
|---|---|
| Construction | Herringfish Feistel ARX v0.2 (solo-arx variant, ARX key schedule) |
| Version | v0.3.0-solo.0 |
| Rounds tested | 4, 6, 8, 12, 14, 16 |
| S-box | HERRINGFISH_SBOX_V02 (frozen, counter=0, a=0x11, b=0x71) |
| Method | Exact per-byte DDT / LAT trail propagation (no sampling) |
| Tool | `examples/trail_search.rs` |
| Platform | Windows, MSVC, Rust stable, `cargo run --release` |
| Determinism | Fully deterministic (no randomness, no seed) |
| Key independence | Trails are key-independent (S-box layer is key-invariant under XOR; diffusion is linear) |

---

## 1. Component properties (exact, full 256×256)

| Property | Value |
|---|---|
| DDT max (input diff ≠ 0) | **4** (probability 4/256 = 1/64) |
| LAT max \|W\| (input mask ≠ 0, output mask ≠ 0) | **32** (max per-byte bias = 32/512 = 1/16 = 0.0625) |

These are the per-byte worst cases. They do **not** by themselves bound the
full-cipher differential or linear resistance; the multi-round trails below do.

---

## 2. Differential trails (forward, exact, greedy best)

Start: ΔL₀ = 0, ΔR₀ = single active byte (8 byte-positions × 255 differences =
2040 starting trails). At each round the best-greedy output difference per
active byte (argmax DDT entry) is taken; trail probability is the product of
per-byte DDT probabilities. The reported trail is the highest-probability one
across all 2040 starts.

| Rounds | Best trail probability p | Work factor ≈ 2^(−log₂ p) | Final ΔL | Final ΔR | Active bytes |
|---|---|---|---|---|---|
| 4  | 1.355 × 10⁻²⁰ | **2^66**  | 0047000047474747 | 0047000000474747 | 8 |
| 6  | 5.170 × 10⁻²⁶ | **2^84**  | 0000000000000000 | 0047000000474747 | 3 |
| 8  | 1.837 × 10⁻⁴⁰ | **2^132** | 0047000047474747 | 0047000000474747 | 7 |
| 12 | 2.673 × 10⁻⁵¹ | **2^168** | 0000000000000000 | 0000000000000047 | 1 |
| 14 | 1.593 × 10⁻⁵⁸ | **2^192** | 4700470000000047 | 0047000000474747 | 5 |
| 16 | 3.622 × 10⁻⁷¹ | **2^234** | 0047000047474747 | 0047000000474747 | 8 |

**Interpretation.** The best 16-round differential trail has probability
≈ 2^−234. A differential distinguisher based on this trail would require
≈ 2^234 chosen plaintext/ciphertext pairs, far beyond the 2^128 birthday
bound and the 2^256 exhaustive-key bound. No differential trail found within
these bounds provides a practical distinguisher against the full 16-round
cipher.

**Security conclusion (bounded).** No differential attack was found with work
factor below 2^128 for any round count 4–16. This is a *search-bound* result:
the greedy best-trail search over single-active-byte starts does not exhaust
all possible input differences (e.g. multi-byte starts, or non-greedy paths
that sacrifice one round for a better later round). A full exhaustive trail
search over all 2^128 input differences is infeasible; the result is
consistent with, but does not prove, differential resistance of the full cipher.

---

## 3. Linear trails (backward, exact, greedy best-bias)

Start: Γ on output L half = single active byte (8 × 255 = 2040 starting masks),
ΓR₀ = 0. Mask propagation is deterministic (diffuseᵀ is a fixed linear map);
per-byte probabilities come from the exact LAT Walsh sums. The reported trail
is the one with the highest combined bias (lowest product of per-byte
minority-direction probabilities).

| Rounds | Trail product | Est. work ≈ 2^(−2 log₂ p) | Final ΓL | Final ΓR |
|---|---|---|---|---|
| 4  | 9.159 × 10⁻³  | **2^13.5** | 0013000000130000 | 1313130000130013 |
| 6  | 2.097 × 10⁻⁵  | **2^31.1** | 0013000000130013 | 0000000000000000 |
| 8  | 1.756 × 10⁻⁶  | **2^38.2** | 0013000000130013 | 1313130000130013 |
| 12 | 4.398 × 10⁻¹⁰ | **2^62.2** | 0000000000000013 | 0000000000000000 |
| 14 | 1.924 × 10⁻¹⁰ | **2^64.5** | 0000000000000013 | 0000000013001313 |
| 16 | 4.028 × 10⁻¹² | **2^75.7** | 0013000000130000 | 1313130000130013 |

**Interpretation.** The best 16-round linear trail has a combined probability
product ≈ 4 × 10⁻¹². The standard linear-cryptanalysis work factor estimate
N ≈ 2^(−2 log₂ p) gives ≈ 2^76 known plaintext/ciphertext pairs. This is
**below** the 2^128 security target, but the work-factor formula assumes the
trail bias survives to the key-bit level and that a key-recovery or
distinguisher can be built from it. The trail's final ΓR is non-zero on 5
bytes, meaning the linear relation constrains 5 output bytes; building a
practical distinguisher or key-recovery from this trail requires additional
analysis (e.g. checking whether the bias is exploitable against the actual
key schedule and round structure).

**Security conclusion (bounded).** The best 16-round linear trail found has
an estimated work factor ≈ 2^76, which is below the 2^128 target. This is a
**candidate weakness** that requires follow-up: (a) verify the trail bias
empirically with a large sample; (b) determine whether a distinguisher or
key-recovery can actually be constructed from this trail; (c) if exploitable,
the cipher's linear security margin is ≈ 76 bits, not 128. This does **not**
constitute a confirmed break — it is a search-bound observation requiring
validation.

---

## 4. What this search does and does not cover

**Covers:**
- Exact per-byte DDT and LAT (full 256×256, no sampling)
- Best-greedy multi-round trail propagation for 4/6/8/12/14/16 rounds
- Single-active-byte start conditions (the standard high-probability entry point)
- Key-independent trail probabilities (valid for any key)

**Does not cover:**
- Multi-byte start conditions (ΔR₀ with 2+ active bytes) — these start with
  lower per-round probability but could in theory yield a better overall trail
  in some ciphers; unlikely here given the DDT max of 4
- Non-greedy trail paths (sacrificing one round's best byte for a better
  subsequent round) — the greedy search finds the locally-optimal path, not
  necessarily the globally-optimal one
- Related-key trails (the key schedule is ARX-based; related-key differentials
  are a separate analysis)
- Integral / higher-order differential properties
- Algebraic degree / algebraic normal form attacks
- Meet-in-the-middle attacks (separate structural analysis)

---

## 5. Recommended follow-up

1. **Validate the 16-round linear trail empirically.** Run a statistical test
   with ≥ 2^20 known plaintext/ciphertext pairs on the specific mask
   (ΓL=0013000000130000, ΓR=1313130000130013) to confirm or refute the
   predicted bias. If confirmed, this is a real (if modest) linear weakness.
2. **Extend the differential search to multi-byte starts** (2-active-byte
   ΔR₀) to confirm the 2^234 bound is not an artifact of the single-byte
   restriction.
3. **Related-key differential analysis** of the ARX key schedule (the
   schedule is ARX-based, not SHAKE-based; related-key behavior may differ
   from the main-line SHAKE variant).
4. **Algebraic degree analysis** of the full 16-round F-function (the
   diffusion layer is linear, the S-box is the only nonlinear component;
   the algebraic degree after 16 rounds bounds algebraic attacks).
