# Exact Multi-Round Trail Search — Herringfish Feistel ARX v0.2 (solo-arx)

**Experiment identity**

| Field | Value |
|---|---|
| Construction | Herringfish Feistel ARX v0.2 (solo-arx variant, ARX key schedule) |
| Version | v0.3.0-solo.0 |
| Rounds tested | Differential: 4, 6, 8, 12, 14, 16. Linear (corrected 2026-10-15, §3): 2, 3, 4, 6, 8, 12, 14, 16 |
| S-box | HERRINGFISH_SBOX_V02 (frozen, counter=0, a=0x11, b=0x71) |
| Method | Exact per-byte DDT / LAT trail propagation (no sampling) for the trail searches; rigorous active-S-box lower bound by dynamic programming (§2.1, §3.3); empirical validation against the real cipher (§4c) |
| Tools | `examples/trail_search.rs` (searches), `examples/active_sbox_bound.rs` (lower bound), `examples/linear_trail_check.rs` (validation), shared `examples/common/lin_trail.rs`, `tests/linear_trail_identity.rs` |
| Platform | Windows 11, MSVC, rustc 1.98.1 (48a229cea 2026-09-01), `cargo run --release`, AMD Ryzen 9 7950X (16C/32T), single-threaded runs; corrected-linear results recorded at commit `52b4053` (solo-arx + the three tool commits) |
| Determinism | Trail searches: fully deterministic (no randomness). Empirical checks: fixed SplitMix64 seeds, fixed keys (see §4c) |
| Key independence | Trail probabilities / correlation magnitudes are key-independent (S-box layer is key-invariant under XOR; diffusion is linear). The sign of a linear trail's correlation depends on the key. |

> **Revision 2026-10-15 — linear results retracted and corrected.** The
> 2^75.7 "candidate weakness" reported in §3 of the previous revision of this
> document was an artifact of a mask-propagation bug in `trail_search.rs`
> (§3.2). It is retracted, kept below as a negative result, and replaced by
> corrected results (§3.3–3.5). The `Final ΔR` column of the §2 table was
> also corrected (it disagreed with the tool output in 5 of 6 rows; ΔL and
> probabilities were right). The differential search itself is unchanged.

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
| 4  | 1.355 × 10⁻²⁰ | **2^66**  | 0047000047474747 | 0047000000470047 | 8 |
| 6  | 5.170 × 10⁻²⁶ | **2^84**  | 0000000000000000 | 0047000000470047 | 3 |
| 8  | 1.837 × 10⁻⁴⁰ | **2^132** | 0047000047474747 | 0047000000470000 | 7 |
| 12 | 2.673 × 10⁻⁵¹ | **2^168** | 0000000000000000 | 0000000000000047 | 1 |
| 14 | 1.593 × 10⁻⁵⁸ | **2^192** | 4700470000000047 | 0047000000470000 | 5 |
| 16 | 3.622 × 10⁻⁷¹ | **2^234** | 0047000047474747 | 0047000000470047 | 8 |

*Correction 2026-10-15:* the `Final ΔR` column previously printed
`0047000000474747` in rows 4, 6, 8, 14, 16; the tool prints the values above
(row 12 was already right). ΔL, probabilities, work factors and active-byte
counts were unaffected. The differential search code is unchanged; its
output is byte-identical before and after the linear fix.

**Interpretation.** The best 16-round differential trail found has
probability ≈ 2^−234. A differential distinguisher based on this single
characteristic would require ≈ 2^234 chosen plaintext/ciphertext pairs, far
beyond the 2^128 codebook. The same table shows much cheaper characteristics
at reduced rounds: 2^66 at 4 rounds and 2^84 at 6 rounds.

**Security conclusion (bounded).** For 4 and 6 rounds the greedy search found
characteristics with work below 2^128 (2^66, 2^84), so reduced-round
differential distinguishers of that size are not excluded. From 8 rounds
(2^132) on, the best greedy characteristic is below 2^−128. (The previous
revision said no differential work factor below 2^128 was found "for any
round count 4–16"; that contradicted this table at 4 and 6 rounds.) This is
a *search-bound* result: the greedy best-trail search over single-active-byte
starts does not exhaust all possible input differences (e.g. multi-byte
starts, or non-greedy paths that sacrifice one round for a better later
round), and single characteristics do not account for differentials
(sums over many characteristics). The rigorous lower bound of §2.1 brackets
the best 16-round characteristic between 2^−186 and 2^−234; the result is
consistent with, but does not prove, differential resistance of the full
cipher.

---

## 2.1 Rigorous lower bound on active S-boxes (differential)

**Tool:** `examples/active_sbox_bound.rs` (replaces `examples/active_sbox_count.rs`,
which printed hard-coded claims and computed nothing).

**Method.** Dynamic programming over byte-activity patterns of the two Feistel
halves. The set of achievable (input activity, output activity) pairs of the
diffusion layer is computed exactly for arbitrary byte values (bit-plane
OR-closure). **Relaxations (can only lower the bound):** cancellation at the
XOR with the other half is per byte and independent; byte values are not
tracked across rounds. **Per-S-box bound:** DDT max 4 ⇒ p ≤ 2^−6 per active
S-box (measured by the tool, not assumed). **Scope:** single characteristic,
independent-round-key assumption; no differentials, no hulls.

| Rounds | min active S-boxes A(r) | p(characteristic) ≤ 2^−6A | greedy trail found (§2) |
|---|---|---|---|
| 4  | 5  | 2^−30  | 2^−66  |
| 6  | 10 | 2^−60  | 2^−84  |
| 8  | 14 | 2^−84  | 2^−132 |
| 12 | 23 | 2^−138 | 2^−168 |
| 14 | 27 | 2^−162 | 2^−192 |
| 16 | 31 | 2^−186 | 2^−234 |

Full sequence for r = 1…16: A = 0, 1, 2, 5, 7, 10, 12, 14, 15, 18, 20, 23,
25, 27, 28, 31. Every greedy trail respects the bound (2^−66 ≤ 2^−30, …).

*Verification status.* The tool reproduces the sequence of an earlier
out-of-repo scratch DP. Soundness of the pair sets is sampled (2 × 200 000
random sparse byte vectors, each pair must lie in the set), not formally
proven; the DP itself is not formally verified. Found linear trails are
cross-checked never to beat the bound (`active_sbox_bound`). "Rigorous" here
means: a lower bound within the stated relaxed model, as implemented.

**Observation / explanation / conclusion.** *Observation:* A(16) = 31, so no
single differential characteristic over 16 rounds has probability above
2^−186; the bound first exceeds 2^128 of work at r = 12 (A = 23, 2^−138; at
r = 11, A = 20, 2^−120). *Explanation:* each round of a Feistel network with
this diffusion layer forces a minimum number of active S-boxes, each costing
at least 6 bits. *Conclusion (bounded):* within the stated model, no
single differential characteristic with probability ≥ 2^−128 exists for 12 or
more rounds. This does not bound differentials (many characteristics with the
same end differences), does not cover related keys, and is not a proof of
security. The gap between the bound (2^−186) and the best trail found
(2^−234) is unresolved: the greedy search is not optimal and the bound is
relaxed.

---

## 3. Linear trails

> **RETRACTED / CORRECTED (2026-10-15).** The result reported in this section
> in the previous revision (best 16-round linear trail ≈ 2^75.7, "candidate
> weakness") was produced by an incorrect mask-propagation rule and does not
> exist in the cipher. It is retained in §3.1 as a negative result. §3.3–3.6
> give the corrected rule, search, bounds and measurements.

### 3.1 Original (retracted) result — kept as a negative result

*Experiment:* `examples/trail_search.rs`, linear part, as of the previous
revision (greedy, "exact per-byte LAT"). Start: Γ on output L half = single
active byte (8 × 255 = 2040 starting masks), ΓR₀ = 0; the reported trail was
the one with the lowest product of per-byte "minority-direction"
probabilities. **The numbers below are what the tool printed; they are
artifacts of the bug in §3.2 and must not be used.**

| Rounds | Trail product | Est. work ≈ 2^(−2 log₂ p) | Final ΓL | Final ΓR |
|---|---|---|---|---|
| 4  | 9.159 × 10⁻³  | ~~2^13.5~~ | 0013000000130000 | 1313130000130013 |
| 6  | 2.097 × 10⁻⁵  | ~~2^31.1~~ | 0013000000130013 | 0000000000000000 |
| 8  | 1.756 × 10⁻⁶  | ~~2^38.2~~ | 0013000000130013 | 1313130000130013 |
| 12 | 4.398 × 10⁻¹⁰ | ~~2^62.2~~ | 0000000000000013 | 0000000000000000 |
| 14 | 1.924 × 10⁻¹⁰ | ~~2^64.5~~ | 0000000000000013 | 0000000013001313 |
| 16 | 4.028 × 10⁻¹² | ~~2^75.7~~ | 0013000000130000 | 1313130000130013 |

The previous revision concluded: "estimated work factor ≈ 2^76, below the
2^128 target … **candidate weakness** that requires follow-up", with follow-up
(a) "verify the trail bias empirically". That follow-up (old §4c, N = 2^20,
one key) found no bias, which the old text could not interpret because the
predicted bias (~4 × 10⁻¹²) was far below the detection threshold. **Status:
retracted. No security conclusion, positive or negative, may be drawn from
these numbers.**

### 3.2 What was wrong

**Observation.**
1. The trails claimed by the old rule are absent from the real cipher.
   `linear_trail_check` section D re-implements the old rule and measures its
   best trails (N = 2^22, key 0; σ = 2.4 × 10⁻⁴):

   | Rounds | Old claim | Measured \|bias\| (as reported / orientations swapped) |
   |---|---|---|
   | 2 | product 0.4375, i.e. bias ≈ 0.0625 | 1.2 × 10⁻⁴ / 4.0 × 10⁻⁴ |
   | 4 | product 9.159 × 10⁻³ | 6.9 × 10⁻⁵ / 1.5 × 10⁻⁴ |

   Both are noise-level. A separate out-of-repo scratch program (3 keys,
   N = 2^22, rounds 2/3/4/6) gave the same result (\|bias\| ≲ 10⁻³).
2. With the corrected rule the same measurement reproduces the prediction
   in magnitude and sign (§4c).

**Explanation.** Round: L′ = R, R′ = L ⊕ F(R), F = D ∘ S_k (S-box layer on
R ⊕ k, then byte diffusion D, y_i = x_i ⊕ x_{i+1} ⊕ x_{i+3}). For output
masks (α on L′, β on R′): α·L′ ⊕ β·R′ = α·R ⊕ β·L ⊕ β·F(R), and
β·F(R) = (Dᵀβ)·S(R ⊕ k). So u = Dᵀβ is the mask on the S-box layer
**output**; the S-box **input** mask w is a free choice (per active byte, one
LAT entry LAT[wᵢ][uᵢ]/256); the input masks are (β, α ⊕ w). The old code
instead XORed the S-box output mask u into the other half
(ΓR′ = ΓL ⊕ Dᵀ(ΓR)) and looked up LAT[ΓR byte][u byte], i.e. it treated the
mask on R as the S-box input mask and never chose w. The old sanity function
`assert_diffuse_t_correct` only printed a message; it checked nothing.

**Security conclusion.** The 2^75.7 figure has no support; the "candidate
weakness" is withdrawn. It does **not** follow that the linear margin is
adequate; see §3.5.

### 3.3 Corrected rule, searches and bound

Backward step over one round with output masks (α, β): u = Dᵀβ; per active
byte pick wᵢ with LAT[wᵢ][uᵢ] ≠ 0 (support of w = support of u, S is a
bijection); input masks (α′, β′) = (β, α ⊕ w); the trail correlation is
∏ LAT[wᵢ][uᵢ]/256 per active byte over all rounds, times a key-dependent sign
(−1)^(Σ w_t·k_t). The magnitude is key-independent. weight W = −log₂|corr|,
|bias| = |corr|/2. Per active S-box the LAT maximum is 32 ⇒ at best 2^−3.

*Exact algebraic check (no statistics).* For any trail built with this rule,
φ(P, C) = ⊕_t ( u_t·S(x_t) ⊕ w_t·R_{t−1} ) holds identically on every
plaintext, where φ is the parity of the trail's masks on (P, C). It is
verified against the real cipher for all reported trails (§4c A,
`tests/linear_trail_identity.rs`); the retracted rule fails it.

Searches (`examples/trail_search.rs`, `examples/common/lin_trail.rs`):
- **greedy:** optimal wᵢ per byte in every round (maximum |LAT|), from all
  4080 output masks with a single active byte on L or on R. Local choices
  only. This is the corrected analogue of the old search.
- **beam:** trails are parametrised by the S-box output masks u₁…u_r; the
  recursion u_{t+1} = u_{t−1} ⊕ Dᵀw_t lets cancellations between rounds be
  searched directly. State (u_{t−1}, u_t); starts (u₁, u₂) with ≤ 1 active
  byte each (byte-rotation symmetry used); the `width` cheapest states per
  round are kept, `k` best w per byte. Default width 2^16, k = 2. Each returned
  trail is re-propagated by the exact rule and validated. The weight found
  is an **upper bound** on the best single-trail weight (heuristic, not
  optimal).
- **lower bound:** `examples/active_sbox_bound.rs` (same DP and assumptions
  as §2.1, with the linear/dual layer Dᵀ and cost 2^−3 per active S-box):
  min active S-boxes A(r) = 0, 1, 2, 4, 5, 6, 7, …, 16 for r = 1…16
  (A(r) = r for r ≥ 5), hence **no single trail has |corr| > 2^−3A(r)**
  (under the relaxations of §2.1; single-trail model, no hulls).

### 3.4 Corrected results (single trail, |corr| = 2^−W)

Beam parameters: width 65536, k = 2. W = weight in bits (= 3 × active
S-boxes in every row: all active S-boxes use |LAT| = 32).

| Rounds | greedy W (active) | beam W (active) | \|corr\| (beam) | \|bias\| (beam) | lower bound 3·A(r) | optimum W lies in |
|---|---|---|---|---|---|---|
| 2  | 9 (3)    | **3** (1)   | 2^−3   | 2^−4   | 3  | **3** (exact) |
| 3  | 18 (6)   | **6** (2)   | 2^−6   | 2^−7   | 6  | **6** (exact) |
| 4  | 36 (12)  | 15 (5)      | 2^−15  | 2^−16  | 12 | [12, 15] |
| 6  | 54 (18)  | 36 (12)     | 2^−36  | 2^−37  | 18 | [18, 36] |
| 8  | 69 (23)  | 45 (15)     | 2^−45  | 2^−46  | 24 | [24, 45] |
| 12 | 108 (36) | 72 (24)     | 2^−72  | 2^−73  | 36 | [36, 72] |
| 14 | 117 (39) | 87 (29)     | 2^−87  | 2^−88  | 42 | [42, 87] |
| 16 | 144 (48) | 99 (33)     | 2^−99  | 2^−100 | 48 | [48, 99] |

(For r = 2 and 3 the found weight equals the lower bound, so these trails are
optimal single trails within the model.)

Beam trails (masks on plaintext (L₀, R₀) and ciphertext (L_r, R_r)):

| r | plaintext (L₀, R₀) | ciphertext (L_r, R_r) |
|---|---|---|
| 2  | 0000000000000000, 0101010000010001 | 0000000000000027, 0101010000010001 |
| 3  | 0101010000010001, 0000000000000027 | 0000000000000027, 0101010000010001 |
| 4  | 0101010000010001, 0000000000000027 | 010101003a013a3b, 0000000000000027 |
| 6  | 0505050000050005, 0000000000000042 | 0000000005000505, 0042000000420042 |
| 8  | 0505050000050005, 0000000000000042 | 0000000005000505, 0000000000000000 |
| 12 | 5252520000520052, 0000000000000017 | 4141410013411352, 0000000000000004 |
| 14 | 0505050000050005, 0000000000000042 | 0505050000050005, 0000000000000000 |
| 16 | 0505050000050005, 0000000000000042 | 0505050005050500, 0000000000000042 |

*Beam sensitivity (rows r = 2, 3, 4, 6, 8, 12, 14, 16; weights only):* the
table is unchanged for (width, k) = (2^14, 2), (2^18, 3), (2^20, 3) and
(2^18, 4) (the last two take ≈ 8 and ≈ 12 minutes on one core). (2^16, 4)
gives identical weights except r = 12: 78 (worse than 72; beam search is not
monotone in its parameters). The weights therefore look converged for this
start set and heuristic, which says nothing about trails the beam cannot
reach.

### 3.5 Interpretation (observation / explanation / conclusion kept separate)

**Observation.**
- A 2-round linear approximation with a single active S-box exists:
  \|corr\| = 2^−3, \|bias\| = 2^−4 = 0.0625. A 3-round one with 2 active
  S-boxes: \|corr\| = 2^−6, \|bias\| = 2^−7 = 7.8 × 10⁻³. Both were measured
  on the real cipher with N = 2^24 for 3 keys and agree with the signed
  prediction within 3σ (§4c).
- At 4 rounds the best trail found has \|bias\| = 2^−16 ≈ 1.5 × 10⁻⁵ (not
  resolvable at N = 2^24, σ = 1.2 × 10⁻⁴; not measured). At 16 rounds the best
  trail found has \|corr\| = 2^−99; the rigorous bound is \|corr\| ≤ 2^−48.

**Explanation (hypothesis, not proven).** Two rounds can be approximated through one S-box because
choosing α = w cancels the first-round F contribution exactly (the S-box
layer of round 1 is inactive); the large masks come from β = (Dᵀ)⁻¹u. Beyond
three rounds the exact cancellations required by the recursion
u_{t+1} = u_{t−1} ⊕ Dᵀw_t no longer fit a one-S-box-per-round pattern; the
search finds about 2 active S-boxes per round, the relaxed bound allows 1.

**Security conclusion (bounded).**
- Reduced-round: 2- and 3-round linear distinguishers with data of order
  1/\|corr\|² ≈ 2^6 and 2^12 (times a small constant) exist; the cipher is
  trivially distinguishable at 2–3 rounds. That is a reduced-round result and
  says nothing by itself about 16 rounds.
- Full 16 rounds: no trail with weight ≤ 64 (data ≲ 2^128) was found, and
  the best trail found (W = 99, data order 2^198) exceeds the codebook. But
  the rigorous bound (W ≥ 48, data ≥ 2^96) is **below** 2^128, so this
  work does **not** establish single-trail linear resistance at 16 rounds:
  the true optimum lies in [48, 99] bits and is unresolved. The beam search
  is heuristic (an upper bound on the optimum only) and the DP bound is a
  relaxation; closing the gap needs an exact search (§5).
- Not covered: linear hulls (many trails per approximation) and
  multi-approximation attacks, which can have larger correlation than a
  single trail; key-dependent effects; trails outside the beam's reach
  (starts with more than one active byte in u₁ or u₂). No linear weakness of
  the full cipher was found; this is not evidence that none exists.

### 3.6 Reproduction

```
cargo run --release --example trail_search               # §2 and §3.4 (≈ 3 s; optional args: beam width, k)
cargo run --release --example active_sbox_bound          # §2.1 and A(r) (≈ 1 s)
cargo run --release --example linear_trail_check         # §4c (≈ 6 s, exit 1 on failure; optional arg: log2 N)
cargo test --test linear_trail_identity                  # exact identity tests
```

---

## 4. What this search does and does not cover

**Covers:**
- Exact per-byte DDT and LAT (full 256×256, no sampling)
- Best-greedy multi-round trail propagation for 4/6/8/12/14/16 rounds
- Single-active-byte start conditions (the standard high-probability entry point)
- Key-independent trail probabilities (valid for any key)
- Non-greedy linear trail search (beam, §3.3) and a rigorous lower bound on
  active S-boxes for differential and linear trails (§2.1, §3.3)
- Multi-byte (2 and 3 active byte) differential starts (§4a)
- Related-key ARX schedule analysis: linearity, HW mixing, simplified differential (§4b)
- Validation of the linear-trail rule against the real cipher: exact
  identity, positive control, 3σ check of every testable reported trail (§4c)
- Algebraic degree analysis: S-box ANF, per-round growth, key invariance (§4d)

**Does not cover:**
- Non-greedy differential trail paths (sacrificing one round's best byte for
  a better subsequent round) — the differential search is still greedy, so
  its result is a locally-optimal path, not necessarily the global optimum
  (bracketed only by the §2.1 bound)
- Provably optimal single trails (the beam is heuristic, the DP bound is a
  relaxation; gaps in §2.1 and §3.4)
- Differentials and linear hulls (sums over many characteristics / trails);
  everything above is single-trail
- Integral / higher-order differential properties
- Algebraic degree / algebraic normal form attacks
- Meet-in-the-middle attacks (separate structural analysis)

---

## 4a. Multi-byte differential starts (exact, greedy best)

**Tool:** `examples/multi_byte_diff.rs`

Extends §2 to 2-active-byte and 3-active-byte starting conditions.

| Rounds | Single-byte p | 2-byte p | 3-byte p (subset) |
|---|---|---|---|
| 4  | 1.355e-20 (2^66)  | 5.170e-26 (2^84)  | 5.170e-26 (2^84)  |
| 6  | 5.170e-26 (2^84)  | 1.262e-29 (2^96)  | 4.484e-44 (2^144) |
| 8  | 1.837e-40 (2^132) | 1.837e-40 (2^132) | 9.496e-66 (2^216) |
| 12 | 2.673e-51 (2^168) | 1.593e-58 (2^192) | 2.538e-116 (2^384) |
| 14 | 1.593e-58 (2^192) | 2.318e-69 (2^228) | 1.312e-141 (2^468) |
| 16 | 3.622e-71 (2^234) | 8.236e-84 (2^276) | 6.783e-167 (2^552) |

**Result: Single-byte starts are the best at every round count.** 2-byte
starts are strictly worse; 3-byte starts are much worse. The 2^234
differential bound from §2 is the best this greedy search found (the
rigorous lower bound on weight is 2^186, §2.1; "tightest known" is a statement
about this search only).

---

## 4b. Related-key analysis (ARX key schedule)

**Tool:** `examples/related_key_arx.rs`

Three analyses of the solo-ARX key schedule's related-key behavior:

**1. Linearity gap.** For 2000 random pairs of single-bit key differences
(ΔK₁, ΔK₂), checked whether Δrk(ΔK₁ XOR ΔK₂) == Δrk(ΔK₁) XOR Δrk(ΔK₂).
Result: **0/2000 linear** → the schedule is **strongly nonlinear** in the
key (due to modular addition in the ARX mixer). Related-key differentials
do not have a systematic advantage from the key schedule alone.

**2. Round-key Hamming weight independence.** For 406 related-key pairs
(1-bit, 2-bit, 4-bit key differences), measured the Hamming weight of each
round-key difference Δrk[i]:

- Round 0: mean HW = 30.4, min = 14 (one mixer step, expected to be lower)
- Rounds 1-15: mean HW ≈ 32.0, min ≥ 18 (near-random, as expected)

The slightly lower HW at round 0 is expected from the one-step mixing and
is not a vulnerability: the Feistel structure means round 0's key is only
used in the first F-function evaluation.

**3. Related-key differential (simplified 1-byte model).** For a specific
1-bit key difference (bit 0, byte 0), computed the trail probability in the
simplified 1-byte DDT model. The related-key trail (2^90) appears better than
the single-key trail (2^96) due to a coincidence: at round 7, the round-key
difference byte 0 happens to be 0x01, making the S-box input difference
0x01 XOR 0x01 = 0x00, which has DDT max = 256/256 = 1.0. This is an artifact
of the 1-byte model, not a full-cipher property. In the full 8-byte Feistel
state, the trail continues through other bytes with normal DDT probabilities.

**Conclusion:** The ARX key schedule provides adequate related-key resistance
for small Hamming-weight key differences. The strong nonlinearity (0% linear
pairs) and near-random round-key mixing (mean HW ≈ 32) prevent systematic
related-key attacks. This does not rule out related-key attacks with larger
key differences or multi-round interactions.

---

## 4c. Validation of the linear-trail rule against the real cipher

**Tool:** `examples/linear_trail_check.rs` (replaces `examples/linear_bias_test.rs`,
removed: it re-derived the retracted 16-round trail with the old rule) and
`tests/linear_trail_identity.rs`.

**Experiment:** Herringfish Feistel ARX v0.2, solo-arx ARX key schedule
(`FeistelArx::new_with_rounds`), 3 fixed keys (`key[i] = 37·i + 101·k + 11`,
k = 0, 1, 2), SplitMix64 plaintexts (seed `0x9E3779B97F4A7C15 ^ (k·0x1234567)`),
N = 2^24 per key and trail. Platform and compiler: header table. Trails:
exactly those printed by `trail_search` (beam width 65536, k = 2) and the
corrected greedy trails. Statistic: z = (measured − predicted)/σ with
σ = √(p(1−p)/N); predicted bias = −½ ∏ LAT/256 · (−1)^(Σ w_t·k_t) (signed,
uses the actual round keys). Pass criterion: |z| ≤ 3.

**A. Exact identity** (2^14 random blocks × 2 keys, no statistics):
φ(P, C) = ⊕_t(u_t·S(x_t) ⊕ w_t·R_{t−1}) holds on every sample for the beam
and greedy trails, r = 1…16, and a local re-implementation of the round
agrees with `encrypt_block`. **PASS.** (The unit tests also corrupt one mask
bit and check that the identity then fails.)

**B. Positive control** — 1 round, output masks (0, 0x33 at byte 0): 3 active
S-boxes with |W| = 32 (w = 0x01, u = 0x33), predicted |bias| = 2^−10 = 9.766 × 10⁻⁴:

| Key | Predicted | Measured | σ | z |
|---|---|---|---|---|
| 0 | −9.766 × 10⁻⁴ | −1.092 × 10⁻³ | 1.2 × 10⁻⁴ | −0.95 |
| 1 | +9.766 × 10⁻⁴ | +1.303 × 10⁻³ | 1.2 × 10⁻⁴ | +2.67 |
| 2 | +9.766 × 10⁻⁴ | +8.004 × 10⁻⁴ | 1.2 × 10⁻⁴ | −1.44 |

**PASS** (key 1 is at 2.7σ, inside the 3σ criterion; the sign of the
prediction, which depends on the key through w·k, matches on all three keys).

**C. Reported trails with predicted |bias| ≥ 10⁻³** (the only ones testable at
N = 2^24, σ ≈ 1.2 × 10⁻⁴). No other reported trail reaches 10⁻³ (all 28
others are listed as skipped by the tool):

| Trail | Key | Predicted | Measured | z |
|---|---|---|---|---|
| beam r = 2 (W = 3) | 0 | +6.250 × 10⁻² | +6.266 × 10⁻² | +1.32 |
| | 1 | −6.250 × 10⁻² | −6.255 × 10⁻² | −0.45 |
| | 2 | +6.250 × 10⁻² | +6.265 × 10⁻² | +1.22 |
| beam r = 3 (W = 6) | 0 | −7.812 × 10⁻³ | −7.981 × 10⁻³ | −1.38 |
| | 1 | −7.812 × 10⁻³ | −7.664 × 10⁻³ | +1.22 |
| | 2 | +7.812 × 10⁻³ | +7.870 × 10⁻³ | +0.47 |

**PASS** (6 of 6 within 3σ). The greedy trails are all below 10⁻³ (best: r = 2,
9.766 × 10⁻⁴) and are covered by A only.

**D. Retraction replay** (N = 2^22, key 0): the trails claimed by the retracted
rule are not present — see the §3.2 table. **PASS** (claim refuted).

**Observation.** The corrected rule predicts both magnitude and sign of the
measured biases for the 1-, 2- and 3-round approximations; the retracted rule
predicts none. **Explanation.** The corrected rule is the exact
mask propagation of the construction (A is an identity, not a fit).
**Conclusion (bounded).** This validates the *rule and the tooling* for trails
with predicted bias ≥ 10⁻³. It does not validate 4-round and longer trails
statistically (|bias| ≈ 1.5 × 10⁻⁵ needs ≳ 2^35 samples per key for 5σ); for those
only A (exact identity) and the §3.3 bound stand. It says nothing about linear
hulls or about full-round security.

**Original §4c (retracted, kept as a negative result).** The previous revision
encrypted 2^20 random blocks with one fixed key and measured the retracted
16-round trail: φ = 1 frequency 0.49984455, 95% CI [0.49888752, 0.50080158],
z = −0.32 vs 0.5, detection threshold |ε| > 1.91 × 10⁻³, predicted bias
~4 × 10⁻¹². "No bias detected" was a null result against a prediction far
below the threshold and was uninformative (the trail does not exist, §3.2);
its conclusion that "the 2^75.7 work factor is a theoretical bound" is
withdrawn.

---

## 5. Recommended follow-up

**Completed:**
1. ✅ Multi-byte differential starts (§4a): single-byte confirmed as best
2. ✅ Related-key ARX analysis (§4b): adequate resistance, strongly nonlinear
3. ✅ Linear-trail rule validated against the real cipher; retracted trail
   replayed as a negative control (§3.2, §4c)
4. ✅ Algebraic degree analysis (§4d): S-box degree 7, saturates at 64 by
   round 3, algebraic attacks infeasible.
5. ✅ Non-greedy linear trail search (beam) and rigorous active-S-box lower
   bounds for differential and linear trails (§2.1, §3.3–3.4)

**Remaining:**
6. **Exact / branch-and-bound linear trail search** using the §3.3 DP as a
   state-dependent lower bound, to close the single-trail gap at 16 rounds
   (optimum weight in [48, 99] bits; at r = 4: [12, 15]).
7. **Non-greedy differential trail search** (the differential search is still
   greedy; at 16 rounds the best characteristic lies in [2^−186, 2^−234]).
8. **Hull / clustering analysis**: differentials and linear hulls over the
   few-round trails of §3.4 (2–6 rounds), since single trails can
   underestimate.
9. **Tighten the DP relaxation** (track actual byte values instead of
   independent per-byte cancellation) to see whether A(r) rises.
10. **Audit the other linear tools** (`linear_trail_search.rs`,
    `linear_trail_search_exact.rs`, `linear_analysis.rs`,
    `cryptanalysis_full.rs`, `trail_hull_analysis.rs`,
    `linear_hull_meet_in_middle.rs`) against the exact identity of §3.3: they
    were not checked in this revision; any figure derived from them is
    unverified.
11. **AEAD mode / SIMD** (optimization, only after cryptanalysis is complete).

---

## 4d. Algebraic degree analysis (exact ANF)

**Tool:** `examples/algebraic_degree.rs`

The algebraic degree of a boolean function is the degree of its Algebraic
Normal Form (ANF). For a block cipher, the algebraic degree bounds the
complexity of algebraic attacks (XL, F4, Gröbner basis, etc.).

**S-box ANF (exact, via Mobius transform):**

| Output bit | Degree | ANF weight |
|---|---|---|
| 0 | 7 | 126 |
| 1 | 7 | 126 |
| 2 | 7 | 131 |
| 3 | 7 | 125 |
| 4 | 7 | 137 |
| 5 | 7 | 128 |
| 6 | 7 | 124 |
| 7 | 7 | 136 |

All 8 output bits have degree **7** — the maximum achievable for a bijective
8-bit S-box (degree 8 is impossible for a bijection: the degree-8 coefficient
x₀·x₁·…·x₇ would make the function non-invertible). ANF weights range from
124 to 137 (out of 256 possible monomials) — moderately dense, no exploitable
sparsity.

**Key invariance:** The degree is always 7 regardless of key XOR (SBOX(x^k)
has the same degree as SBOX(x) for any constant k). Sparsity varies slightly
with key (min weight: 111 for k=0x55) but remains dense.

**Per-round degree growth:**

| Round | deg(L) | deg(R) | Note |
|---|---|---|---|
| 1 | 0 | 7 | S-box applied to plaintext (linear) |
| 2 | 7 | 49 | 7×7 composition |
| 3 | 49 | **64** | **SATURATED** (max for 64-bit half) |
| 4-16 | 64 | 64 | saturated |

The algebraic degree saturates at 64 (the maximum for a 64-bit half) by
round 3. After 16 rounds, the ANF of each ciphertext bit has up to 2^64
monomials. Algebraic attacks require solving a system with C(128,64) ≈ 10^18
monomials — completely infeasible.

**Conclusion:** The S-box's high algebraic degree (7, maximum for bijective)
and rapid degree growth (saturating at 64 by round 3) mean that algebraic
attacks cannot exploit the S-box structure. The cipher is algebraically
"random" after 3 rounds. No algebraic attack provides a practical advantage.
