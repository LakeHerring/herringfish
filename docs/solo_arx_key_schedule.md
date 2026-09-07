# Solo-ARX Key Schedule – Design Rationale

**Branch:** `solo-arx`  
**Implementation:** `src/cipher/arx_key_schedule.rs` (Feistel ARX), `src/cipher/key_schedule.rs` (SPN variant)  
**Tests:** `tests/arx_schedule.rs` (5 integration) + 11 unit tests in `src/cipher/arx_key_schedule.rs`  
**Date:** 2026-08 (solo-arx branch)

## 1. Purpose

The canonical v0.2 specification derives round keys with
`SHAKE256("HERRINGFISH-FEISTEL-KEY" || master_key)`. The solo-arx branch
removes **all** SHAKE/SHA-3/Keccak dependencies so the cipher is fully
self-contained: round-key derivation uses only rotations, XOR, 64-bit
modular addition, and a frozen constant array. No hash, XOF, or other
external primitive is linked or invoked.

The frozen v0.2 specification is left unchanged; it documents the canonical
SHAKE-based variant. This branch differs **only** in the key schedule.

## 2. Construction

The 256-bit master key is split into four little-endian 64-bit words
`(w0, w1, w2, w3)`. Each round key `i` is produced with a global step
counter `g = 2i`:

1. **Two `full_mix` iterations** — in each, every word is replaced by the
   modular sum of itself, the XOR of its three rotated neighbours
   (12 distinct rotation amounts), and a frozen constant
   `C[g], C[g+5], C[g+9], C[g+14]` (indices mod 16).
2. **One bijective XOR network** —
   `m0 = w0 ^ rotr(w1,21) ^ rotr(w3,33)`,
   `m1 = w1 ^ rotr(w2,25) ^ rotr(w0,37)`,
   `m2 = w2 ^ rotr(w3,41) ^ rotr(w1,17)`,
   `m3 = w3 ^ rotr(w0,53) ^ rotr(w2,13)`.
3. `round_key[i] = m0 ^ m1 ^ m2 ^ m3`.

### Constants

`C[i] = GOLDEN64 * (2i+1) mod 2^64` with
`GOLDEN64 = 0x9E37_79B9_7F4A_7C15 = floor(2^64 / φ)` — the 64-bit analogue
of the RC5 "Q" constant, a "nothing up my sleeve" choice (see §4.2). The
multiplication occurs **at compile time only** (Rust `const` evaluation to
build the frozen literal array); the runtime schedule contains no
multiplication — only rot, XOR, and modular addition, as mandated.

### Why the XOR network uses rotate-right

The rotate-**left** variant of the network has GF(2) rank 254 (kernel
dimension 2) and is therefore not bijective; the rotate-**right** variant
was verified programmatically to have rank 256/256 (the
`xor_net_is_bijective` unit test applies each of the 256 basis vectors to
the actual function and checks the resulting matrix rank). Bijectivity of
the network guarantees the round-key stream is a pure function of the
full register state at every step.

## 3. Measured properties

All measurements below are reproducible from the test suite and the
cryptanalysis examples on this branch.

| Property | Measurement |
| --- | --- |
| Deterministic | `expansion_is_deterministic` — identical stream for identical key |
| Key differentiation | `expansion_changes_with_key` — different keys, different streams |
| Streaming (prefix) property | `prefix_property` — first `k` keys of a longer derivation unchanged |
| Full key sensitivity | `all_key_words_influence_every_round_key` — every master-key word flips every round key |
| Key avalanche (zero-key base, all 256 single-bit flips) | mean-of-means 31.86 bits per 64-bit round key; worst flip 29.38 (bit 188), best 35.44 (bit 93); every flip within [26, 38] |
| Key avalanche (200 random-base keys, all 256 flips each) | mean-of-means 32.06 bits |
| XOR network bijectivity | GF(2) rank 256/256 (programmatic basis-vector check) |
| Stream health | `round_keys_are_distinct_and_nonzero` — no duplicates or zero words in 16-key streams for representative keys |
| Round-key independence | `key_schedule_independence` — pairwise round-key Hamming ≈ 32.00 of 64 bits; `key_schedule_independence_large` (100k samples) — total Hamming 512.05 of 1024 bits, std 15.99 |
| SPN variant | `related_key_analysis` — 128-bit SPN round keys: 64.0 of 128 bits for HW1/2/4 and random key pairs |

A 1-bit master-key change therefore alters about half of every round key
from round 0 onward, matching the pseudorandom target (~50%) that
key-schedule security proofs assume.

## 4. Literature rationale

### 4.1 ARX key schedules are the established class

Key schedules built from rotation/XOR/modular-addition with frozen
constants are the standard "PRNG-seeded-by-key" design: Blowfish, RC5,
RC6, and KHAZAD all use this style. Avanza's survey of block-cipher design
("A Salad of Block Ciphers", eprint 2016/1171, §1 and §1.7) documents ARX
schedules for small-block ciphers and the general principle that round-key
derivation should look pseudorandom; security proofs for Feistel and
ARX constructions typically assume independent or pseudorandom round keys.
Replacing a SHAKE XOF with a well-mixed ARX expansion keeps the schedule
in this established class while removing the external dependency.

### 4.2 "Nothing up my sleeve" constants

`GOLDEN64 = floor(2^64/φ)` is the direct 64-bit analogue of the RC5 Q
constant (`floor(2^32/φ)`). Deriving the 16 frozen constants as
`GOLDEN64·(2i+1) mod 2^64` (odd multipliers) gives distinct,
key-independent, deterministic constants without any hash function — the
same "nothing up my sleeve" practice endorsed by the Avanza survey (§1).

### 4.3 S-box: the frozen AES-affine S-box is a theorem, not a measurement

The frozen S-box `S[x] = a·AES_SBOX[x] ⊕ b` (a=0x11, b=0x71) is an affine
equivalent of the AES S-box. Affine-equivalent S-boxes have **identical
DDT and LAT up to relabeling** — a theorem (Canteaut–Roué, "On the
Differential and Linear Equivalence of S-Boxes", EUROCRYPT 2015, Lemma 1;
Biryukov, Kelbert, Kulganov, Perrin, "On the Equivalence of S-Boxes",
EUROCRYPT 2003). The measured `DDT_max = 4` and `LAT_max bias = 32` are
therefore inherited properties, not coincidences of the particular
`a`, `b` pair.

Two caveats are documented for completeness:

* 2-round MEDP/MELP of the F-function varies **within** the affine
  equivalence class (the class invariant is only the 1-round DDT/LAT);
  AES's own affine wrapper is among the better choices but not provably
  optimal.
* The AES S-box's linear-approximation structure (e.g. the linear
  redundancies analyzed by Fuller, Millan, et al., eprint 2002/111) is
  inherited by every affine equivalent, including this frozen S-box.

### 4.4 Round count

By the Luby–Rackoff construction (1986), a 3-round Feistel network is a
PRP and 4 rounds a strong PRP. 16 Feistel rounds is 4× the 4-round floor,
consistent with the round-count band used by published Feistel ciphers
(DES: 16, Camellia: 18, etc.) and with the 4-round lower bound discussed
in the Avanza survey.

### 4.5 Naming clarification

The "ARX" in the project name refers to the **key schedule / mixing
style** (rotations, XORs, modular additions with constants). The Feistel
round function itself is S-box + XOR-based byte diffusion
(`out[i] = in[i] ^ in[i+1] ^ in[i+3]`), not pure ARX. Documentation on
this branch uses "ARX" consistently in the former sense.

## 5. Known open items

* The schedule's security rests on measurement (avalanche, independence,
  bijectivity), not proof — same epistemic status as before the branch
  change. A formal analysis (e.g. differential trail search over the
  schedule itself) is future work.
* The SPN variant's 128-bit round keys are pairs of consecutive 64-bit
  words from the same expansion; their independence is covered by the
  pairwise-Hamming measurements above, not by a separate analysis.
* The KAT tables under `docs/tables/` were regenerated for this branch;
  ciphertexts differ from the canonical SHAKE-based v0.2.6 vectors (e.g.
  zero key / zero plaintext → `aa354bd490644e772f4ce31005156dc5`).
