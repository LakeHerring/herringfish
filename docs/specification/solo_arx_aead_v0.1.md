# Herringfish Solo-ARX AEAD v0.1 (experimental)

**Branch:** `solo-arx`
**Implementation:** `src/cipher/aead.rs` (`HerringfishAead`)
**Status:** experimental construction. Not production cryptography. No independent review.
**Supersedes:** the unversioned AEAD in commit `bca2397` (see §9).

This document is normative for the AEAD mode on the `solo-arx` branch. It does
not modify the frozen v0.2 block-cipher specification.

## 1. Construction

CTR-mode encryption plus GHASH authentication, following the structure of NIST
SP 800-38D (GCM) with the Herringfish solo-ARX block cipher in place of AES.

| Symbol | Meaning |
| --- | --- |
| `E_K` | solo-ARX Feistel block encryption, 16 rounds, 128-bit block, 256-bit key `K` (`FeistelArx::new`). Operates on 16-byte strings exactly as `FeistelArx::encrypt_block` does. Its internal byte order is defined by `feistel_arx_v0.2.md` §3 and is not restated here. |
| `IV` | 96-bit nonce, 12 bytes. |
| `A` | associated data, any byte length `len(A) < 2^61`. |
| `P`, `C` | plaintext and ciphertext, equal byte length, `len ≤ 16·(2^32 − 2)`. |
| `T` | tag, 128 bits, never truncated. |
| `‖`, `⊕` | concatenation, bitwise XOR. |
| `[n]_w` | `n` as a `w`-bit big-endian unsigned integer. |

## 2. Blocks and bit order

Every 128-bit quantity in this mode is a 16-byte string. For GF(2^128)
arithmetic the bit string `x_0 x_1 … x_127` is read with `x_0` the **most
significant bit of byte 0** and `x_127` the least significant bit of byte 15
(NIST SP 800-38D §6.3). As an integer, `x` is `u128::from_be_bytes(block)`;
bit `x_i` is integer bit `127 − i`.

## 3. GF(2^128) multiplication

The field is `GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)`. The coefficient of `x^i`
is `x_i` in the bit order of §2. Multiplication `X · Y` is NIST SP 800-38D
Algorithm 1:

```text
Z_0 = 0,  V_0 = Y
for i = 0 .. 127:
    Z_{i+1} = Z_i ⊕ V_i          if x_i = 1
              Z_i                if x_i = 0
    V_{i+1} = V_i >> 1           if LSB(V_i) = 0
              (V_i >> 1) ⊕ R     if LSB(V_i) = 1
return Z_128
```

`>>` is a logical right shift of the 128-bit integer by one position and
`R = 0xE1 ‖ 0^120` (integer `0xE1 << 120`). `LSB(V)` is integer bit 0, which is
`x_127`.

An implementation must not branch on `x_i` or `LSB(V_i)` (§7).

## 4. GHASH

For a hash subkey `H` and blocks `X_1 … X_m`:

```text
Y_0 = 0^128
Y_i = (Y_{i-1} ⊕ X_i) · H        i = 1 .. m
GHASH_H(X_1 … X_m) = Y_m
```

The input blocks for `(A, C)` are

```text
A ‖ 0^v ‖ C ‖ 0^u ‖ [8·len(A)]_64 ‖ [8·len(C)]_64
```

where `v` and `u` are the smallest non-negative bit counts that make `A ‖ 0^v`
and `C ‖ 0^u` multiples of 128 bits. An empty `A` or `C` contributes no blocks.
The length block is always present.

## 5. Encryption and decryption

```text
H  = E_K(0^128)
J0 = IV ‖ [1]_32
```

`inc32` adds 1 to the last 32 bits of a block, modulo 2^32, leaving the first
96 bits unchanged. Data block `j` (0-based) is encrypted with counter block

```text
CB_j = IV ‖ [j + 2]_32          (= inc32^(j+1)(J0))
```

so the data counters are `2, 3, …` and **no data counter block equals `J0`**.
For `P = P_0 ‖ … ‖ P_{n-1}` with a possibly partial last block:

```text
C_j = P_j ⊕ MSB_{len(P_j)}( E_K(CB_j) )
T   = GHASH_H(A, C) ⊕ E_K(J0)
```

The maximum number of data blocks is `2^32 − 2` (counters `2 … 2^32 − 1`), i.e.
`len(P) ≤ 16·(2^32 − 2)` bytes, equal to NIST's `2^39 − 256` bits. An
implementation must reject longer inputs rather than let the counter wrap. It
must also reject `len(A) ≥ 2^61` bytes so the 64-bit bit-length does not wrap.

Decryption: recompute `T' = GHASH_H(A, C) ⊕ E_K(J0)`, compare `T'` and `T` over
all 16 bytes without early exit, and only if equal return `P` (CTR applied to
`C`). On mismatch no plaintext is released.

## 6. Nonce requirement

`(K, IV)` must never be used for two different messages. The mode has no nonce
misuse resistance. Reuse reveals `P ⊕ P'` as in any CTR mode and, as in GCM,
exposes `H`, after which tags can be forged.

## 7. Implementation notes

* The reference implementation performs the GF multiplication with mask
  arithmetic (no branch on `x_i` or `LSB(V_i)`) and compares tags without early
  exit. This is a statement about those two code paths only. `E_K` is
  the cipher's default table-lookup path, which indexes the S-box with secret
  data, so the mode as a whole is **not** claimed constant-time. See
  `docs/side_channel_review_v0.2.md`.
* `GHASH` is implemented as a pure function of `(H, A, C)` so that it can be
  tested against vectors that do not involve the block cipher.

## 8. Test vectors

| Kind | Status | Where |
| --- | --- | --- |
| GHASH, McGrew–Viega GCM spec Test Case 2 (`H`, one 16-byte `C`, empty `A`) | independent, published | `ghash_mcgrew_viega_tc2` |
| GHASH derived from NIST ACVP-AES-GCM-1.0, tgId 1, tcId 1–15 (15-byte `A`, empty `C`) | independent: `H` and `E_K(J0)` from OpenSSL AES-128, checked against the NIST tags by `scripts/gen_ghash_kat.py` | `ghash_acvp_derived_kats` |
| `J0` is not a data counter block; counters start at 2 | regression | `ctr_never_uses_j0_counter` |
| Counter-limit boundary arithmetic | regression | `length_limits` |
| Herringfish AEAD full-mode KATs | **none yet.** Any future vectors will be self-generated and are regression-only, not independently verified. | n/a |

The ACVP tags themselves cannot be reproduced by this mode because they contain
`AES_K(J0)`. Only the GHASH component is validated against NIST data.

## 9. Differences from the unversioned AEAD in `bca2397`

This is a **construction change** and a ciphertext/tag compatibility break. No
stable vectors existed for the old mode.

1. **GF multiplication.** The old `xtime` shifted left but tested the low bit
   and reduced into byte 0. Observed (scratch test, 2000 random pairs, fixed
   seed): the old multiply was commutative in 497/2000 and associative in
   1043/2000, so it was not a field multiplication and the old GHASH was not a
   polynomial MAC. It also failed to reproduce the McGrew–Viega Test Case 2
   GHASH value. An uncommitted working-tree variant (left shift, reduce into
   byte 15) was a correct field multiplication (associative 2000/2000,
   bit-reversal isomorphic to Algorithm 1 in 2000/2000) but used a non-NIST bit
   order and also failed Test Case 2; it was not adopted so NIST vectors can
   validate the code.
2. **Counter layout.** `bca2397` encrypted data block 0 with counter 1 and
   used `J0 = IV ‖ [1]_32`, so keystream block 0 equalled the tag mask
   `E_K(J0)`. The uncommitted working-tree variant used counter 0 for both and
   had the same overlap. Standard GCM starts data at `inc32(J0)`; so does this
   version.

Hypothesis, **not tested**: with `E_K(J0)` equal to keystream block 0, an
attacker who knows the first plaintext block learns `E_K(J0)` and then the
GHASH value `S` from the tag. `S` is a polynomial in the secret `H`, so root
finding over GF(2^128) could recover `H`, enabling same-nonce tag forgery. The
overlap is removed here; the attack was not implemented.

## 10. Status

| Claim | Status |
| --- | --- |
| Mode matches this document | implemented, unit-tested |
| GHASH matches NIST SP 800-38D | tested against 16 independent vectors |
| Counter layout has no J0 overlap | regression-tested |
| Security of the mode | **not analysed.** GCM-style bounds assume `E_K` is a good PRP, which is itself unproven for Herringfish. |
| Constant-time | not claimed (§7) |
| Related-key, reduced-round, nonce-misuse behaviour of the mode | not tested |
