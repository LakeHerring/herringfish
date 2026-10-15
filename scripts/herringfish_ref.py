#!/usr/bin/env python3
"""Independent Python reference for Herringfish Feistel ARX v0.2, solo-arx variant.

Written from docs/specification/feistel_arx_v0.2.md (sections 3-8 and 12-S), NOT
from the Rust source. Two things are therefore checked against the Rust code:

  1. the S-box is DERIVED here from its definition (affine-equivalent of the AES
     S-box, S[x] = a*AES_SBOX[x] ^ b over GF(2^8), a=0x11, b=0x71) and compared
     with the frozen table archived in docs/tables/sbox_accepted.txt;
  2. the whole cipher (key schedule + Feistel) is run on every vector in the
     four KAT files under docs/tables/ and compared with the stored ciphertexts.

Limits of this check, stated honestly: the author of this file also read the Rust
code, so it is independent in implementation language and in derivation of the
S-box, not in authorship. It shares the spec's own ambiguities, if any remain.
Observed agreement means "spec text and implementation agree", not "secure".

Run (from anywhere):  python -I scripts/herringfish_ref.py
Exit status 0 = everything matched.
"""

import re
import sys
from pathlib import Path

M64 = (1 << 64) - 1
ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------- S-box (spec section 8)


def gf_mul(a: int, b: int, poly: int = 0x11B) -> int:
    """Multiplication in GF(2^8) modulo the AES polynomial x^8+x^4+x^3+x+1."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return r


def rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def aes_sbox() -> list:
    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if gf_mul(x, y) == 1:
                inv[x] = y
                break
    return [
        inv[x] ^ rotl8(inv[x], 1) ^ rotl8(inv[x], 2) ^ rotl8(inv[x], 3) ^ rotl8(inv[x], 4) ^ 0x63
        for x in range(256)
    ]


def herringfish_sbox(a: int = 0x11, b: int = 0x71) -> list:
    return [gf_mul(a, s) ^ b for s in aes_sbox()]


# ---------------------------------------------------------------- key schedule (spec 12-S)


def rotl(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64 if n else x


def rotr(x: int, n: int) -> int:
    return rotl(x, 64 - n)


GOLDEN64 = 0x9E3779B97F4A7C15
C = [(GOLDEN64 * (2 * i + 1)) & M64 for i in range(16)]


def full_mix(w: list, g: int) -> list:
    w0, w1, w2, w3 = w  # all four right-hand sides use the OLD words
    return [
        (w0 + (rotl(w1, 7) ^ rotl(w2, 15) ^ rotl(w3, 23) ^ C[g % 16])) & M64,
        (w1 + (rotl(w0, 19) ^ rotl(w2, 29) ^ rotl(w3, 41) ^ C[(g + 5) % 16])) & M64,
        (w2 + (rotl(w0, 33) ^ rotl(w1, 47) ^ rotl(w3, 11) ^ C[(g + 9) % 16])) & M64,
        (w3 + (rotl(w0, 51) ^ rotl(w1, 9) ^ rotl(w2, 37) ^ C[(g + 14) % 16])) & M64,
    ]


def xor_net(w: list) -> list:
    w0, w1, w2, w3 = w
    return [
        w0 ^ rotr(w1, 21) ^ rotr(w3, 33),
        w1 ^ rotr(w2, 25) ^ rotr(w0, 37),
        w2 ^ rotr(w3, 41) ^ rotr(w1, 17),
        w3 ^ rotr(w0, 53) ^ rotr(w2, 13),
    ]


def round_keys(key: bytes, rounds: int) -> list:
    assert len(key) == 32
    state = [int.from_bytes(key[8 * i : 8 * i + 8], "little") for i in range(4)]
    out = []
    for i in range(rounds):
        g = 2 * i
        state = full_mix(state, g)
        state = full_mix(state, g + 1)
        state = xor_net(state)  # the state is carried to the next round
        out.append(state[0] ^ state[1] ^ state[2] ^ state[3])
    return out


# ---------------------------------------------------------------- cipher (spec 3-6)


def f_function(x: int, k: int, sbox: list) -> int:
    xb, kb = x.to_bytes(8, "little"), k.to_bytes(8, "little")
    y = [sbox[xb[i] ^ kb[i]] for i in range(8)]
    d = bytes(y[i] ^ y[(i + 1) % 8] ^ y[(i + 3) % 8] for i in range(8))
    return int.from_bytes(d, "little")


def encrypt(key: bytes, pt: bytes, rounds: int, sbox: list) -> bytes:
    assert len(pt) == 16
    left = int.from_bytes(pt[:8], "little")
    right = int.from_bytes(pt[8:], "little")
    for k in round_keys(key, rounds):
        left, right = right, left ^ f_function(right, k, sbox)
    return left.to_bytes(8, "little") + right.to_bytes(8, "little")


# ---------------------------------------------------------------- KAT files


def parse_kats(path: Path, default_rounds: int = 16):
    """Yield (rounds, key, plaintext, ciphertext). Handles the three file styles."""
    rounds, key, pt = default_rounds, None, None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"\[rounds=(\d+)\]$", line)
        if m:
            rounds = int(m.group(1))
            continue
        if line.startswith("#"):
            m = re.search(r"(\d+) rounds KAT$", line)
            if m:
                rounds = int(m.group(1))
            continue
        m = re.match(r"(?i)(key|plaintext|ciphertext)\s*[:=]\s*([0-9a-fA-F]+)$", line)
        if not m:
            continue
        field, value = m.group(1).lower(), bytes.fromhex(m.group(2))
        if field == "key":
            key = value
        elif field == "plaintext":
            pt = value
        else:
            yield rounds, key, pt, value


def main() -> int:
    ok = True

    # 1. S-box derived from its definition vs the frozen table
    table = [int(t, 16) for t in (ROOT / "docs/tables/sbox_accepted.txt").read_text().split()]
    derived = herringfish_sbox()
    same = derived == table
    print(f"S-box derived from definition (AES poly 0x11B, a=0x11, b=0x71) == frozen table: {same}")
    print(f"  bijective: {len(set(derived)) == 256}")
    ok &= same

    # 2. KAT files, using the DERIVED S-box (so the table is not trusted at all)
    total = 0
    for name in (
        "kat_vectors_v02.txt",
        "kat_reduced_rounds_v02.txt",
        "kat_reduced_all.txt",
        "kat_expanded_v02.txt",
    ):
        passed = failed = 0
        for rounds, key, pt, ct in parse_kats(ROOT / "docs/tables" / name):
            got = encrypt(key, pt, rounds, derived)
            if got == ct:
                passed += 1
            else:
                failed += 1
                print(f"MISMATCH {name} rounds={rounds}\n  key {key.hex()}\n  pt  {pt.hex()}\n  got {got.hex()}\n  exp {ct.hex()}")
        print(f"docs/tables/{name}: {passed} passed, {failed} failed")
        total += passed
        ok &= failed == 0

    print(f"{'ALL MATCH' if ok else 'MISMATCH'} ({total} vectors checked against the Python reference)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
