#!/usr/bin/env python3
"""Derive cipher-independent GHASH known-answer vectors from NIST ACVP AES-GCM.

Why: an AES-GCM tag is GHASH_H(A, C) XOR AES_K(J0).  Herringfish AEAD uses a
different block cipher, so ACVP tags cannot be compared to Herringfish tags.
GHASH itself depends only on (H, A, C), so for each ACVP AAD-only vector we
derive H = AES_K(0^128) and the GHASH value = tag XOR AES_K(J0), then check
that an independent GHASH implementation (NIST SP 800-38D Algorithm 1, below)
reproduces it.  The printed triples (H, A, GHASH) are what the Rust unit test
`ghash_acvp_derived_kats` embeds.

Source vectors: NIST ACVP-AES-GCM-1.0, testGroup tgId=1, tcId 1..15
(AAD only, empty payload).  The tags below equal those in
tests/vectors/ACVP-AES-GCM-1.0/expectedResults.json.

Run:  python -I scripts/gen_ghash_kat.py
Needs: Python 3 stdlib and the `openssl` CLI (used for AES-128-ECB only).
"""

import subprocess
import sys

# (key, iv, aad, tag), hex.  AES-128 keys, 96-bit IVs, 15-byte AAD.
VECTORS = [
    ("4B2CBE2158F5D6A28CC798DF4F99F777", "3851BAF79831605B75086E79", "4607F76F4FDA85DAFDC8CE085E0CE5", "9E557D92647C1510D4101EBEED0C52DD"),
    ("32E106F67A99F89788D168BEB6596400", "491F4B2DF6D0288DB54716B6", "65FC70A3CC2E0F14B3C56216881F8C", "6A7BBCDB4834109B6AA067B5358D94F3"),
    ("15BF034EE6DC3DA6296EE138B90FC0CE", "DE8CB48EE0F1CB57F4E9FFB5", "EDDE20197C7DED0B293B061F349840", "72445E31C5DF05DFA2CCBA54AE385DFD"),
    ("A1BAF46B4B1E8C169EA89892697C1CB4", "B857C80F75CC7336114DEF84", "6A4687585852AE3438D97CC703EE17", "4F8508CB9C385C72935DEFD397BEB317"),
    ("0E5EB84C7E64825C7569712DFEB2F156", "F88AD682C50FD2EFBF5DFFA2", "2BC528CEB661427363C3D7C41A474B", "374A8920101702D1CCDE488A3ED7BD74"),
    ("BF5C3A9C65D72512F752A09C9B5ABA59", "0B8AE56978B462A5C0F8486C", "9D43A96F28E0753DEF6E6E07FD8442", "350DB3900067E56F16C77C835DAC544C"),
    ("28DCCD63B305BB169BB7E85FE55591DF", "407F6C53CCF5DDA6F868B22C", "8F8EDFA6E95B755976955ED3483CD2", "F150351CD6C3D09ED6F65CCDD9016329"),
    ("3AD410F60CF85C923F2D9CE336E6A185", "FE37880DC4531AD581C4E24D", "900865D0DB20458368F9A191775A58", "7F6917FC8C4437E897DED97F56BAF97E"),
    ("1D650E5AD0B45A2A519DE40203C271CF", "3FE45FF564B983251816574D", "BF4D54FB100225DB37D80AA5883B92", "7C0487B32951712B1C8B5A383D1D2C7D"),
    ("7B7473CA6E44320019A0DD324B77B5AD", "0F25C4D8969D268C89CF89DC", "EE74A91456154EA7DF2702E8069099", "3EB7851F7C2C22FE454487DC6F3DF568"),
    ("368EF87F3BA49549334D756F7127C264", "BE20E127CBEEB126BA5705A8", "0EE044D4503197D12D2773BAD595DD", "D4FAB95E8D69AEA9FBD8F5828D3BD431"),
    ("AC8B6AF21571F41B413DD940CC0CE10E", "F0EABB2B51EDA331A8F69401", "CAB5E1F3A6E9F334A1E3A0A480E430", "142EC77E700EA07AFEDCA19968237921"),
    ("95F171B040EDEC74200716786A4C9883", "8A099FB344B8D82105CDE359", "81FEBC3A769A3EC54CC2B2AF464EB5", "25A704866524EDF070813B81D076BC0A"),
    ("D933FFCCCF7F179277F2B409F089F497", "2B8E42BF97178EF7A6E4F745", "37E2149B37A2199F6DEF54B283A4C8", "17FFF7D09A61124C5D7B41EC93A030CF"),
    ("29214E6ABF1A50CBC3EA399138ED22FA", "F451A8FD6B66E538E72E655B", "AB966DC5A64F1FA1588ACC1CF4062C", "935A4D11F33268110BB7EC6ED1DA7440"),
]

R = 0xE1 << 120


def gmul(x: int, y: int) -> int:
    """NIST SP 800-38D Algorithm 1; blocks as big-endian 128-bit integers."""
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R if v & 1 else v >> 1
    return z


def ghash(h: int, aad: bytes, ct: bytes) -> int:
    def blocks(d: bytes):
        d = d + b"\x00" * (-len(d) % 16)
        return [int.from_bytes(d[i:i + 16], "big") for i in range(0, len(d), 16)]

    y = 0
    for b in blocks(aad) + blocks(ct):
        y = gmul(y ^ b, h)
    ln = ((len(aad) * 8) << 64) | (len(ct) * 8)
    return gmul(y ^ ln, h)


def aes128_ecb(key: bytes, block: bytes) -> bytes:
    out = subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-nopad", "-K", key.hex()],
        input=block, capture_output=True, check=True,
    ).stdout
    assert len(out) == 16
    return out


def main() -> int:
    # Self-check against McGrew-Viega GCM spec, Test Case 2 (H given, C one block).
    h2 = int("66e94bd4ef8a2c3b884cfa59ca342b2e", 16)
    c2 = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
    assert ghash(h2, b"", c2) == int("f38cbb1ad69223dcc3457ae5b6b0f885", 16)

    for n, (k, iv, aad, tag) in enumerate(VECTORS, 1):
        key, iv_b, aad_b = bytes.fromhex(k), bytes.fromhex(iv), bytes.fromhex(aad)
        h = aes128_ecb(key, bytes(16))
        ej0 = aes128_ecb(key, iv_b + b"\x00\x00\x00\x01")
        g = ghash(int.from_bytes(h, "big"), aad_b, b"")
        want = int.from_bytes(bytes.fromhex(tag), "big") ^ int.from_bytes(ej0, "big")
        if g != want:
            print(f"tcId {n}: GHASH disagrees with NIST tag", file=sys.stderr)
            return 1
        print(f'        ("{h.hex()}", "{aad.lower()}", "{g:032x}"),  // tcId {n}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
