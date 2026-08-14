# Herringfish Prototype Specification v0.1

## Status
Experimental prototype. Not frozen.

## Parameters
* Cipher type: Substitution-Permutation Network (SPN)
* Block size: 128 bits (16 bytes)
* Key size: 256 bits (32 bytes)
* Rounds: 14
* State: 4x4 byte matrix

## Round Structure
Encrypt round:
1. SubBytes - 8-bit S-box applied to each byte
2. ShiftRows - row i shifted left by i bytes
3. MixColumns - MDS-like linear diffusion over GF(2^8) with matrix:
   [2 3 1 1]
   [1 2 3 1]
   [1 1 2 3]
   [3 1 1 2]
4. AddRoundKey - XOR with round key

Final round omits MixColumns.

Decrypt round:
AddRoundKey -> InvMixColumns -> InvShiftRows -> InvSubBytes

## Key Schedule
Placeholder expansion:
* Master key 256 bits -> 15 round keys 128 bits each
* Derivation uses simple rotation + round constants
* This is intentionally weak for prototyping; will be replaced after analysis

## Non-linear component
Prototype uses AES S-box:
S[x] = affine( inv(x) in GF(2^8) )
InvS-box used for decryption.

Future work: design Herringfish-specific S-box with good DDT/LAT properties.

## Rationale
SPN chosen for:
* Well-studied diffusion properties
* Easy constant-time implementation
* Clear separation of non-linear and linear layers
* Facilitates differential/linear analysis

14 rounds provides initial security margin for reduced-round experiments.
Prototype aims for correctness and testability before cryptanalysis.

## Known Answer Test
Key = 00...00
Plaintext = 00...00
Ciphertext = 1128f96930a7c88510c577b37e29541a

## Next steps
* Replace placeholder key schedule with cryptographically strong expansion
* Design custom S-box and verify DDT/LAT
* Implement reduced-round tests
* Differential and linear cryptanalysis
* Avalanche measurements
* Constant-time audit
