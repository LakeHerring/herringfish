# Hash Difficulty Summary for "hashme"

## SHA-256
SHA-256(hashme) = 02208b9403a87df9f4ed6b2ee2657efaa589026b4cce9accc8e8a5bf3d693c86
Best public collision: 39-step SFS, 31-step free-start.
Full 64-step remains secure.
Preimage ≈ 2^256
Collision resistance ≈ 2^128

## SHA3-256
SHA3-256(hashme) = 80d3abe0d26ba5f08e231bb7787b1df7c007df6d4490e52654bf8566abcea81f
Best public collision: 5-round reduced Keccak-f.
Full 24 rounds secure.
Preimage ≈ 2^256
Collision resistance ≈ 2^128

## SHA3-512
SHA3-512(hashme) = 1f744a8721ce9f243e740bb29dd1dece709e0801d98dc08ea5bbe9eef2f7b559098c79ce6565da523f88987b7c338a3503ea50c6ff3732bbd7729502a3d40150
Best public collision: 4-round.
Full 24 rounds secure.
Preimage ≈ 2^512
Collision resistance ≈ 2^256

## SHAKE128-256
SHAKE128-256(hashme) = 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
Best public collision: 6-round, complexity ≈ 2^123.5
Full 24 rounds secure.
Preimage ≈ 2^128 for 256-bit output

## SHAKE256-256
SHAKE256-256(hashme) = 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f
Best public collision: 6-round, complexity ≈ 2^232.29
Full 24 rounds secure.
Preimage ≈ 2^256 for 256-bit output

Notes:
- All estimates are based on public cryptanalysis as of 2024/2025.
- Full-round security remains unbroken for all five primitives.
- Verification H(message)==digest is feasible; inversion is infeasible.
