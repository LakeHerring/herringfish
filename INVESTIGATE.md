Yes — as a research direction, that is actually quite interesting, but I would avoid simply making “Blowfish + SHA-3” a construction by concatenation. The more interesting question is what role the SHA-3/SHAKE machinery plays inside Herringfish.

Blowfish gives you a useful historical starting point: a Feistel cipher with key-dependent S-boxes and a substantial key schedule. SHA-3/SHAKE gives you a very different primitive: the Keccak sponge/permutation.

That gives Herringfish two fundamentally different sources of cryptographic structure.

A potentially interesting Herringfish architecture

One direction I'd investigate is:

                 256-bit Herringfish Key
                          │
                          ▼
                 ┌─────────────────┐
                 │  SHAKE256-based │
                 │   key expansion │
                 └────────┬────────┘
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
          Round key     S-boxes     Constants
             │            │            │
             └────────────┼────────────┘
                          ▼
Plaintext ───────► Herringfish Core ───────► Ciphertext
                          │
                    Feistel/SPN
                          │
                   SHA-3-derived
                  nonlinear mixing

The important part is that SHAKE wouldn't necessarily be the cipher itself.

It could instead provide cryptographically strong material for the construction.

Why SHAKE is particularly interesting

I'd actually favor SHAKE256 over SHA3-256 for experimentation.

SHA3-256 gives you a fixed 256-bit output:

SHA3-256(input) → 256 bits

SHAKE256 is an extendable-output function:

SHAKE256(input) → arbitrary number of bits

That is useful for generating things such as:

round constants
subkeys
S-box material
initialization material
domain-separated parameters
test vectors
potentially larger internal state material

For example, conceptually:

K
│
├── SHAKE256("HERRINGFISH-SBOX" || K)
│       └── S-box material
│
├── SHAKE256("HERRINGFISH-KEY" || K)
│       └── round keys
│
└── SHAKE256("HERRINGFISH-CONST")
        └── round constants

The domain separation is important. You don't want different purposes accidentally sharing the same cryptographic derivation.

But there is a major design question

There are two very different ways we could approach this.

Approach A — SHAKE-derived Herringfish

Use SHAKE primarily during key setup.

For example:

256-bit key
     │
     ▼
 SHAKE256
     │
     ├── S-boxes
     ├── round keys
     └── constants
             │
             ▼
       Blowfish-like
       Feistel network
             │
             ▼
         ciphertext

This would make Herringfish somewhat conceptually related to Blowfish while replacing its key-expansion machinery with a modern sponge-derived mechanism.

Approach B — Keccak-inspired Herringfish

This is more radical.

Instead of merely using SHAKE to generate parameters, borrow concepts from the Keccak permutation:

State
 │
 ├── nonlinear transformation
 ├── bit permutation
 ├── diffusion
 └── round constants
        │
        ▼
      State'

Then design a new block-cipher structure around those principles.

That would make Herringfish much more original.

I would NOT directly reuse Keccak's round function

This is important.

If the goal is to create a genuinely new cipher, I wouldn't do:

Blowfish + Keccak round function = Herringfish

That's essentially composition rather than designing a new primitive.

Instead, I'd extract design principles:

From Blowfish:

Feistel structure
key-dependent nonlinear components
strong key diffusion
many rounds
asymmetric-looking round transformations

From Keccak/SHA-3:

nonlinear transformations
strong diffusion
permutation-based thinking
round constants
bit-level mixing
sponge-derived key material

Then develop a new construction.

One idea I'd seriously investigate

A 128-bit Feistel Herringfish with a SHAKE-derived key schedule:

                  256-bit key
                       │
                       ▼
                  SHAKE256
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
       Round material       S-box material
             │                   │
             └─────────┬─────────┘
                       ▼


             ┌───────────────────┐
             │   128-bit state   │
             │                   │
             │    L       R      │
             └────┬───────┬──────┘
                  │       │
                  │       ▼
                  │    F(R,Kᵢ)
                  │       │
                  └── XOR ◄┘
                      │
                      ▼
                    Swap
                      │
                      ▼
                    Round
                      │
                     ...
                      │
                      ▼
                  Ciphertext

But the F function is where I'd make Herringfish distinctive.

For example, it could combine:

F(x, k)
    │
    ├── nonlinear transformation
    ├── rotation/permutation
    ├── modular addition
    ├── XOR
    └── diffusion layer

That's potentially a Feistel + ARX + SHAKE-derived-material design.

That would be much more interesting to cryptanalyze than simply wrapping SHAKE around Blowfish.

There's another possibility I like even more

Instead of generating fixed S-boxes during compilation, Herringfish could have key-dependent S-boxes generated from SHAKE256.

Something conceptually like:

             256-bit master key
                     │
                     ▼
                 SHAKE256
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       S-box 0    S-box 1    S-box N
          │          │          │
          └──────────┼──────────┘
                     ▼
              Key-dependent
               nonlinear layer

That gives us an immediate cryptanalysis question:

Does the SHAKE-derived S-box generation actually improve security, or does it introduce exploitable structure?

That's exactly the sort of question Herringfish should be designed around.

And it connects very nicely to your original inspiration from Blowfish.