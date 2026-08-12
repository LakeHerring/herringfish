# herringfish

Cross-platform cryptography math attack toolkit in Rust, targeting SHA-2, SHA-3 and SHAKE families.

## Overview

`herringfish` is a research-oriented toolkit for mathematical cryptanalysis of hash functions. It focuses on the internal structures of SHA-2, SHA-3 and SHAKE rather than black-box collision search.

Supported families:
- **SHA2** – SHA-256, SHA-512 variants
- **SHA3** – Keccak-f permutation, SHA3-256/512
- **SHAKE** – SHAKE128, SHAKE256 extendable-output functions

Modules:
- `primitives` – Reference implementations and differential/linear hooks for SHA-256 compressor, Keccak-f, SHA3/SHAKE
- `attack` – Differential, Linear, Algebraic attack scaffolding with a common `Attack` trait
- `math` – Combinatorics, DDT construction, Keccak χ DDT, linear algebra utilities, probability helpers

## Building

```bash
cargo build --release
```

The release profile enables LTO, opt-level 3, strip and single codegen unit for crypto hot paths.

## CLI usage

```bash
cargo run -- --family SHA3 --attack differential --rounds 6
cargo run -- --family SHA2 --attack differential --rounds 16
cargo run -- --ddt
cargo run -- --keccak-chi-ddt
```

Options:
- `--family <SHA2|SHA3|SHAKE>`
- `--attack <differential|linear|algebraic>`
- `--rounds <n>` default 4
- `--ddt` compute DDT for PRESENT S-box
- `--keccak-chi-ddt` print Keccak χ DDT summary
- `--help`

## Project layout

```
src/
  primitives/  sha2.rs sha256.rs sha3.rs shake.rs keccak.rs
  attack/      differential.rs linear.rs algebraic.rs mod.rs
  math/        combinatorics.rs ddt.rs keccak_chi_ddt.rs linear_algebra.rs probability.rs
scripts/       update_acvp_vectors.sh / .ps1
tests/vectors/ ACVP test vectors
```

## Development notes

- The current implementation contains reduced-round demonstrators and placeholders for full round analysis. Replace placeholders with real Keccak-f / SHA-256 round analysis for production research.
- Warnings are tracked; see `cargo check` output.
- ACVP vectors can be refreshed with `scripts/update_acvp_vectors.sh`.

## License

MIT

## Compliance

See [COMPLIANCE.md](COMPLIANCE.md). Research use only.

## Side-channel considerations

See [SIDE_CHANNEL.md](SIDE_CHANNEL.md).
