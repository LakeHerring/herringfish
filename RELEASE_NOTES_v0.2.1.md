# Herringfish v0.2.1

## ✨ Highlights
* Feistel ARX v0.2 initial release – 128-bit balanced Feistel with 8-bit S-box, linear diffusion, SHAKE256 key schedule
* Frozen S-box – affine equivalent of AES S-box with `a=0x11`, `b=0x71`, DDT_max=4, LAT_max=32
* Specification and hardening docs added
* Reduced-round KATs and security margin documentation

## 🐛 Fixes
* Repository cleanup – removed legacy attack/math/primitives modules
* Cargo metadata updated

## 🔬 Cryptography
* Initial Feistel ARX v0.2 implementation with frozen S-box
* Specification `docs/specification/feistel_arx_v0.2.md` introduced
* DDT/LAT matrices and S-box tables added

## 🧪 Testing
* Linux – build and examples
* Windows – build
* macOS – build

**Full Changelog**: initial...v0.2.1
- cfaf86d refactor(src): remove legacy attack/math/primitives modules
- 873d43e chore(repo): update root docs and Cargo metadata
- 4f774db feat(examples): add Feistel ARX cryptanalysis examples
- c4b88bf docs(spec): add Feistel ARX v0.2 specification and hardening docs
- d7bbbf8 feat(tables): add DDT/LAT matrices and S-box tables
- ab0faa5 feat(cipher): add Feistel ARX v0.2 implementation with frozen S-box
- ae1ecf3 feat: reduced-round KATs, update spec and security margin
- ae8b3e0 feat: reproduction tests for reduced-round attacks and extend identify_hash with best-known attack data
- 34e726e chore: README with attack families principles and How to use for a digest guide
- a6bd932 feat: attack families and principles documentation
- 9ab74b0 feat: bench_hash example for throughput and preimage time estimate
- 3a4b9d0 feat: hash difficulty summary for hashme digests
- 8145cb6 feat: side-channel considerations to identify_hash demo
- 33fed15 feat: concrete demos: identify_hash and identify_primitive
- a2d151a feat: PrimeField unit tests and SHA-256 reduced experiment demo
- 36453fb refactor: math modules under sub-modules; implement PrimeField arithmetic and hash attack experiments
- 4f269cd feat: attack/hash and math submodules; add finite_field, bigint, matrix, polynomial, lattice, ntt stubs
- f91bc31 refactor: primitives under hash/symmetric/asymmetric/pqc and align imports; update README architecture
