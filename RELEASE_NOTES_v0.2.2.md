# Herringfish v0.2.2

## ✨ Highlights
* Constant-time S-box integration – `src/cipher/sbox_ct.rs` with `subtle`, `encrypt_block_ct`/`decrypt_block_ct` added and benchmarked
* Specification hardening – frozen affine AES S-box formalised, S-box generation updated to frozen parameters `a=0x11`, `b=0x71`
* Reduced-round KATs – Feistel parameterised for variable rounds, KATs generated for 4/6/8 rounds
* AVX2 diffusion benchmark – scalar vs AVX2 speedup ~2.7x, example gated to x86_64
* Key-schedule independence tests formalised with 100k samples
* Hull/meet-in-the-middle enumeration – top-K per-byte, cache-timing statistical analysis with Welch's t-test

## 🐛 Fixes
* Import fix for `ExtendableOutput` in `kat_reduced_rounds`
* Normalised line endings, added `linear_trail_search_exact` example
* README rewritten to remove questions, clarify security claims and research maturity

## 🔬 Cryptography
* No changes to core Feistel ARX primitive
* S-box frozen for v0.2 interoperability
* Differential/linear sampling extended to 12 rounds, margin remains experimental

## 🧪 Testing
* Linux – cargo test / clippy / examples
* Windows – examples build and run
* macOS – CI compatible, AVX2 gated

**Full Changelog**: v0.2.1...v0.2.2
- 54acc67 chore: normalize line endings, add linear_trail_search_exact example
- 754a01c docs: update security margin summary for v0.2.2 and increase hull enumeration budget
- cec15b6 feat(eng): add AVX2 diffusion benchmark and formal key-schedule independence tests
- 960312b feat(cipher): parameterise Feistel rounds and generate reduced-round KATs
- 4315184 feat(eng): add CI hooks, SIMD benchmark placeholder, and clippy cleanup
- c791261 feat(cryptanalysis): refine hull enumeration with top-K per-byte and add statistical cache-timing with Welch's t-test
- 49e990f feat(cryptanalysis): improve cache-timing stats and meet-in-the-middle hull enumeration
- aff11b8 feat(cryptanalysis): add cache-timing measurement and meet-in-the-middle hull skeleton
- 23ed815 feat(cryptanalysis): add trail/hull heuristic analysis and side-channel review of SHAKE expansion
- a456896 feat(cipher): integrate constant-time S-box into Feistel path and benchmark overhead
- 06338ea feat(cryptanalysis): add exact differential characteristic enumeration with DDT and diffusion
- 3e28eed feat(cipher): remove dead code and unused domain constant from feistel_arx
- b595d69 feat(example): add specification validation example for v0.2
- 3136f41 feat(cipher): add constant-time S-box lookup module with subtle
- 5697551 docs(spec): update S-box generation section to reflect frozen affine AES S-box for v0.2
- d9afb1c docs(readme): rewrite README per review feedback
- b3bb379 docs(readme): rewrite README to remove questions, clarify security claims, and reflect v0.2 research maturity
- db37f3a docs(readme): rewrite README to remove questions and reflect v0.2 research maturity
- 91ef2d1 docs(security): update S-box generation description to frozen affine AES equivalent
- 11689ea Merge remote changes
- 8bc3fbb docs(readme): update Current Status for Feistel ARX v0.2 progress
- b635cbe Create rust.yml
- a59bbd7 fix(example): import ExtendableOutput from shake for kat_reduced_rounds
