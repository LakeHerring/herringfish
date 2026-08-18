# Herringfish v0.2.3

## ✨ Highlights
* Specification hardening – added §27 Normative Clarifications: prototype vs security claims, S-box affine parameters, SHAKE256 encoding, ARX definition, constant-time qualification
* Full-cipher statistical analysis – avalanche/SAC sampling added to `examples/statistical_full_cipher.rs`, results recorded in `docs/security_margin_summary.md`
* SIMD portability – `src/simd/avx2.rs` stub added, AVX2 diffusion benchmark gated to x86_64 for macOS CI compatibility
* Documentation – formal specification lead item in Current Status, research phase notes clarified

## 🐛 Fixes
* Fixed compilation of `simd_avx2_sbox` on non-x86_64 macOS targets – example now gated behind `#[cfg(target_arch = "x86_64")]`
* Suppressed example clippy warnings and cleaned test warnings
* Ran `cargo fmt` across workspace

## 🔬 Cryptography
* No changes to the Herringfish cryptographic primitives
* S-box remains frozen v0.2 with `a=0x11`, `b=0x71`, DDT_max=4, LAT_max=32
* Key schedule and round function unchanged

## 🧪 Testing
* Linux – `cargo test`, `cargo clippy`, examples build
* Windows – examples build and run
* macOS – CI compiles with x86_64 gates, AVX2 example correctly skipped on aarch64

**Full Changelog**: v0.2.2...v0.2.3
- d9f164e docs(spec): add normative clarifications for v0.2.2; update security margin with full-cipher stats; add SIMD stub
- 84db239 docs(spec): add v0.2.2 updates to feistel_arx_v0.2.md
- 870af7a docs: make Formal specification the lead item in Current Status
- 31f498b docs: reorder and clarify ongoing work items in Current Status
- d11d513 docs: note current research phase in Research Status
- a1ac07f docs: update README with v0.2.2 status, SIMD/benchmark progress, and completed work
- a0e245a fix: gate AVX2 example behind x86_64 target for macOS CI
- 923e7d0 style: run cargo fmt
- 92de411 fix: suppress example clippy warnings and clean test warnings
