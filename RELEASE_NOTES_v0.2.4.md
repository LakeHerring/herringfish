# Herringfish v0.2.4

## ✨ Highlights
* Example stability – `examples/hull_meet_in_middle.rs` now compiles cleanly with Rust 2021 edition patterns
* Meet-in-the-middle hull tooling usable for 2-round exact enumeration and MITM validation
* CI clean – format and cross-platform bench fixes applied

## 🐛 Fixes
* Fixed `cannot explicitly dereference within an implicitly-borrowing pattern` in DDT validation iterator chain
* Fixed unused variable `name` in reference tables printing – renamed to `_name`
* Suppressed dead_code warnings in `examples/hull_meet_in_middle.rs`
* Ran `cargo fmt` on `examples/hull_meet_in_middle.rs` to satisfy CI format check
* Gated `std::arch::x86_64` imports in benches with `#[cfg(target_arch = "x86_64")]` to allow builds on aarch64 CI

## 🔬 Cryptography
* No changes to Herringfish cryptographic primitives
* S-box remains frozen v0.2 with `a=0x11`, `b=0x71`, DDT_max=4, LAT_max=32
* Key schedule and round function unchanged

## 🧪 Testing
* `cargo check --example hull_meet_in_middle` passes
* `cargo test --lib` passes
* `cargo fmt -- --check` passes
* `cargo check --benches` passes on aarch64 and x86_64
* Example runs end-to-end in release mode with correct probability conservation and MITM consistency

**Full Changelog**: v0.2.3...v0.2.4
- 44e3ae4 docs(release): update RELEASE_NOTES_v0.2.4 with fmt and bench fixes
- 736de4c fix(bench): gate std::arch::x86_64 import in simd_sbox
- 548454d style: run cargo fmt on hull_meet_in_middle example
- 465fbb4 fix(bench): gate std::arch::x86_64 import behind target_arch
- 756dc87 chore(example): suppress dead_code warnings in hull_meet_in_middle
- e033fb1 Merge remote changes into main
- 8e7cb73 docs(release): add RELEASE_NOTES_v0.2.4
- 591e19e fix(example): resolve implicit deref pattern and unused variable in hull_meet_in_middle
- 80779fc chore(version): bump crate to 0.2.3 to match research tag
- fdc6591 docs(spec): finalize v0.2 formal specification and update README research status
- a2578cb docs(side-channel): add side-channel review v0.2
- 7fe5ef0 docs(spec): freeze normative v0.2 specification
- 5e5092f feat(bench): add systematic Criterion benchmarks for SIMD path
- d62f9bf feat(cryptanalysis): tune hull enumeration for 8-round 4+4 with weight-3 output diffs and max_active_bytes=4
- 380a030 chore(docs): update README to v0.2.3, formal spec draft, and security docs
- a6386c2 fix(example): define dr_in for hull meet-in-the-middle 8-round search
- fccfd2c feat(simd): true AVX2 gather S-box prototype; feat(cryptanalysis): 8-round hull with weight-2 diffs; bench: criterion SIMD S-box
- dba8a03 feat(cryptanalysis): increase hull meet-in-the-middle budget; feat(simd): prototype AVX2 S-box gather
- 205e689 Badges
- cac06e1 chore: add MIT LICENSE file
