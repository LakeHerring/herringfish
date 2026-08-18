# Herringfish — Unreleased

## ✨ Highlights

* Hardened the Feistel reference implementation with configurable rounds,
  a frozen v0.2 S-box, and a shared diffusion transform for cryptanalysis.
* Added bounded differential-characteristic search, weight profiling,
  linear-hull, targeted-verification, and SIMD benchmark tools.
* Added an explicit `--result-limit` to keep the round-3 optimizer's output
  memory-bounded while retaining the best results.

## 🐛 Fixes

* Corrected the round-3 optimizer so it does not include a nonexistent
  fourth-round cost in a three-round search.
* Made partial lower bounds diffusion-aware and corrected bounded-heap
  ordering and truncation reporting.

## 🔬 Cryptography

* No changes to the frozen Herringfish Feistel ARX v0.2 primitive parameters:
  128-bit block, 256-bit master key, 16 rounds, and the v0.2 S-box.
* The new tools search individual differential characteristics unless they
  explicitly report a differential or linear hull.

## 🧪 Testing

* `cargo test --lib --tests`
* `cargo test --example differential_round3_optimizer`
* Round-3 target-boundary regression: a characteristic at weight 37 is found
  for the documented optimizer configuration.

**Full Changelog**: to be set by the release manager when the version tag is created.
