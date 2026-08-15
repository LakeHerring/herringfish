# Herringfish v0.2.4

## ✨ Highlights
* Example stability – `examples/hull_meet_in_middle.rs` now compiles cleanly with Rust 2021 edition patterns
* Meet-in-the-middle hull tooling usable for 2-round exact enumeration and MITM validation

## 🐛 Fixes
* Fixed `cannot explicitly dereference within an implicitly-borrowing pattern` in DDT validation iterator chain
* Fixed unused variable `name` in reference tables printing – renamed to `_name`

## 🔬 Cryptography
* No changes to Herringfish cryptographic primitives
* S-box remains frozen v0.2 with `a=0x11`, `b=0x71`, DDT_max=4, LAT_max=32
* Key schedule and round function unchanged

## 🧪 Testing
* `cargo check --example hull_meet_in_middle` passes
* `cargo test --lib` passes
* Example runs end-to-end in release mode with correct probability conservation and MITM consistency

**Full Changelog**: v0.2.3...v0.2.4
- 591e19e fix(example): resolve implicit deref pattern and unused variable in hull_meet_in_middle
