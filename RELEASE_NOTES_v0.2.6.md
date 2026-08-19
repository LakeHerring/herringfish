# Herringfish v0.2.6

## ✨ Highlights
* Refactored the exact differential hull / meet-in-the-middle example around a single direction-aware `expand_round`, unifying forward and backward expansion (−414/+204 lines) and importing `diffuse` / `HERRINGFISH_SBOX_V02` from the crate instead of local copies.
* Rewrote the linear-hull meet-in-the-middle example as an exact/bounded LAT-based propagation engine with a configurable CLI (`--total`, `--forward`, `--backward`, hex input/output masks, `--top`, `--max-states`), replacing hardcoded 4-round constants.
* Added an independent exhaustive two-round sanity oracle (`--sanity-check`) that certifies the MITM hull correlation against direct evaluation without reusing the LAT transition tables.
* Targeted Monte-Carlo verification gains a `--weight` option: sampled round differentials are now tracked by Hamming weight (non-zero byte count) for weight-constrained hypothesis testing.
* Lint hygiene in the differential-hull example: blanket `#![allow(clippy::all)]` / `dead_code` suppressions replaced with targeted item-level allows; dead code (`load_exact_ddt`, `Dyadic::from_count`) removed.

## 🐛 Fixes
* Consistency verdict uses relative tolerance (`relative_difference <= 1e-9`) instead of an absolute `< 1e-30` threshold that spuriously failed on large dyadic products due to f64 rounding.
* `--prune` now bounds both forward and backward expansion; previously only the forward direction was pruned (an accidental asymmetry).

## 🔬 Cryptography
* No changes to the frozen Herringfish Feistel ARX v0.2 primitive parameters or S-box: 128-bit block, 256-bit master key, 16 rounds, and the v0.2 S-box are untouched.
* Differential-hull analysis results unchanged: best differential, MITM intersection, and consistency verdicts verified identical against the pre-refactor implementation across all deterministic scenarios; backward expansion math confirmed by A/B testing against the original code.
* Linear hull propagation now carries exact per-byte LAT correlations through F(x) = D(S(x)), with output masks explicitly entering the S-box as D^T(q); bounded mode reports truncation instead of silently approximating, and sanity-check mode refuses to certify truncated results.

## 🧪 Testing
* Windows (verified): `cargo build --examples` succeeds with zero warnings.
* Windows (verified): `cargo clippy --example hull_meet_in_middle` — zero warnings, no blanket allows.
* Windows (verified): 7-scenario CLI regression for the differential-hull example (help / bad config / unknown flag / prune / single-round / default / hex I/O) — byte-identical output and exit codes against pre-refactor baselines; the only diff in limit-hit runs is a pre-existing nondeterministic "Source ΔR" line (HashMap iteration order).
* Windows (verified): 2-round linear-hull runs complete end-to-end; sanity-check path correctly reports truncation and declines to certify a bounded hull.
* Windows (verified): targeted_mitm runs end-to-end with the new `--weight` filter at small sample counts.

**Full Changelog**: v0.2.5...v0.2.6

## 📄 Documentation & Reproducibility Update
* Finalized normative serialization and endianness for Herringfish Feistel ARX v0.2 in `docs/specification/feistel_arx_v0.2.md` – Section 26 Normative Serialization and Section 27 Normative Freeze Summary added; block and round-key byte ordering fixed to little-endian for interoperability.
* Updated `README.md` Specification and Validation Status: Specification → `v0.2 finalized with normative serialization §26/27`, Full-cipher statistical analysis → `Completed – 1M samples avalanche/SAC verified`.
* Moved `Normative serialization / endianness finalized` to Completed in Current Research Status.
* Added reproducibility metadata example to README covering Herringfish version/tag, spec version, experiment parameters, samples, random seed, compiler version, OS, CPU architecture, CPU features, Cargo features, hardware and execution time.
* `Cargo.toml` version bumped to `0.2.6` to match tag and description clarified as experimental research project.
* No cryptographic changes to the frozen v0.2 primitive.
