//! herringfish – Cryptography analysis toolkit
//! Targets the mathematical structures of SHA-2, SHA-3 and SHAKE
//! rather than black-box hash collisions.

pub mod primitives;
pub mod attack;
pub mod math;

pub const SUPPORTED_FAMILIES: &[&str] = &["SHA2", "SHA3", "SHAKE"];
