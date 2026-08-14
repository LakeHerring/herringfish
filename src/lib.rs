//! Herringfish - experimental symmetric cipher research
//!
//! This crate provides a reference implementation of the Herringfish prototype.
//! Current design: SPN, 128-bit block, 256-bit key, 14 rounds.
//!
//! WARNING: Experimental. Not for production use.

pub mod cipher;

pub use cipher::{Cipher, Key};
