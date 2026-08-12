pub mod keccak;
pub mod sha2;
pub mod sha256;
pub mod sha3;
pub mod shake;

pub trait HashFamily {
    fn name(&self) -> &'static str;
    fn state_size_bits(&self) -> usize;
    fn digest_size_bits(&self) -> usize;
}
