pub mod hash;
pub mod symmetric;
pub mod public_key;
pub mod lattice;
pub mod pqc;

pub trait Attack {
    fn name(&self) -> &'static str;
    fn target_family(&self) -> &str;
    fn describe(&self) -> String;
}
