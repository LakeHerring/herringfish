pub mod differential;
pub mod linear;
pub mod algebraic;

pub trait Attack {
    fn name(&self) -> &'static str;
    fn target_family(&self) -> &str;
    fn describe(&self) -> String;
}
