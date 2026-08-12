// Lattice utilities placeholder
pub trait LatticeBasis {
    fn rank(&self) -> usize;
}

pub struct Basis {
    pub dim: usize,
}

impl LatticeBasis for Basis {
    fn rank(&self) -> usize { self.dim }
}
