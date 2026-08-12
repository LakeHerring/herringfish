// Matrix utilities placeholder
pub struct Matrix<T> {
    rows: usize,
    cols: usize,
    data: Vec<T>,
}

impl<T: Clone> Matrix<T> {
    pub fn new(rows: usize, cols: usize, default: T) -> Self {
        Self { rows, cols, data: vec![default; rows*cols] }
    }
}
