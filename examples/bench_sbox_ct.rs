use herringfish::cipher::feistel_arx::FeistelArx;
use std::time::Instant;

fn main() {
    let key = [0u8; 32];
    let cipher = FeistelArx::new(&key);
    
    // Warm up
    let mut block = [0u8; 16];
    for i in 0..16 { block[i] = i as u8; }
    cipher.encrypt_block(&mut block);
    cipher.encrypt_block_ct(&mut block);
    
    const ITER: usize = 100_000;
    let mut data = [0u8; 16];
    
    // Table lookup version
    let start = Instant::now();
    for _ in 0..ITER {
        let mut b = data;
        cipher.encrypt_block(&mut b);
    }
    let dur_table = start.elapsed();
    
    // Constant-time version
    let start = Instant::now();
    for _ in 0..ITER {
        let mut b = data;
        cipher.encrypt_block_ct(&mut b);
    }
    let dur_ct = start.elapsed();
    
    println!("Benchmark: {} encryptions", ITER);
    println!("Table lookup:   {:?}  ({:.0} ops/s)", dur_table, ITER as f64 / dur_table.as_secs_f64());
    println!("Constant-time:  {:?}  ({:.0} ops/s)", dur_ct, ITER as f64 / dur_ct.as_secs_f64());
    let overhead = dur_ct.as_secs_f64() / dur_table.as_secs_f64();
    println!("Overhead factor: {:.2}x", overhead);
    
    // Verify correctness
    let mut pt = [0u8; 16];
    for i in 0..16 { pt[i] = i as u8; }
    let mut a = pt;
    let mut b = pt;
    cipher.encrypt_block(&mut a);
    cipher.encrypt_block_ct(&mut b);
    assert_eq!(a, b, "CT and table outputs diverge");
    println!("Correctness check passed: CT output matches table lookup");
}
