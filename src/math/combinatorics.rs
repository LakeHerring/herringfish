pub fn binomial(n: u64, k: u64) -> u128 {
    if k > n { return 0 }
    let k = k.min(n - k);
    let mut num = 1u128;
    for i in 1..=k {
        num = num * (n - k + i) as u128 / i as u128;
    }
    num
}
