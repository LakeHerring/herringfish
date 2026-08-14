use crate::cipher::feistel_arx::HERRINGFISH_SBOX_V02;
use subtle::ConstantTimeEq;

/// Constant-time S-box lookup for a single byte.
/// The lookup is performed via table access with secret-dependent index.
/// This implementation uses a constant-time selection over all 256 entries
/// to avoid cache-timing leakage. It is slower than direct indexing but
/// suitable for reference implementation and side-channel evaluation.
///
/// Note: This is a pedagogical constant-time implementation. For production
/// use, a bitsliced S-box or hardware-accelerated implementation would be
/// preferred.
pub fn sbox_ct_lookup(x: u8) -> u8 {
    let mut out = 0u8;
    for i in 0..256u16 {
        let idx = i as u8;
        // Constant-time equality test
        let eq = idx.ct_eq(&x);
        // Convert Choice to bool then to 0xFF mask
        let mask = u8::from(bool::from(eq)) * 0xFF;
        let s = HERRINGFISH_SBOX_V02[idx as usize];
        // Constant-time select via bitwise AND/OR
        out |= s & mask;
    }
    out
}

/// Constant-time 8-byte S-box application used in the Feistel F-function.
/// Applies sbox_ct_lookup to each byte of the 64-bit input in constant time.
pub fn sbox_apply_ct(input: u64) -> u64 {
    let mut out = 0u64;
    for i in 0..8 {
        let byte = ((input >> (8 * i)) & 0xff) as u8;
        let s = sbox_ct_lookup(byte);
        out |= (s as u64) << (8 * i);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

    #[test]
    fn test_sbox_ct_correctness() {
        for x in 0u8..=255 {
            let ct = sbox_ct_lookup(x);
            let direct = HERRINGFISH_SBOX_V02[x as usize];
            assert_eq!(ct, direct);
        }
    }

    #[test]
    fn test_sbox_apply_ct_correctness() {
        for _ in 0..1000 {
            let v = rand::random::<u64>();
            let ct = sbox_apply_ct(v);
            let mut direct = 0u64;
            for i in 0..8 {
                let byte = ((v >> (8 * i)) & 0xff) as u8;
                let s = HERRINGFISH_SBOX_V02[byte as usize];
                direct |= (s as u64) << (8 * i);
            }
            assert_eq!(ct, direct);
        }
    }
}
