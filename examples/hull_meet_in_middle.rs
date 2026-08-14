use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;
use std::collections::HashMap;

/// Meet-in-the-middle differential hull analysis for Herringfish Feistel ARX
/// 
/// This is a research prototype for 6-round hull enumeration.
/// Forward 3 rounds from input difference, backward 3 rounds from output difference.
/// Prunes to top N intermediate states.

fn build_ddt() -> [[u16;256];256] {
    let mut ddt = [[0u16;256];256];
    for dx in 0..256 {
        for x in 0..256 {
            let dy = (HERRINGFISH_SBOX_V02[x ^ dx] ^ HERRINGFISH_SBOX_V02[x]) as usize;
            ddt[dx][dy] += 1;
        }
    }
    ddt
}

fn diffuse(t: u64) -> u64 {
    let mut bytes = [0u8;8];
    for i in 0..8 { bytes[i] = ((t >> (8*i)) & 0xff) as u8; }
    let mut out = [0u8;8];
    for i in 0..8 { out[i] = bytes[i] ^ bytes[(i+1)%8] ^ bytes[(i+3)%8]; }
    let mut res = 0u64;
    for i in 0..8 { res |= (out[i] as u64) << (8*i); }
    res
}

fn active_bytes(v: u64) -> usize {
    (0..8).filter(|i| ((v >> (8*i)) & 0xff) != 0).count()
}

fn main() {
    let ddt = build_ddt();
    println!("Meet-in-the-middle hull analysis for 6 rounds");
    println!("Forward 3 rounds, backward 3 rounds");
    println!("Pruning to top 2000 intermediate states");
    
    // Input difference: 1-bit
    let dr0 = 1u64 << 0;
    let mut forward: HashMap<(u64,u64), f64> = HashMap::new();
    forward.insert((0, dr0), 1.0);
    
    // Forward 3 rounds
    for r in 0..3 {
        let mut next = HashMap::new();
        for (&(dl, dr), &p) in forward.iter() {
            let k = active_bytes(dr);
            if k > 2 { continue; }
            // Enumerate t for active bytes
            let mut active_idx = Vec::new();
            for i in 0..8 {
                if ((dr >> (8*i)) & 0xff) != 0 { active_idx.push(i); }
            }
            let total = 256usize.pow(active_idx.len() as u32);
            for mask in 0..total {
                let mut t_val = 0u64;
                let mut tmp = mask;
                for &i in &active_idx {
                    let tb = (tmp % 256) as u8;
                    tmp /= 256;
                    t_val |= (tb as u64) << (8*i);
                }
                let f_out = diffuse(t_val);
                let mut prob = p;
                for &i in &active_idx {
                    let din_b = ((dr >> (8*i)) & 0xff) as u8;
                    let t_b = ((t_val >> (8*i)) & 0xff) as u8;
                    let cnt = ddt[din_b as usize][t_b as usize];
                    prob *= cnt as f64 / 256.0;
                }
                let dl_next = dr;
                let dr_next = dl ^ f_out;
                let e = next.entry((dl_next, dr_next)).or_insert(0.0);
                if prob > *e { *e = prob; }
            }
        }
        // Prune
        let mut vec: Vec<_> = next.into_iter().collect();
        vec.sort_by(|a,b| (b.1).partial_cmp(&a.1).unwrap());
        forward = vec.into_iter().take(2000).collect();
        println!("Round {} forward states: {}", r+1, forward.len());
        if forward.is_empty() { break; }
    }
    
    println!("Forward enumeration complete. Intermediate states: {}", forward.len());
    println!("Meet-in-the-middle skeleton implemented.");
    println!("Next steps: implement backward enumeration from output differences,");
    println!("match intermediate states, and sum probabilities for hull.");
}
