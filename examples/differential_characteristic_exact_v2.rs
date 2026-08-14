use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

/// Build S-box DDT
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

// Inverse diffusion matrix for F function
const INV_M: [[u8;8];8] = [
    [1,0,1,0,0,1,1,1],
    [1,1,0,1,0,0,1,1],
    [1,1,1,0,1,0,0,1],
    [1,1,1,1,0,1,0,0],
    [0,1,1,1,1,0,1,0],
    [0,0,1,1,1,1,0,1],
    [1,0,0,1,1,1,1,0],
    [0,1,0,0,1,1,1,1],
];

fn inv_diffuse(d: u64) -> u64 {
    let mut t = 0u64;
    for i in 0..8 {
        let mut byte = 0u8;
        for j in 0..8 {
            if INV_M[i][j] == 1 {
                let dj = ((d >> (8*j)) & 0xff) as u8;
                byte ^= dj;
            }
        }
        t |= (byte as u64) << (8*i);
    }
    t
}

fn diffuse(t: u64) -> u64 {
    let mut bytes = [0u8;8];
    for i in 0..8 {
        bytes[i] = ((t >> (8*i)) & 0xff) as u8;
    }
    let mut out = [0u8;8];
    for i in 0..8 {
        out[i] = bytes[i] ^ bytes[(i+1)%8] ^ bytes[(i+3)%8];
    }
    let mut res = 0u64;
    for i in 0..8 {
        res |= (out[i] as u64) << (8*i);
    }
    res
}

fn f_prob(d_in: u64, f_out: u64, ddt: &[[u16;256];256]) -> f64 {
    let t = inv_diffuse(f_out);
    let mut prob = 1.0;
    for i in 0..8 {
        let din_b = ((d_in >> (8*i)) & 0xff) as u8;
        let t_b = ((t >> (8*i)) & 0xff) as u8;
        if din_b == 0 {
            if t_b != 0 {
                return 0.0;
            }
        } else {
            let cnt = ddt[din_b as usize][t_b as usize];
            if cnt == 0 {
                return 0.0;
            }
            prob *= cnt as f64 / 256.0;
        }
    }
    prob
}

fn active_bytes(v: u64) -> usize {
    let mut cnt = 0;
    for i in 0..8 {
        if ((v >> (8*i)) & 0xff) != 0 { cnt += 1; }
    }
    cnt
}

fn hamming_weight(x: u64) -> u32 {
    x.count_ones()
}

fn main() {
    let ddt = build_ddt();
    println!("S-box DDT max = {}", ddt.iter().flatten().max().unwrap());

    // Enumerate 1-bit input differences
    let rounds_list = [4usize, 6usize];
    for rounds in rounds_list {
        println!("\n=== {} rounds, exact enumeration for 1-bit input differences (pruned) ===", rounds);
        let mut best_prob = 0.0;
        let mut best_diff = 0u64;
        // Start with ΔL=0, ΔR = 1-bit
        for bit in 0..64 {
            let dr0 = 1u64 << bit;
            // BFS limited
            use std::collections::HashMap;
            let mut cur: HashMap<(u64,u64), f64> = HashMap::new();
            cur.insert((0, dr0), 1.0);
            for _ in 0..rounds {
                let mut next: HashMap<(u64,u64), f64> = HashMap::new();
                for (&(dl, dr), &p) in cur.iter() {
                    let k = active_bytes(dr);
                    if k > 2 {
                        // prune: keep only top candidates via heuristic
                        // skip enumeration for large k
                        continue;
                    }
                    // Enumerate t for active bytes
                    // For simplicity, enumerate all 256^k possibilities
                    // Collect active indices
                    let mut active_idx = Vec::new();
                    for i in 0..8 {
                        if ((dr >> (8*i)) & 0xff) != 0 {
                            active_idx.push(i);
                        }
                    }
                    // Brute force via recursion
                    let total = 256usize.pow(active_idx.len() as u32);
                    for mask in 0..total {
                        // Build t
                        let mut t_val = 0u64;
                        let mut tmp = mask;
                        for &i in &active_idx {
                            let tb = (tmp % 256) as u8;
                            tmp /= 256;
                            t_val |= (tb as u64) << (8*i);
                        }
                        let f_out = diffuse(t_val);
                        // Compute probability for this t
                        let mut prob = p;
                        for &i in &active_idx {
                            let din_b = ((dr >> (8*i)) & 0xff) as u8;
                            let t_b = ((t_val >> (8*i)) & 0xff) as u8;
                            let cnt = ddt[din_b as usize][t_b as usize];
                            prob *= cnt as f64 / 256.0;
                        }
                        let dl_next = dr;
                        let dr_next = dl ^ f_out;
                        let entry = next.entry((dl_next, dr_next)).or_insert(0.0);
                        if prob > *entry {
                            *entry = prob;
                        }
                    }
                }
                // Prune to top N states
                let mut vec: Vec<_> = next.into_iter().collect();
                vec.sort_by(|a,b| (b.1).partial_cmp(&a.1).unwrap());
                cur = vec.into_iter().take(2000).collect::<HashMap<_,_>>();
                if cur.is_empty() { break; }
            }
            // Find best probability for this starting diff
            let mut best_p = 0.0;
            for &p in cur.values() { if p > best_p { best_p = p; } }
            if best_p > best_prob {
                best_prob = best_p;
                best_diff = dr0;
            }
        }
        println!("Best exact prob (pruned) ≈ {:.3e} for Δin = {:#018x} (HW={})", best_prob, best_diff, hamming_weight(best_diff));
        println!("Note: enumeration is pruned to active bytes ≤2 and top 2000 states per round.");
    }
}
