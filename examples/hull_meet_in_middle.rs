use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;
use std::collections::HashMap;

/// Meet-in-the-middle differential hull analysis for 6-round Herringfish Feistel ARX
/// Forward 3 rounds from input, backward 3 rounds from output, match on middle state.

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

fn enumerate_forward(ddt: &[[u16;256];256], dl0: u64, dr0: u64, rounds: usize, max_active: usize, top_n: usize) -> HashMap<(u64,u64), f64> {
    let mut cur = HashMap::new();
    cur.insert((dl0, dr0), 1.0);
    for _ in 0..rounds {
        let mut next = HashMap::new();
        for (&(dl, dr), &p) in cur.iter() {
            let k = active_bytes(dr);
            if k > max_active { continue; }
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
        let mut vec: Vec<_> = next.into_iter().collect();
        vec.sort_by(|a,b| (b.1).partial_cmp(&a.1).unwrap());
        cur = vec.into_iter().take(top_n).collect();
        if cur.is_empty() { break; }
    }
    cur
}

fn enumerate_backward(ddt: &[[u16;256];256], dl_out: u64, dr_out: u64, rounds: usize, max_active: usize, top_n: usize) -> HashMap<(u64,u64), f64> {
    let mut cur = HashMap::new();
    cur.insert((dl_out, dr_out), 1.0);
    for _ in 0..rounds {
        let mut next = HashMap::new();
        for (&(dl, dr), &p) in cur.iter() {
            // backward step: previous state (dl_prev, dr_prev)
            // dr_prev = dl
            // dl_prev = dr XOR f(dl)
            let dr_prev = dl;
            let k = active_bytes(dr_prev);
            if k > max_active { continue; }
            let mut active_idx = Vec::new();
            for i in 0..8 {
                if ((dr_prev >> (8*i)) & 0xff) != 0 { active_idx.push(i); }
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
                    let din_b = ((dr_prev >> (8*i)) & 0xff) as u8;
                    let t_b = ((t_val >> (8*i)) & 0xff) as u8;
                    let cnt = ddt[din_b as usize][t_b as usize];
                    prob *= cnt as f64 / 256.0;
                }
                let dl_prev = dr ^ f_out;
                let dr_prev_state = dr_prev;
                let e = next.entry((dl_prev, dr_prev_state)).or_insert(0.0);
                if prob > *e { *e = prob; }
            }
        }
        let mut vec: Vec<_> = next.into_iter().collect();
        vec.sort_by(|a,b| (b.1).partial_cmp(&a.1).unwrap());
        cur = vec.into_iter().take(top_n).collect();
        if cur.is_empty() { break; }
    }
    cur
}

fn main() {
    let ddt = build_ddt();
    println!("Meet-in-the-middle hull analysis for 6 rounds");
    println!("Config: max_active_bytes=2, top_n=2000");
    
    let dr_in = 1u64 << 0; // 1-bit input difference
    let forward_map = enumerate_forward(&ddt, 0, dr_in, 3, 2, 2000);
    println!("Forward 3 rounds states: {}", forward_map.len());
    
    // Backward from output differences with 1 active byte
    let mut best_prob = 0.0;
    let mut best_pair = None;
    for bit in 0..64 {
        let dr_out = 1u64 << bit;
        // try zero left output for simplicity
        let backward_map = enumerate_backward(&ddt, 0, dr_out, 3, 2, 2000);
        for (&(dl_mid, dr_mid), &p_back) in backward_map.iter() {
            if let Some(&p_fwd) = forward_map.get(&(dl_mid, dr_mid)) {
                let total = p_fwd * p_back;
                if total > best_prob {
                    best_prob = total;
                    best_pair = Some((dr_in, dr_out, dl_mid, dr_mid));
                }
            }
        }
    }
    
    println!("Best 6-round characteristic probability found: {:.3e}", best_prob);
    if let Some((in_diff, out_diff, dl_mid, dr_mid)) = best_pair {
        println!("Input ΔR:  {:#018x}", in_diff);
        println!("Output ΔR: {:#018x}", out_diff);
        println!("Middle state: ΔL={:#018x}, ΔR={:#018x}", dl_mid, dr_mid);
    }
    println!("\nNote: This is a pruned meet-in-the-middle search with active byte budget 2.");
    println!("Increase budget/top_n for more exhaustive hull enumeration.");
}
