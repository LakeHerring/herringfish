#![allow(
    clippy::all,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments
)]
use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;
use std::collections::HashMap;

/// Meet-in-the-middle differential hull analysis for 6-round Herringfish Feistel ARX
/// Forward 3 rounds from input, backward 3 rounds from output, match on middle state.
/// Uses top-K per-byte enumeration to make 3-active-byte search feasible.

fn build_ddt() -> [[u16; 256]; 256] {
    let mut ddt = [[0u16; 256]; 256];
    for dx in 0..256 {
        for x in 0..256 {
            let dy = (HERRINGFISH_SBOX_V02[x ^ dx] ^ HERRINGFISH_SBOX_V02[x]) as usize;
            ddt[dx][dy] += 1;
        }
    }
    ddt
}

fn diffuse(t: u64) -> u64 {
    let mut bytes = [0u8; 8];
    for i in 0..8 {
        bytes[i] = ((t >> (8 * i)) & 0xff) as u8;
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = bytes[i] ^ bytes[(i + 1) % 8] ^ bytes[(i + 3) % 8];
    }
    let mut res = 0u64;
    for i in 0..8 {
        res |= (out[i] as u64) << (8 * i);
    }
    res
}

fn active_bytes(v: u64) -> usize {
    (0..8).filter(|i| ((v >> (8 * i)) & 0xff) != 0).count()
}

fn top_k_t_values(ddt: &[[u16; 256]; 256], dx: u8, k: usize) -> Vec<(u8, f64)> {
    let mut vals: Vec<(u8, f64)> = (0..256)
        .map(|t| {
            let cnt = ddt[dx as usize][t as usize];
            (t as u8, cnt as f64 / 256.0)
        })
        .collect();
    vals.sort_by(|a, b| (b.1).partial_cmp(&a.1).unwrap());
    vals.truncate(k);
    vals
}

fn enumerate_forward(
    ddt: &[[u16; 256]; 256],
    dl0: u64,
    dr0: u64,
    rounds: usize,
    max_active: usize,
    top_n: usize,
    top_k_per_byte: usize,
) -> HashMap<(u64, u64), f64> {
    let mut cur = HashMap::new();
    cur.insert((dl0, dr0), 1.0);
    for _ in 0..rounds {
        let mut next = HashMap::new();
        for (&(dl, dr), &p) in cur.iter() {
            let k = active_bytes(dr);
            if k > max_active {
                continue;
            }
            let mut active_idx = Vec::new();
            for i in 0..8 {
                if ((dr >> (8 * i)) & 0xff) != 0 {
                    active_idx.push(i);
                }
            }
            // Precompute top-K candidates per active byte
            let mut candidates_per_byte: Vec<Vec<(u8, f64)>> = Vec::new();
            for &i in &active_idx {
                let dx = ((dr >> (8 * i)) & 0xff) as u8;
                if dx == 0 {
                    candidates_per_byte.push(vec![(0, 1.0)]);
                } else {
                    candidates_per_byte.push(top_k_t_values(ddt, dx, top_k_per_byte));
                }
            }
            // Cartesian product
            let total = candidates_per_byte
                .iter()
                .map(|v| v.len())
                .product::<usize>();
            for idx in 0..total {
                let mut tmp = idx;
                let mut t_val = 0u64;
                let mut prob = p;
                for (b_idx, &i) in active_idx.iter().enumerate() {
                    let choices = &candidates_per_byte[b_idx];
                    let choice_idx = tmp % choices.len();
                    tmp /= choices.len();
                    let (tb, p_byte) = choices[choice_idx];
                    t_val |= (tb as u64) << (8 * i);
                    prob *= p_byte;
                }
                let f_out = diffuse(t_val);
                let dl_next = dr;
                let dr_next = dl ^ f_out;
                let e = next.entry((dl_next, dr_next)).or_insert(0.0);
                if prob > *e {
                    *e = prob;
                }
            }
        }
        let mut vec: Vec<_> = next.into_iter().collect();
        vec.sort_by(|a, b| (b.1).partial_cmp(&a.1).unwrap());
        cur = vec.into_iter().take(top_n).collect();
        if cur.is_empty() {
            break;
        }
    }
    cur
}

fn enumerate_backward(
    ddt: &[[u16; 256]; 256],
    dl_out: u64,
    dr_out: u64,
    rounds: usize,
    max_active: usize,
    top_n: usize,
    top_k_per_byte: usize,
) -> HashMap<(u64, u64), f64> {
    let mut cur = HashMap::new();
    cur.insert((dl_out, dr_out), 1.0);
    for _ in 0..rounds {
        let mut next = HashMap::new();
        for (&(dl, dr), &p) in cur.iter() {
            let dr_prev = dl;
            let k = active_bytes(dr_prev);
            if k > max_active {
                continue;
            }
            let mut active_idx = Vec::new();
            for i in 0..8 {
                if ((dr_prev >> (8 * i)) & 0xff) != 0 {
                    active_idx.push(i);
                }
            }
            let mut candidates_per_byte: Vec<Vec<(u8, f64)>> = Vec::new();
            for &i in &active_idx {
                let dx = ((dr_prev >> (8 * i)) & 0xff) as u8;
                if dx == 0 {
                    candidates_per_byte.push(vec![(0, 1.0)]);
                } else {
                    candidates_per_byte.push(top_k_t_values(ddt, dx, top_k_per_byte));
                }
            }
            let total = candidates_per_byte
                .iter()
                .map(|v| v.len())
                .product::<usize>();
            for idx in 0..total {
                let mut tmp = idx;
                let mut t_val = 0u64;
                let mut prob = p;
                for (b_idx, &i) in active_idx.iter().enumerate() {
                    let choices = &candidates_per_byte[b_idx];
                    let choice_idx = tmp % choices.len();
                    tmp /= choices.len();
                    let (tb, p_byte) = choices[choice_idx];
                    t_val |= (tb as u64) << (8 * i);
                    prob *= p_byte;
                }
                let f_out = diffuse(t_val);
                let dl_prev = dr ^ f_out;
                let e = next.entry((dl_prev, dr_prev)).or_insert(0.0);
                if prob > *e {
                    *e = prob;
                }
            }
        }
        let mut vec: Vec<_> = next.into_iter().collect();
        vec.sort_by(|a, b| (b.1).partial_cmp(&a.1).unwrap());
        cur = vec.into_iter().take(top_n).collect();
        if cur.is_empty() {
            break;
        }
    }
    cur
}

fn main() {
    let ddt = build_ddt();
    println!("Meet-in-the-middle hull analysis for 6 rounds");
    println!("Config: max_active_bytes=4, top_n=20000, top_k_per_byte=32");

    let dr_in = 1u64 << 0;
    let forward_map = enumerate_forward(&ddt, 0, dr_in, 3, 4, 20000, 32);
    println!("Forward 3 rounds states: {}", forward_map.len());

    let mut best_prob = 0.0;
    let mut best_pair = None;
    // Test a few output differences
    for bit in 0..8 {
        let dr_out = 1u64 << bit;
        let backward_map = enumerate_backward(&ddt, 0, dr_out, 3, 4, 20000, 32);
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

    println!(
        "Best 6-round characteristic probability found: {:.3e}",
        best_prob
    );
    if let Some((in_diff, out_diff, dl_mid, dr_mid)) = best_pair {
        println!("Input ΔR:  {:#018x}", in_diff);
        println!("Output ΔR: {:#018x}", out_diff);
        println!("Middle state: ΔL={:#018x}, ΔR={:#018x}", dl_mid, dr_mid);
    } else {
        println!("No matching intermediate state found with current budget.");
    }
    println!("\nNote: Using top-K per-byte enumeration to keep search tractable.");
}
