use herringfish::cipher::feistel_arx::HERRINGFISH_SBOX_V02;

/// Build S-box DDT
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

fn max_ddt_prob(ddt: &[[u16; 256]; 256]) -> f64 {
    let mut max = 0u16;
    for dx in 1..256 {
        for dy in 0..256 {
            if ddt[dx][dy] > max {
                max = ddt[dx][dy];
            }
        }
    }
    max as f64 / 256.0
}

fn active_bytes_mask(v: u64) -> u8 {
    let mut mask = 0u8;
    for i in 0..8 {
        if ((v >> (8 * i)) & 0xff) != 0 {
            mask |= 1 << i;
        }
    }
    mask
}

fn count_active(mask: u8) -> usize {
    mask.count_ones() as usize
}

fn diffuse_active(mask: u8) -> u8 {
    let mut out = 0u8;
    for i in 0..8 {
        if (mask >> i) & 1 == 1 {
            out |= 1 << i;
            out |= 1 << ((i + 1) % 8);
            out |= 1 << ((i + 3) % 8);
        }
    }
    out
}

fn main() {
    let ddt = build_ddt();
    let p_max = max_ddt_prob(&ddt);
    println!("S-box max differential probability = {:.6} (4/256)", p_max);

    println!("\nDifferential trail heuristic for 1-bit input differences");
    println!("Rounds | active bytes in F | trail probability");

    for rounds in [6usize, 8usize] {
        // Start with ΔL=0, ΔR = 1-bit -> one active byte in F
        // We simulate worst-case active byte growth
        let mut active_mask = 1u8; // one byte active in F input
        let mut log_prob = 0.0f64;
        // For each round, F input is right half
        // Initial state: ΔL=0, ΔR has 1 active byte
        // We need to track active bytes in both halves
        let mut left_active = 0u8;
        let mut right_active = 1u8; // start with one byte active in right
        for r in 0..rounds {
            // F input = right_active
            let k = count_active(right_active);
            log_prob += k as f64 * p_max.log2();
            // Compute F output active
            let f_out_active = diffuse_active(right_active);
            // Next state
            let new_left = right_active;
            // right_next = left XOR f_out -> active = union
            let new_right = left_active | f_out_active;
            left_active = new_left;
            right_active = new_right;
        }
        let prob = 2f64.powf(log_prob);
        println!(
            "{:<6} | {:<18} | {:.3e}",
            rounds,
            count_active(right_active),
            prob
        );
    }

    println!("\nHull analysis note:");
    println!(
        "A differential hull aggregates all characteristics with same input/output difference."
    );
    println!("Current heuristic uses per-S-box max probability 4/256.");
    println!(
        "Full hull requires enumeration of all intermediate differences consistent with the input/output pair."
    );
    println!(
        "For 6-8 rounds, exact hull enumeration is computationally intensive and is left as a research task."
    );
}
