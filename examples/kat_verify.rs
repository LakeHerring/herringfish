// One-shot verifier: confirm docs/tables KAT files match the current
// implementation (solo-arx ARX key schedule). Exit 0 = all match.
// Reduced-round files use [rounds=N] group headers; the full KAT file is 16.

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}


fn from_hex16(s: &str) -> [u8; 16] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

fn from_hex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

fn encrypt(key: &[u8; 32], pt: &[u8; 16], rounds: usize) -> String {
    let mut block = *pt;
    herringfish::cipher::feistel_arx::FeistelArx::new_with_rounds(key, rounds).encrypt_block(&mut block);
    hex_of(&block)
}

fn check(path: &str, default_rounds: usize) -> (usize, usize) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut rounds = default_rounds;
    let mut key = String::new();
    let mut pt = String::new();
    let (mut passed, mut failed) = (0, 0);
    for line in text.lines().map(|l| l.trim()) {
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') && !line.ends_with("rounds KAT") {
            continue;
        }
        // key=/plaintext=/ciphertext= style (kat_reduced_rounds_v02.txt)
        let line = line
            .replacen("key=", "Key: ", 1)
            .replacen("plaintext=", "Plaintext: ", 1)
            .replacen("ciphertext=", "Ciphertext: ", 1);
        if let Some(v) = line.strip_prefix("[rounds=") {
            rounds = v.trim_end_matches(']').parse().unwrap();
        } else if line.starts_with('#') && line.ends_with("rounds KAT") {
            // "# ... N rounds KAT" header style (kat_reduced_all.txt)
            let pos = line.find(" rounds KAT").unwrap();
            rounds = line[..pos].chars().rev().find(|c| c.is_ascii_digit()).unwrap().to_digit(10).unwrap() as usize;
        } else if let Some(v) = line.strip_prefix("Key: ") {
            key = v.to_string();
        } else if let Some(v) = line.strip_prefix("Plaintext: ") {
            pt = v.to_string();
        } else if let Some(v) = line.strip_prefix("Ciphertext: ") {
            let got = encrypt(&from_hex32(&key), &from_hex16(&pt), rounds);
            if got == v {
                passed += 1;
            } else {
                failed += 1;
                eprintln!("MISMATCH {path} rounds={rounds}\n  key {key}\n  pt {pt}\n  got {got}\n  exp {v}");
            }
        }
    }
    println!("{path} (base rounds {default_rounds}): {passed} passed, {failed} failed");
    (passed, failed)
}

fn main() {
    let mut failed = 0;
    let mut passed = 0;
    for (path, rounds) in [
        ("docs/tables/kat_vectors_v02.txt", 16),
        ("docs/tables/kat_reduced_rounds_v02.txt", 16),
        ("docs/tables/kat_reduced_all.txt", 16),
        ("docs/tables/kat_expanded_v02.txt", 16),
    ] {
        let (p, f) = check(path, rounds);
        passed += p;
        failed += f;
    }
    if failed == 0 {
        println!("ALL KATs MATCH current implementation ({passed} vectors)");
    } else {
        eprintln!("{failed} MISMATCHES");
        std::process::exit(1);
    }
}
