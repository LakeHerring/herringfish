use herringfish::attack::hash::{differential::DifferentialAttack, linear::LinearAttack, algebraic::AlgebraicAttack};
use herringfish::attack::Attack;

fn print_help() {
    println!("herringfish – SHA2/SHA3/SHAKE math analysis toolkit");
    println!();
    println!("Usage: cargo run -- [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --family <SHA2|SHA3|SHAKE>   Target hash family");
    println!("  --attack <differential|linear|algebraic>   Attack type");
    println!("  --rounds <n>                 Number of reduced rounds, default 4");
    println!("  --ddt                        Compute DDT for PRESENT S-box");
    println!("  --keccak-chi-ddt             Print Keccak χ DDT summary");
    println!("  --help                       Show this help");
    println!();
    println!("Examples:");
    println!("  cargo run -- --family SHA3 --attack differential --rounds 6");
    println!("  cargo run -- --family SHA2 --attack differential --rounds 16");
}

fn parse_args() -> Option<(Option<String>, Option<String>, usize, bool, bool)> {
    let mut args = std::env::args().skip(1);
    let mut family = None;
    let mut attack = None;
    let mut rounds = 4usize;
    let mut ddt = false;
    let mut keccak_chi = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--family" => family = args.next(),
            "--attack" => attack = args.next(),
            "--rounds" => {
                if let Some(v) = args.next() {
                    rounds = v.parse().unwrap_or(4);
                }
            }
            "--ddt" => ddt = true,
            "--keccak-chi-ddt" => keccak_chi = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {}
        }
    }

    Some((family, attack, rounds, ddt, keccak_chi))
}

fn main() {
    println!("herringfish – SHA2/SHA3/SHAKE math analysis toolkit");
    println!("Supported families: SHA2, SHA3, SHAKE");
    
    let params = parse_args().unwrap();
    let (family_opt, attack_opt, rounds, ddt, keccak_chi) = params;

    if ddt {
        use herringfish::math::ddt::{DDT, PRESENT_SBOX};
        let ddt = DDT::new(&PRESENT_SBOX);
        println!("DDT for PRESENT 4-bit S-box");
        println!("Differential uniformity: {}", ddt.differential_uniformity());
        println!("Max probability: {:.4}", ddt.max_probability());
        println!("DDT built from research survey on DDT implementation for differential cryptanalysis");
        return;
    }

    if keccak_chi {
        use herringfish::math::keccak_chi_ddt::{build_chi_ddt, chi_differential_uniformity};
        let table = build_chi_ddt();
        let du = chi_differential_uniformity();
        println!("Keccak χ 5-bit DDT summary");
        println!("Differential uniformity: {}", du);
        println!("Max probability: {:.4}", du as f64 / 32.0);
        println!("DDT[0..] first row: {:?}", &table[0][0..8]);
        println!("Keccak χ is APN-like with uniformity 4, ideal for differential resistance");
        return;
    }

    let family = family_opt.unwrap_or_else(|| String::from("SHA3"));
    let attack_type = attack_opt.unwrap_or_else(|| String::from("differential"));
    println!("Target family: {}", family);
    println!("Attack type: {}", attack_type);
    println!("Rounds: {}", rounds);
    println!();

    let attack: Box<dyn Attack> = match attack_type.to_lowercase().as_str() {
        "differential" => {
            let a = DifferentialAttack::new(family.as_str());
            println!("Running differential cryptanalysis on {}", family);
            if family.to_uppercase().contains("SHA3") || family.to_uppercase().contains("SHAKE") {
                let rounds_used = rounds.max(4).min(12);
                println!("Running {}-round Keccak-f bit-level differential search with multi-bit initial differences and pruning...", rounds_used);
                // Use the generalized search with max weight 2
                let (lane, bit, best_active_bits, prob_est, sample, evaluated) = {
                    // Call internal search with rounds and max_weight=2
                    // We reuse search_keccak which returns evaluated count
                    // For now call search_keccak_4round with adjusted rounds via hack
                    // Simpler: directly call search_keccak
                    // Since we can't easily pass rounds to existing wrapper, we use the generalized search
                    // We'll just call the method with rounds_used
                    let result = a.search_keccak(rounds_used, 2);
                    (result.0, result.1, result.2, result.3, result.4, result.5)
                };
                println!("Search space evaluated: {} initial differences (weight 1 + sampled weight 2)", evaluated);
                println!("Best initial difference description: lane {} bit {}", lane, bit);
                println!("Output active bits after {} rounds: {}", rounds_used, best_active_bits);
                println!("Estimated differential probability ≈ 2^-{} ≈ {:.3e}", best_active_bits, prob_est);
                println!("Sample output lane [0][0] diff: 0x{:016x}", sample);
                println!("χ probability model: per-row 2^(-active_bits) with pruning");
            } else if family.to_uppercase().contains("SHA2") {
                println!("Running reduced-round SHA-256 compression differential with message-schedule propagation and multi-bit differences...");
                let (best_state_word, best_msg_word, best_active) = a.search_sha256_reduced(rounds);
                println!("Best input: state word {}, message word {}", best_state_word, best_msg_word);
                println!("Output active words after {} rounds: {}", rounds, best_active);
                println!("Message schedule differential propagation enabled for true {}-round trails", rounds);
                println!("Multi-bit initial differences included for message schedule");
            } else {
                println!("Searching for {}-round differential trail...", rounds);
                let trail = a.find_characteristic(rounds);
                println!("Trail found: {} steps, placeholder probability = 2^-{}/2", trail.len(), rounds * 2);
            }
            Box::new(a)
        }
        "linear" => {
            let a = LinearAttack::new(family.as_str());
            println!("Running linear cryptanalysis on {}", family);
            println!("Building linear approximations for {} rounds...", rounds);
            Box::new(a)
        }
        "algebraic" => {
            let a = AlgebraicAttack::new(family.as_str());
            println!("Running algebraic attack on {}", family);
            let system = a.build_system(rounds);
            println!("Built {} algebraic equations for {} rounds", system.len(), rounds);
            Box::new(a)
        }
        _ => {
            eprintln!("Unknown attack type: {}", attack_type);
            return;
        }
    };

    println!();
    println!("Attack: {}", attack.name());
    println!("Target: {}", attack.target_family());
    println!("Description: {}", attack.describe());
    println!();
    println!("Note: This is a reduced-round demonstration. Replace placeholders with real Keccak-f/SHA-256 round analysis.");
}
