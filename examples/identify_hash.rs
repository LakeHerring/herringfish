fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --example identify_hash <hex_digest>");
        std::process::exit(1);
    }
    let input = args[1].trim();
    // Strip common prefixes
    let hex = input.trim_start_matches("0x").to_lowercase();
    // Validate hex
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        eprintln!("Input is not valid hex");
        std::process::exit(1);
    }
    let len = hex.len();
    let bytes = len / 2;
    println!("Digest length: {} hex chars ({} bytes)", len, bytes);
    let candidates = match bytes {
        16 => vec!["MD5"],
        20 => vec!["SHA-1"],
        32 => vec!["SHA-256", "SHA3-256", "BLAKE2b-256"],
        48 => vec!["SHA-384"],
        64 => vec!["SHA-512", "SHA3-512"],
        32 => vec!["SHAKE128 output"],
        _ => vec![],
    };
    // Better mapping
    let algos = match bytes {
        16 => vec!["MD5"],
        20 => vec!["SHA-1"],
        32 => vec!["SHA-256", "SHA3-256"],
        48 => vec!["SHA-384"],
        64 => vec!["SHA-512", "SHA3-512"],
        _ => vec![],
    };
    if algos.is_empty() {
        println!("Unknown length, could be SHAKE / custom output");
    } else {
        println!("Possible algorithms:");
        for a in algos {
            println!(" - {}", a);
        }
    }
    // Additional heuristic for herringfish families
    println!("\nHerringfish families:");
    if bytes == 32 {
        println!(" - SHA2 family: SHA-256");
        println!(" - SHA3 family: SHA3-256");
        println!(" - SHAKE family: SHAKE128 truncated to 256 bits");
    } else if bytes == 64 {
        println!(" - SHA2 family: SHA-512");
        println!(" - SHA3 family: SHA3-512");
    }
}
