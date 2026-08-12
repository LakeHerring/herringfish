fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --example identify_hash <hex_digest>");
        std::process::exit(1);
    }
    let input = args[1].trim();
    let hex = input.trim_start_matches("0x").to_lowercase();
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        eprintln!("Input is not valid hex");
        std::process::exit(1);
    }
    let len = hex.len();
    let bytes = len / 2;
    println!("Digest length: {} hex chars ({} bytes)", len, bytes);

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
        for a in &algos {
            println!(" - {}", a);
        }
    }

    println!("\nHerringfish families:");
    if bytes == 32 {
        println!(" - SHA2 family: SHA-256");
        println!(" - SHA3 family: SHA3-256");
        println!(" - SHAKE family: SHAKE128 truncated to 256 bits");
    } else if bytes == 64 {
        println!(" - SHA2 family: SHA-512");
        println!(" - SHA3 family: SHA3-512");
    }

    println!("\nSide-channel considerations:");
    match bytes {
        32 => {
            println!(" - 32-byte digests are common for SHA-256/SHA3-256.");
            println!("   Many software implementations use byte-oriented table lookups for S-box/χ.");
            println!("   Variable-time table accesses and secret-dependent branches can leak via cache timing.");
            println!("   Recommendation: use constant-time, bit-sliced implementations for high-risk contexts.");
        }
        64 => {
            println!(" - 64-byte digests are common for SHA-512/SHA3-512.");
            println!("   64-bit word operations are often constant-time on modern CPUs, but message scheduling");
            println!("   and padding can still introduce timing variability in naive code.");
            println!("   Recommendation: validate with constant-time tests and avoid secret-dependent memory access.");
        }
        20 => {
            println!(" - 20-byte SHA-1 digests are legacy.");
            println!("   Many implementations are unmasked and variable-time.");
            println!("   Recommendation: avoid SHA-1 in new designs; if used, enforce constant-time code.");
        }
        _ => {
            println!(" - Length does not match common fixed-output hashes.");
            println!("   SHAKE/XOF outputs are variable length; implementations must handle streaming safely.");
            println!("   Recommendation: ensure output length is enforced at API boundary to avoid oracle leakage.");
        }
    }

    println!("\nCryptanalytic difficulty summary [from HASH_DIFFICULTY.md]:");
    match bytes {
        32 => {
            println!(" SHA-256:");
            println!("  Best public collision: 39-step SFS, 31-step free-start");
            println!("  Full rounds: 64");
            println!("  Preimage ≈ 2^256, Collision resistance ≈ 2^128");
            println!(" SHA3-256:");
            println!("  Best public collision: 5-round reduced Keccak-f");
            println!("  Full rounds: 24");
            println!("  Preimage ≈ 2^256, Collision resistance ≈ 2^128");
            println!(" SHAKE128/256 truncated to 256 bits:");
            println!("  Best public collision: 6-round, complexity ≈ 2^123.5");
            println!("  Full rounds: 24");
            println!("  Preimage ≈ 2^128 for 256-bit output");
        }
        64 => {
            println!(" SHA-512:");
            println!("  Best public collision: 28-step practical, 31-step theoretic");
            println!("  Full rounds: 80");
            println!("  Preimage ≈ 2^512, Collision resistance ≈ 2^256");
            println!(" SHA3-512:");
            println!("  Best public collision: 4-round");
            println!("  Full rounds: 24");
            println!("  Preimage ≈ 2^512, Collision resistance ≈ 2^256");
        }
        _ => {
            println!("  No specific difficulty data for this length.");
        }
    }
}
