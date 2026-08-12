use herringfish::primitives::hash;

fn main() {
    println!("Herringfish hash primitives available:");
    println!(" - SHA2 family: SHA-256, SHA-512 variants");
    println!(" - SHA3 family: Keccak-f, SHA3-256/512");
    println!(" - SHAKE family: SHAKE128/256");
    println!();
    println!("Modules:");
    println!(" primitives::hash::sha2");
    println!(" primitives::hash::sha256");
    println!(" primitives::hash::sha3");
    println!(" primitives::hash::shake");
    println!(" primitives::hash::keccak");
    println!();
    println!("To identify an algorithm from a digest, use identify_hash example.");
}
