use herringfish::attack::{differential::DifferentialAttack, Attack};

fn main() {
    let family = "SHA3";
    let attack = DifferentialAttack::new(family);
    println!("Running {} on {}", attack.name(), attack.target_family());
    println!("{}", attack.describe());
    
    // Example reduced-round search
    let rounds = 4;
    let trail = attack.find_characteristic(rounds);
    println!("Characteristic placeholder length: {}", trail.len());
}
