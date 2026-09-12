//! AEAD mode demonstration
//!
//! Shows encrypt/decrypt with AAD, tamper detection, and basic throughput.
//! Run: cargo run --example aead_demo

use herringfish::cipher::aead::{HerringfishAead, NONCE_SIZE, TAG_SIZE};

fn main() {
    let key = [0x42u8; 32];
    let nonce = [0x07u8; NONCE_SIZE];
    let aead = HerringfishAead::new(&key);

    // --- Basic roundtrip ---
    let plaintext = b"Attack at dawn. Coordinate via channel 7.";
    let aad = b"header:secret|version:1";
    let (ciphertext, tag) = aead.encrypt(&nonce, aad, plaintext);

    println!("Plaintext:  {}", String::from_utf8_lossy(plaintext));
    println!("AAD:        {}", String::from_utf8_lossy(aad));
    println!("Ciphertext: {} bytes", ciphertext.len());
    println!("Tag:        {} bytes ({} hex)", TAG_SIZE, hex(&tag));

    let decrypted = aead.decrypt(&nonce, aad, &ciphertext, &tag).unwrap();
    assert_eq!(&decrypted, plaintext);
    println!("Decrypted:  OK");

    // --- Tamper detection ---
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xFF;
    match aead.decrypt(&nonce, aad, &tampered, &tag) {
        Err(e) => println!("Tampered CT:  rejected ({})", e),
        Ok(_) => panic!("should have failed"),
    }

    let mut bad_tag = tag;
    bad_tag[0] ^= 0x01;
    match aead.decrypt(&nonce, aad, &ciphertext, &bad_tag) {
        Err(e) => println!("Tampered TAG: rejected ({})", e),
        Ok(_) => panic!("should have failed"),
    }

    match aead.decrypt(&nonce, b"different-aad", &ciphertext, &tag) {
        Err(e) => println!("Tampered AAD: rejected ({})", e),
        Ok(_) => panic!("should have failed"),
    }

    // --- Throughput benchmark ---
    let sizes = [16usize, 256, 4096, 65536, 1_048_576];
    println!("\nThroughput (encryption only, no AAD):");
    println!("{:<12} {:>10} {:>12}", "Size", "Time (ms)", "MB/s");
    for size in &sizes {
        let data = vec![0xABu8; *size];
        let start = std::time::Instant::now();
        let reps = if *size <= 4096 {
            100
        } else if *size <= 65536 {
            10
        } else {
            1
        };
        for _ in 0..reps {
            let (ct, _) = aead.encrypt(&nonce, b"", &data);
            let _ = ct.len();
        }
        let elapsed = start.elapsed().as_secs_f64() / reps as f64;
        let mbps = (*size as f64) / (1024.0 * 1024.0) / elapsed;
        println!(
            "{:<12} {:>10.3} {:>12.2}",
            human_size(*size),
            elapsed * 1000.0,
            mbps
        );
    }

    println!("\nAll AEAD checks passed.");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn human_size(n: usize) -> String {
    if n < 1024 {
        format!("{} B", n)
    } else if n < 1024 * 1024 {
        format!("{:.0} KB", n as f64 / 1024.0)
    } else {
        format!("{:.0} MB", n as f64 / (1024.0 * 1024.0))
    }
}
