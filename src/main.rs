fn main() {
    use herringfish::cipher::Cipher;
    let key = [0u8; 32];
    let mut plaintext = [0u8; 16];
    plaintext[0] = 0x01;
    let mut buf = plaintext;
    let cipher = Cipher::new(&key);
    cipher.encrypt_block(&mut buf);
    cipher.decrypt_block(&mut buf);
    assert_eq!(buf, plaintext);
    println!("herringfish prototype round-trip OK");
}
