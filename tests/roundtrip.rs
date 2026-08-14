use herringfish::cipher::Cipher;

#[test]
fn roundtrip_all_zero() {
    let key = [0u8; 32];
    let mut pt = [0u8; 16];
    let mut buf = pt;
    let c = Cipher::new(&key);
    c.encrypt_block(&mut buf);
    c.decrypt_block(&mut buf);
    assert_eq!(buf, pt);
}

#[test]
fn roundtrip_random() {
    let key = [0x42u8; 32];
    let mut pt = [0u8; 16];
    for i in 0..16 {
        pt[i] = i as u8;
    }
    let mut buf = pt;
    let c = Cipher::new(&key);
    c.encrypt_block(&mut buf);
    c.decrypt_block(&mut buf);
    assert_eq!(buf, pt);
}
