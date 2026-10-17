use kappa_store_redb::encrypted::TableEncryptor;

#[test]
fn repeated_updates_have_distinct_nonces_and_authenticate_the_record_key()
-> Result<(), Box<dyn std::error::Error>> {
    let encryptor = TableEncryptor::new(&[7; 32])?;
    let first = encryptor.encrypt_value("tags:namespace:key", b"value")?;
    let second = encryptor.encrypt_value("tags:namespace:key", b"value")?;
    assert_ne!(first, second);
    assert_eq!(
        encryptor.decrypt_value("tags:namespace:key", &first)?,
        b"value"
    );
    assert_eq!(
        encryptor.decrypt_value("tags:namespace:key", &second)?,
        b"value"
    );
    assert!(encryptor.decrypt_value("tags:other:key", &first).is_err());
    for end in 0..28 {
        assert!(
            encryptor
                .decrypt_value("tags:namespace:key", &first[..end])
                .is_err()
        );
    }
    let mut damaged = first;
    damaged[0] ^= 1;
    assert!(
        encryptor
            .decrypt_value("tags:namespace:key", &damaged)
            .is_err()
    );
    Ok(())
}
