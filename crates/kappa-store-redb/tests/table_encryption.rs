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

#[test]
fn encryption_preserves_empty_values_and_rejects_key_tag_and_payload_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let encryptor = TableEncryptor::new(&[7; 32])?;
    let other = TableEncryptor::new(&[8; 32])?;
    let key = "tags:namespace:key";
    let empty = encryptor.encrypt_value(key, b"")?;
    assert!(encryptor.decrypt_value(key, &empty)?.is_empty());
    let encrypted = encryptor.encrypt_value(key, b"private value")?;
    assert!(other.decrypt_value(key, &encrypted).is_err());
    // The empty envelope identifies the nonce-plus-tag length without
    // coupling the assertion to the cipher's nonce width.
    let tag_end = empty.len();
    for index in [tag_end - 1, tag_end] {
        let mut corrupted = encrypted.clone();
        corrupted[index] ^= 1;
        assert!(encryptor.decrypt_value(key, &corrupted).is_err());
    }
    assert_ne!(&encrypted[tag_end..], b"private value");
    assert_eq!(encryptor.hmac_key(key), encryptor.hmac_key(key));
    assert_ne!(encryptor.hmac_key(key), encryptor.hmac_key("other-row"));
    assert_ne!(encryptor.hmac_key(key), other.hmac_key(key));
    Ok(())
}
