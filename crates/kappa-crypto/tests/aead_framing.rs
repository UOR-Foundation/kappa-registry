use kappa_crypto::aead::{BlobEncryptor, FRAME_SIZE};

#[test]
fn exact_framing_rejects_missing_empty_authentication_and_added_frames() {
    let directory = tempfile::tempdir().expect("temporary KMS");
    let kms =
        kappa_crypto::kms::FileKms::new([7; 32], directory.path().join("erased")).expect("KMS");
    let encryptor = BlobEncryptor::new(&kms, "framing").expect("encryptor");
    for size in [0, 1, FRAME_SIZE, FRAME_SIZE + 1] {
        let blob = encryptor
            .encrypt("identity", &vec![42; size])
            .expect("encrypt");
        assert_eq!(
            encryptor
                .decrypt_all(
                    "identity",
                    &blob.disk_bytes,
                    &blob.base_nonce,
                    blob.plaintext_size
                )
                .expect("valid framing")
                .len(),
            size
        );
        for malformed in [
            blob.disk_bytes[..blob.disk_bytes.len() - 1].to_vec(),
            [blob.disk_bytes.as_slice(), &[0; 16]].concat(),
        ] {
            assert!(
                encryptor
                    .decrypt_all(
                        "identity",
                        &malformed,
                        &blob.base_nonce,
                        blob.plaintext_size
                    )
                    .is_err()
            );
            assert!(
                encryptor
                    .decrypt_range(
                        "identity",
                        &malformed,
                        &blob.base_nonce,
                        blob.plaintext_size,
                        0,
                        0
                    )
                    .is_err()
            );
        }
    }
    assert!(encryptor.decrypt_all("identity", &[], &[0; 8], 0).is_err());
    assert!(
        encryptor
            .decrypt_range("identity", &[], &[0; 8], u64::MAX, 0, 1)
            .is_err()
    );
}

#[test]
fn boundary_truncation_cannot_be_relabelled_as_a_complete_stream() {
    let directory = tempfile::tempdir().expect("KMS directory");
    let kms =
        kappa_crypto::kms::FileKms::new([9; 32], directory.path().join("erased")).expect("KMS");
    let encryptor = BlobEncryptor::new(&kms, "framing").expect("encryptor");
    for size in [0, 1, FRAME_SIZE, FRAME_SIZE + 1, FRAME_SIZE * 2] {
        let content = vec![31; size];
        let mut ciphertext = Vec::new();
        let (nonce, declared) = encryptor
            .encrypt_streaming("identity", &mut content.as_slice(), &mut ciphertext)
            .expect("streaming encryption");
        assert_eq!(declared, size as u64);
        assert_eq!(
            encryptor
                .decrypt_all("identity", &ciphertext, &nonce, declared)
                .expect("authenticated stream"),
            content
        );
        assert!(
            encryptor
                .decrypt_range("wrong identity", &ciphertext, &nonce, declared, 0, 0)
                .is_err()
        );
        if size > FRAME_SIZE {
            let truncated = &ciphertext[..kappa_crypto::aead::FRAME_DISK_SIZE];
            assert!(
                encryptor
                    .decrypt_all("identity", truncated, &nonce, FRAME_SIZE as u64)
                    .is_err()
            );
            assert!(
                encryptor
                    .decrypt_range("identity", truncated, &nonce, FRAME_SIZE as u64, 0, 1)
                    .is_err()
            );
        }
        let mut tampered = ciphertext.clone();
        *tampered.last_mut().expect("authenticated final frame") ^= 1;
        assert!(
            encryptor
                .decrypt_range("identity", &tampered, &nonce, declared, 0, 0)
                .is_err()
        );
    }
}
