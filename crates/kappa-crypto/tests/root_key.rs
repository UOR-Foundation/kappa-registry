use kappa_crypto::keystore::load_root_key;

#[test]
fn root_key_admission_rejects_missing_short_and_excess_sources() {
    let directory = tempfile::tempdir().expect("key directory");
    let path = directory.path().join("root.key");
    assert!(load_root_key(&path).is_err());
    assert!(load_root_key(directory.path()).is_err());
    for size in [0, 1, 31, 33, 1048576] {
        std::fs::write(&path, vec![71; size]).expect("invalid fixture");
        let error = load_root_key(&path).expect_err("reject invalid length");
        assert!(
            !error.to_string().contains(&"G".repeat(32)),
            "diagnostics must not expose secret bytes"
        );
    }
    std::fs::write(&path, [71; 32]).expect("valid fixture");
    assert_eq!(*load_root_key(&path).expect("exact key"), [71; 32]);
}
