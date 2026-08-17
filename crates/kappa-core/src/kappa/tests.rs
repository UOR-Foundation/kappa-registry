//! Tests for the kappa module.

#[cfg(test)]
mod tests {
    use crate::kappa::*;

    const EMPTY_SHA1: &str = "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const HELLO_SHA1: &str = "sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
    const EMPTY_SHA256: &str =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HELLO_SHA256: &str =
        "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const EMPTY_BLAKE3: &str =
        "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const HELLO_BLAKE3: &str =
        "blake3:ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";
    const EMPTY_SHA3_256: &str =
        "sha3-256:a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    const HELLO_SHA3_256: &str =
        "sha3-256:3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392";
    const EMPTY_KECCAK256: &str =
        "keccak256:c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    const HELLO_KECCAK256: &str =
        "keccak256:1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";

    // -- SHA-1 ----------------------------------------------------------------

    #[test]
    fn sha1_empty() {
        assert_eq!(KappaLabel::sha1(b"").unwrap().as_str(), EMPTY_SHA1);
    }

    #[test]
    fn sha1_hello() {
        assert_eq!(KappaLabel::sha1(b"hello").unwrap().as_str(), HELLO_SHA1);
    }

    #[test]
    fn sha1_label_length() {
        assert_eq!(KappaLabel::sha1(b"x").unwrap().as_str().len(), 45);
    }

    #[test]
    fn parse_roundtrip_sha1() {
        let k = KappaLabel::sha1(b"test").unwrap();
        let parsed = KappaLabel::parse(k.as_str()).unwrap();
        assert_eq!(k, parsed);
    }

    #[test]
    fn parse_sha1_wrong_digits() {
        let s = format!("sha1:{}", "a".repeat(41));
        assert_eq!(s.len(), 46);
        assert!(matches!(
            KappaLabel::parse(&s),
            Err(LabelError::WrongDigitCount {
                expected: 40,
                got: 41
            })
        ));
    }

    #[test]
    fn verify_sha1() {
        assert_eq!(verify_kappa(HELLO_SHA1, b"hello"), Ok(true));
    }

    #[test]
    fn verify_sha1_mismatch() {
        assert_eq!(verify_kappa(HELLO_SHA1, b"wrong"), Ok(false));
    }

    #[test]
    fn complement_sha1_roundtrip() {
        let k = KappaLabel::sha1(b"involution test").unwrap();
        assert_eq!(k.complement().complement(), k);
    }

    // -- SHA-256 --------------------------------------------------------------

    #[test]
    fn sha256_empty() {
        assert_eq!(KappaLabel::sha256(b"").as_str(), EMPTY_SHA256);
    }

    #[test]
    fn sha256_hello() {
        assert_eq!(KappaLabel::sha256(b"hello").as_str(), HELLO_SHA256);
    }

    #[test]
    fn blob_kappa_is_sha256() {
        let data = b"hello world";
        let kappa = kappa_from_bytes(data);
        assert!(kappa.starts_with("sha256:"));
        assert_eq!(
            kappa,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    // -- BLAKE3 ---------------------------------------------------------------

    #[test]
    fn blake3_empty() {
        assert_eq!(KappaLabel::blake3(b"").as_str(), EMPTY_BLAKE3);
    }

    #[test]
    fn blake3_hello() {
        assert_eq!(KappaLabel::blake3(b"hello").as_str(), HELLO_BLAKE3);
    }

    // -- SHA-3-256 -------------------------------------------------------------

    #[test]
    fn sha3_256_empty() {
        assert_eq!(KappaLabel::sha3_256(b"").as_str(), EMPTY_SHA3_256);
    }

    #[test]
    fn sha3_256_hello() {
        assert_eq!(KappaLabel::sha3_256(b"hello").as_str(), HELLO_SHA3_256);
    }

    #[test]
    fn sha3_256_label_length() {
        assert_eq!(KappaLabel::sha3_256(b"x").as_str().len(), 73);
    }

    #[test]
    fn parse_roundtrip_sha3_256() {
        let k = KappaLabel::sha3_256(b"test");
        let parsed = KappaLabel::parse(k.as_str()).unwrap();
        assert_eq!(k, parsed);
    }

    #[test]
    fn verify_sha3_256() {
        assert_eq!(verify_kappa(HELLO_SHA3_256, b"hello"), Ok(true));
    }

    #[test]
    fn verify_sha3_256_mismatch() {
        assert_eq!(verify_kappa(HELLO_SHA3_256, b"wrong"), Ok(false));
    }

    #[test]
    fn complement_sha3_256_roundtrip() {
        let k = KappaLabel::sha3_256(b"involution test");
        assert_eq!(k.complement().complement(), k);
    }

    // -- Keccak-256 -----------------------------------------------------------

    #[test]
    fn keccak256_empty() {
        assert_eq!(KappaLabel::keccak256(b"").as_str(), EMPTY_KECCAK256);
    }

    #[test]
    fn keccak256_hello() {
        assert_eq!(KappaLabel::keccak256(b"hello").as_str(), HELLO_KECCAK256);
    }

    #[test]
    fn keccak256_label_length() {
        assert_eq!(KappaLabel::keccak256(b"x").as_str().len(), 74);
    }

    #[test]
    fn parse_roundtrip_keccak256() {
        let k = KappaLabel::keccak256(b"test");
        let parsed = KappaLabel::parse(k.as_str()).unwrap();
        assert_eq!(k, parsed);
    }

    #[test]
    fn verify_keccak256() {
        assert_eq!(verify_kappa(HELLO_KECCAK256, b"hello"), Ok(true));
    }

    #[test]
    fn verify_keccak256_mismatch() {
        assert_eq!(verify_kappa(HELLO_KECCAK256, b"wrong"), Ok(false));
    }

    #[test]
    fn complement_keccak256_roundtrip() {
        let k = KappaLabel::keccak256(b"involution test");
        assert_eq!(k.complement().complement(), k);
    }

    // -- SHA-3-256 vs Keccak-256 distinction ----------------------------------

    #[test]
    fn sha3_256_differs_from_keccak256() {
        // Same input, different padding, different output
        let sha3 = KappaLabel::sha3_256(b"distinct");
        let keccak = KappaLabel::keccak256(b"distinct");
        assert_ne!(sha3.as_str(), keccak.as_str());
        assert_ne!(sha3.axis(), keccak.axis());
    }

    // -- Every axis computes and verifies -------------------------------------

    #[test]
    fn every_parsed_axis_can_be_computed_and_verified() {
        for axis in ["sha1", "sha256", "blake3", "sha3-256", "keccak256", "sha512"] {
            let label = compute_kappa(axis, b"axis parity").unwrap();
            assert_eq!(KappaLabel::parse(label.as_str()).unwrap(), label);
            assert_eq!(verify_kappa(label.as_str(), b"axis parity"), Ok(true));
        }
    }

    // -- Parse and verify -----------------------------------------------------

    #[test]
    fn parse_roundtrip_sha256() {
        let k = KappaLabel::sha256(b"test");
        let parsed = KappaLabel::parse(k.as_str()).unwrap();
        assert_eq!(k, parsed);
    }

    #[test]
    fn parse_roundtrip_blake3() {
        let k = KappaLabel::blake3(b"test");
        let parsed = KappaLabel::parse(k.as_str()).unwrap();
        assert_eq!(k, parsed);
    }

    #[test]
    fn reject_unknown_axis() {
        let s = format!("unknown:{}", "a".repeat(64));
        assert!(matches!(
            KappaLabel::parse(&s),
            Err(LabelError::UnknownAxis)
        ));
    }

    #[test]
    fn reject_uppercase_hex() {
        let s = format!("sha256:{}", "A".repeat(64));
        assert!(matches!(
            KappaLabel::parse(&s),
            Err(LabelError::BadHex { .. })
        ));
    }

    #[test]
    fn verify_match() {
        assert_eq!(verify_kappa(HELLO_SHA256, b"hello"), Ok(true));
    }

    #[test]
    fn verify_mismatch() {
        assert_eq!(verify_kappa(HELLO_SHA256, b"wrong"), Ok(false));
    }

    #[test]
    fn complement_roundtrip() {
        let k = KappaLabel::sha256(b"involution test");
        assert_eq!(k.complement().complement(), k);
    }

    // -- Structured values ----------------------------------------------------

    #[test]
    fn structured_value_kappa_is_deterministic() {
        let v1 = "test value".to_string();
        let v2 = "test value".to_string();
        assert_eq!(kappa_from_value(&v1), kappa_from_value(&v2));
    }

    #[test]
    fn verify_kappa_succeeds_on_match() {
        let data = b"verify me";
        let kappa = kappa_from_bytes(data);
        assert_eq!(verify_kappa(&kappa, data), Ok(true));
    }

    #[test]
    fn verify_kappa_fails_on_mismatch() {
        let data = b"verify me";
        let kappa = kappa_from_bytes(data);
        assert_eq!(verify_kappa(&kappa, b"different data"), Ok(false));
    }

    // -- split_kappa ----------------------------------------------------------

    #[test]
    fn split_kappa_parses_correctly() {
        let (algo, digest) = split_kappa("sha256:abcdef").unwrap();
        assert_eq!(algo, "sha256");
        assert_eq!(digest, "abcdef");
    }

    #[test]
    fn split_kappa_rejects_no_colon() {
        assert!(split_kappa("sha256abcdef").is_none());
    }

    #[test]
    fn split_kappa_rejects_empty_parts() {
        assert!(split_kappa(":abcdef").is_none());
        assert!(split_kappa("sha256:").is_none());
    }

    // -- compute_kappa multi-axis ---------------------------------------------

    #[test]
    fn compute_kappa_sha256() {
        let k = compute_kappa("sha256", b"hello").unwrap();
        assert_eq!(k.as_str(), HELLO_SHA256);
    }

    #[test]
    fn compute_kappa_blake3() {
        let k = compute_kappa("blake3", b"hello").unwrap();
        assert_eq!(k.as_str(), HELLO_BLAKE3);
    }

    #[test]
    fn compute_kappa_sha1() {
        let k = compute_kappa("sha1", b"hello").unwrap();
        assert_eq!(k.as_str(), HELLO_SHA1);
    }

    #[test]
    fn compute_kappa_sha3_256() {
        let k = compute_kappa("sha3-256", b"hello").unwrap();
        assert_eq!(k.as_str(), HELLO_SHA3_256);
    }

    #[test]
    fn compute_kappa_keccak256() {
        let k = compute_kappa("keccak256", b"hello").unwrap();
        assert_eq!(k.as_str(), HELLO_KECCAK256);
    }

    #[test]
    fn compute_kappa_unknown_axis() {
        assert!(matches!(
            compute_kappa("md5", b"hello"),
            Err(LabelError::UnknownAxis)
        ));
    }

    // -- axis_of --------------------------------------------------------------

    #[test]
    fn axis_of_sha256() {
        assert_eq!(axis_of("sha256:abc"), Some("sha256"));
    }

    #[test]
    fn axis_of_blake3() {
        assert_eq!(axis_of("blake3:def"), Some("blake3"));
    }

    #[test]
    fn axis_of_no_colon() {
        assert_eq!(axis_of("nocolon"), None);
    }

    // -- Axis enum ------------------------------------------------------------

    #[test]
    fn axis_enum_roundtrip() {
        for axis in [
            Axis::Sha1,
            Axis::Sha256,
            Axis::Blake3,
            Axis::Sha512,
            Axis::Sha3_256,
            Axis::Keccak256,
        ] {
            assert_eq!(Axis::parse(axis.as_str()), Some(axis));
        }
    }

    #[test]
    fn axis_enum_unknown() {
        assert_eq!(Axis::parse("md5"), None);
    }

    #[test]
    fn label_axis_enum() {
        let k = KappaLabel::sha256(b"test");
        assert_eq!(k.axis_enum(), Axis::Sha256);
    }

    #[test]
    fn label_hex_digest() {
        let k = KappaLabel::sha256(b"hello");
        let hex = k.hex_digest();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -- blob_path_for --------------------------------------------------------

    #[test]
    fn blob_path_for_sha256() {
        let root = std::path::Path::new("/blobs");
        let kappa = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let path = blob_path_for(root, kappa).unwrap();
        assert_eq!(
            path,
            std::path::PathBuf::from(
                "/blobs/sha256/ab/cd/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            )
        );
    }

    #[test]
    fn blob_path_for_sha512() {
        let root = std::path::Path::new("/blobs");
        let hex = "a".repeat(128);
        let kappa = format!("sha512:{}", hex);
        let path = blob_path_for(root, &kappa).unwrap();
        assert_eq!(path, std::path::PathBuf::from(format!("/blobs/sha512/aa/aa/{}", hex)));
    }

    #[test]
    fn blob_path_for_rejects_no_colon() {
        let root = std::path::Path::new("/blobs");
        assert!(blob_path_for(root, "sha256abcdef").is_err());
    }

    #[test]
    fn blob_path_for_rejects_short_digest() {
        let root = std::path::Path::new("/blobs");
        assert!(blob_path_for(root, "sha256:ab").is_err());
    }

    #[test]
    fn blob_path_for_rejects_uppercase() {
        let root = std::path::Path::new("/blobs");
        let kappa = format!("sha256:{}", "A".repeat(64));
        assert!(blob_path_for(root, &kappa).is_err());
    }

    #[test]
    fn blob_path_for_rejects_path_traversal() {
        let root = std::path::Path::new("/blobs");
        assert!(blob_path_for(root, "sha256:../../etc/passwd").is_err());
    }

    #[test]
    fn blob_path_for_rejects_dots() {
        let root = std::path::Path::new("/blobs");
        assert!(blob_path_for(root, "sha256:....").is_err());
    }

    // -- Streaming multi-axis computation adversarial tests --------------------

    #[test]
    fn streaming_compute_multi_primary_is_first_axis() {
        let content = b"primary axis selection test";
        let mut cursor = std::io::Cursor::new(content);
        let proof = streaming_compute_multi(&["blake3", "sha256"], &mut cursor).unwrap();
        assert!(proof.kappa().starts_with("blake3:"), "primary should be blake3, got {}", proof.kappa());
    }

    #[test]
    fn streaming_compute_multi_primary_is_first_axis_reversed() {
        let content = b"primary axis selection test reversed";
        let mut cursor = std::io::Cursor::new(content);
        let proof = streaming_compute_multi(&["sha256", "blake3"], &mut cursor).unwrap();
        assert!(proof.kappa().starts_with("sha256:"), "primary should be sha256, got {}", proof.kappa());
    }

    #[test]
    fn streaming_compute_multi_all_six_axes() {
        let content = b"all six axes test";
        let mut cursor = std::io::Cursor::new(content);
        let proof = streaming_compute_multi(
            &["sha1", "sha256", "blake3", "sha512", "sha3-256", "keccak256"],
            &mut cursor,
        ).unwrap();
        assert!(proof.kappa().starts_with("sha1:"), "primary should be sha1");
        assert_eq!(proof.additional().len(), 5, "should have 5 additional axes");
    }

    #[test]
    fn streaming_compute_multi_single_axis() {
        let content = b"single axis test";
        let mut cursor = std::io::Cursor::new(content);
        let proof = streaming_compute_multi(&["sha256"], &mut cursor).unwrap();
        assert!(proof.kappa().starts_with("sha256:"));
        assert!(proof.additional().is_empty(), "single axis should have no additional");
    }

    #[test]
    fn streaming_compute_multi_duplicate_axis() {
        let content = b"duplicate axis test";
        let mut cursor = std::io::Cursor::new(content);
        let proof = streaming_compute_multi(&["sha256", "sha256"], &mut cursor).unwrap();
        assert!(proof.kappa().starts_with("sha256:"));
        // Duplicate axis: only one hasher created, results list has one entry
        // The primary consumes it, additional should be empty
        assert!(proof.additional().is_empty());
    }

    #[test]
    fn streaming_compute_multi_unknown_axis_rejected() {
        let content = b"unknown axis";
        let mut cursor = std::io::Cursor::new(content);
        let result = streaming_compute_multi(&["unknown"], &mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn streaming_compute_multi_empty_content() {
        let mut cursor = std::io::Cursor::new(b"");
        let proof = streaming_compute_multi(&["sha256", "blake3"], &mut cursor).unwrap();
        let oneshot_sha256 = KappaLabel::sha256(b"");
        assert_eq!(proof.kappa(), oneshot_sha256.as_str());
    }

    #[test]
    fn streaming_compute_multi_large_content() {
        let content: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
        let mut cursor = std::io::Cursor::new(&content);
        let proof = streaming_compute_multi(&["sha256"], &mut cursor).unwrap();
        let oneshot = KappaLabel::sha256(&content);
        assert_eq!(proof.kappa(), oneshot.as_str());
    }

    #[test]
    fn streaming_compute_kappa_matches_one_shot() {
        let content = b"streaming vs oneshot comparison";
        for axis in &["sha1", "sha256", "blake3", "sha512", "sha3-256", "keccak256"] {
            let mut cursor = std::io::Cursor::new(content);
            let proof = streaming_compute_kappa(axis, &mut cursor).unwrap();
            let oneshot = compute_kappa(axis, content).unwrap();
            assert_eq!(proof.kappa(), oneshot.as_str(), "mismatch for axis {}", axis);
        }
    }

}
