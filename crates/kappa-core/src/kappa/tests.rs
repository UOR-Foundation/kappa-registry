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

    // -- Sha1Policy -----------------------------------------------------------

    #[test]
    fn sha1_policy_default_is_allow() {
        assert_eq!(Sha1Policy::default(), Sha1Policy::Allow);
    }

    #[test]
    fn sha1_policy_from_str() {
        assert_eq!(Sha1Policy::parse_str("allow"), Sha1Policy::Allow);
        assert_eq!(Sha1Policy::parse_str("deny"), Sha1Policy::Deny);
        assert_eq!(
            Sha1Policy::parse_str("upgrade"),
            Sha1Policy::AllowWithSha256Upgrade
        );
        assert_eq!(Sha1Policy::parse_str("unknown"), Sha1Policy::Allow);
        assert_eq!(Sha1Policy::parse_str(""), Sha1Policy::Allow);
    }

    #[test]
    fn sha1_policy_roundtrip() {
        for policy in [
            Sha1Policy::Allow,
            Sha1Policy::Deny,
            Sha1Policy::AllowWithSha256Upgrade,
        ] {
            assert_eq!(Sha1Policy::parse_str(policy.as_str()), policy);
        }
    }
}
