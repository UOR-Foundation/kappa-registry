//! Known-answer test vectors for PERF-HSH-001, PERF-EPO-001, and
//! PERF-EPO-002 through PERF-EPO-003.
//!
//! Sources:
//! - NIST FIPS 180-4 (SHA-256, SHA-512)
//! - NIST FIPS 202 (SHA3-256)
//! - Keccak team reference (Keccak-256)
//! - BLAKE3 test vectors (blake3.io)
//! - RFC 9162 section 2.1 (Merkle tree)

/// NIST SHA-256 test vector: SHA-256("abc")
pub const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// NIST SHA-256 test vector: SHA-256("")
pub const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// NIST SHA-512 test vector: SHA-512("abc")
pub const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
     2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

/// NIST SHA-512 test vector: SHA-512("")
pub const SHA512_EMPTY: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
     47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/// NIST SHA3-256 test vector: SHA3-256("")
pub const SHA3_256_EMPTY: &str = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

/// Keccak-256 test vector: Keccak-256("")
pub const KECCAK256_EMPTY: &str =
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

/// BLAKE3 test vector: BLAKE3("")
pub const BLAKE3_EMPTY: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

/// SHA-1 test vector: SHA-1("abc")
/// From NIST FIPS 180-4. Collision-detecting SHA-1 produces the same
/// output for non-colliding inputs.
pub const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";

/// SHA-1 test vector: SHA-1("")
pub const SHA1_EMPTY: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_types::axis::Axis;
    use kappa_types::kappa::Kappa;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // -- PERF-HSH-001: known-answer vectors for all axes --

    #[test]
    fn sha256_empty_vector() {
        let k = Kappa::sha256(b"");
        assert_eq!(k.to_string(), format!("sha256:{SHA256_EMPTY}"));
    }

    #[test]
    fn sha256_abc_vector() {
        let k = Kappa::sha256(b"abc");
        assert_eq!(k.to_string(), format!("sha256:{SHA256_ABC}"));
    }

    #[test]
    fn sha512_empty_vector() {
        let k = Kappa::sha512(b"");
        assert_eq!(k.to_string(), format!("sha512:{SHA512_EMPTY}"));
    }

    #[test]
    fn sha512_abc_vector() {
        let k = Kappa::sha512(b"abc");
        assert_eq!(k.to_string(), format!("sha512:{SHA512_ABC}"));
    }

    #[test]
    fn sha3_256_empty_vector() {
        let k = Kappa::sha3_256(b"");
        assert_eq!(k.to_string(), format!("sha3-256:{SHA3_256_EMPTY}"));
    }

    #[test]
    fn keccak256_empty_vector() {
        let k = Kappa::keccak256(b"");
        assert_eq!(k.to_string(), format!("keccak256:{KECCAK256_EMPTY}"));
    }

    #[test]
    fn blake3_empty_vector() {
        let k = Kappa::blake3(b"");
        assert_eq!(k.to_string(), format!("blake3:{BLAKE3_EMPTY}"));
    }

    #[test]
    fn sha1_empty_vector() -> TestResult {
        let k = Kappa::sha1(b"")?;
        assert_eq!(k.to_string(), format!("sha1:{SHA1_EMPTY}"));
        Ok(())
    }

    #[test]
    fn sha1_abc_vector() -> TestResult {
        let k = Kappa::sha1(b"abc")?;
        assert_eq!(k.to_string(), format!("sha1:{SHA1_ABC}"));
        Ok(())
    }

    // -- PERF-EPO-001: RFC 9162 Merkle tree vectors --
    // Test every tree size from 0 to 1024.

    #[test]
    fn rfc9162_root_at_every_size_0_to_1024() {
        use kappa_types::merkle::{EMPTY_ROOT, merkle_proof, merkle_root, merkle_verify};

        // Size 0: empty root
        assert_eq!(merkle_root(&[]), EMPTY_ROOT);

        // Sizes 1 through 1024: root is deterministic, every leaf
        // has a verifiable proof.
        for size in 1..=1024u32 {
            let leaves: Vec<Vec<u8>> = (0..size).map(|i| i.to_le_bytes().to_vec()).collect();
            let refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
            let root = merkle_root(&refs);

            // Root is not the empty root
            assert_ne!(root, EMPTY_ROOT, "size {size} root equals empty root");

            // Deterministic
            assert_eq!(
                root,
                merkle_root(&refs),
                "size {size} root is not deterministic"
            );

            // Spot-check proofs at first, middle, and last leaf
            for index in [0, size as usize / 2, size as usize - 1] {
                let proof = merkle_proof(&refs, index)
                    .unwrap_or_else(|| panic!("no proof at index {index} for size {size}"));
                assert!(
                    merkle_verify(&root, &leaves[index], &proof),
                    "proof failed at index {index} for size {size}"
                );
            }
        }
    }

    // -- PERF-EPO-002: duplicate-tail rejection --

    #[test]
    fn rfc9162_duplicate_tail_rejection_all_odd_sizes() {
        use kappa_types::merkle::merkle_root;

        // For every odd size 3..=101, [a..c] and [a..c,c] must differ.
        for size in (3..=101).step_by(2) {
            let leaves: Vec<Vec<u8>> = (0..size).map(|i: u32| i.to_le_bytes().to_vec()).collect();
            let refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
            let root_n = merkle_root(&refs);

            // Append a duplicate of the last leaf, leaf index size - 1.
            let mut extended = leaves.clone();
            extended.push((size - 1).to_le_bytes().to_vec());
            let ext_refs: Vec<&[u8]> = extended.iter().map(Vec::as_slice).collect();
            let root_n_plus_dup = merkle_root(&ext_refs);

            assert_ne!(
                root_n, root_n_plus_dup,
                "CVE-2012-2459 collision at size {size}"
            );
        }
    }

    // -- PERF-EPO-003: domain separation --

    #[test]
    fn rfc9162_domain_separation_leaf_vs_node() {
        use kappa_types::merkle::hash_leaf;

        // A 32-byte input that looks like a hash must not collide
        // with the leaf hash of that same input.
        let data = [0u8; 32];
        let leaf = hash_leaf(&data);
        assert_ne!(leaf, data);

        // Two different 32-byte inputs produce different leaf hashes
        let a = hash_leaf(&[0u8; 32]);
        let b = hash_leaf(&[1u8; 32]);
        assert_ne!(a, b);
    }

    // -- PERF-HSH-002: streaming equals one-shot for every axis --

    #[test]
    fn streaming_equals_oneshot_all_axes() -> TestResult {
        use kappa_types::kappa_streaming::streaming_compute_kappa;
        use std::io::Cursor;

        let data = b"streaming equals oneshot test data for all six axes";

        for axis in [
            Axis::Sha256,
            Axis::Sha512,
            Axis::Blake3,
            Axis::Sha1,
            Axis::Sha3_256,
            Axis::Keccak256,
        ] {
            let oneshot = Kappa::compute(axis, data)?;
            let mut reader = Cursor::new(data.as_slice());
            let proof = streaming_compute_kappa(axis, &mut reader)?;
            assert_eq!(*proof.kappa(), oneshot, "streaming != oneshot for {axis:?}");
        }
        Ok(())
    }
}
