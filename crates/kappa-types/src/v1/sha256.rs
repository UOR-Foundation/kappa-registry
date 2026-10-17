//! SHA-256 for content addresses, one backend per target.
//!
//! SHA-256 is the mandatory axis of every ingest, so its rate bounds every
//! store write. `RustCrypto` `sha2` 0.11 dispatches SHA-256 on x86-64 to
//! SHA-NI only and otherwise runs portable code (sha2 `src/sha256.rs`); on
//! hosts without SHA-NI that is a third of aws-lc's AVX2 assembly, as the
//! calibration's reference floors measure. x86-64 and aarch64 therefore
//! hash through aws-lc, which dispatches to SHA-NI, AVX2 or the `ARMv8` SHA-2
//! instructions at run time; every other target (wasm among them, where
//! aws-lc does not build) keeps the portable `RustCrypto` implementation. The
//! backend is chosen per target at compile time: one per build, never a
//! runtime fallback.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod backend {
    use aws_lc_rs::digest;

    fn bytes(digest: &digest::Digest) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        bytes(&digest::digest(&digest::SHA256, data))
    }

    #[derive(Clone)]
    pub struct Hasher(digest::Context);

    impl Hasher {
        pub fn new() -> Self {
            Self(digest::Context::new(&digest::SHA256))
        }

        pub fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }

        pub fn finalize(self) -> [u8; 32] {
            bytes(&self.0.finish())
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod backend {
    use sha2::Digest as _;

    fn bytes(digest: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(digest);
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        bytes(&sha2::Sha256::digest(data))
    }

    #[derive(Clone)]
    pub struct Hasher(sha2::Sha256);

    impl Hasher {
        pub fn new() -> Self {
            Self(sha2::Sha256::new())
        }

        pub fn update(&mut self, data: &[u8]) {
            sha2::Digest::update(&mut self.0, data);
        }

        pub fn finalize(self) -> [u8; 32] {
            bytes(&self.0.finalize())
        }
    }
}

/// SHA-256 of `data`.
pub fn digest(data: &[u8]) -> [u8; 32] {
    backend::digest(data)
}

/// Incremental SHA-256.
#[derive(Clone)]
pub struct Hasher(backend::Hasher);

impl Hasher {
    pub fn new() -> Self {
        Self(backend::Hasher::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize()
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

    use super::*;

    /// FIPS 180-4 known answers, and agreement with the portable
    /// implementation at every length through the 64-byte block and the
    /// 56-byte padding threshold, one-shot and across split updates.
    #[test]
    fn backend_matches_known_answers_and_the_portable_implementation() {
        assert_eq!(
            hex::encode(digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let data: Vec<u8> = (0..=u8::MAX).cycle().take(4 * 1024 + 7).collect();
        for length in (0..=200).chain([4096, data.len()]) {
            let message = &data[..length];
            let portable = sha2::Sha256::digest(message);
            assert_eq!(
                digest(message).as_slice(),
                portable.as_slice(),
                "one-shot at {length}"
            );
            let mut split = Hasher::new();
            let (head, tail) = message.split_at(length / 3);
            split.update(head);
            split.update(&[]);
            split.update(tail);
            assert_eq!(
                split.finalize().as_slice(),
                portable.as_slice(),
                "split update at {length}"
            );
        }
    }
}
