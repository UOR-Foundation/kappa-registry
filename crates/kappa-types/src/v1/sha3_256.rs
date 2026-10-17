//! SHA3-256 for content addresses, one backend per target.
//!
//! Follows the same dual-backend pattern as `sha256.rs`: x86-64 and
//! aarch64 hash through aws-lc (AVX2-vectorized Keccak permutation on
//! x86-64); every other target keeps the portable `RustCrypto`
//! implementation.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod backend {
    use aws_lc_rs::digest;

    fn bytes(digest: &digest::Digest) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        bytes(&digest::digest(&digest::SHA3_256, data))
    }

    #[derive(Clone)]
    pub struct Hasher(digest::Context);

    impl Hasher {
        pub fn new() -> Self {
            Self(digest::Context::new(&digest::SHA3_256))
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
    use sha3::Digest as _;

    fn bytes(digest: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(digest);
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        bytes(&sha3::Sha3_256::digest(data))
    }

    #[derive(Clone)]
    pub struct Hasher(sha3::Sha3_256);

    impl Hasher {
        pub fn new() -> Self {
            Self(sha3::Sha3_256::new())
        }

        pub fn update(&mut self, data: &[u8]) {
            sha3::Digest::update(&mut self.0, data);
        }

        pub fn finalize(self) -> [u8; 32] {
            bytes(&self.0.finalize())
        }
    }
}

/// SHA3-256 of `data`.
pub fn digest(data: &[u8]) -> [u8; 32] {
    backend::digest(data)
}

/// Incremental SHA3-256.
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

/// Dispatch provenance: which backend compiled this module.
pub const BACKEND: &str = if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
    "aws_lc"
} else {
    "sha3"
};

#[cfg(test)]
mod tests {
    use sha3::Digest as _;

    use super::*;

    #[test]
    fn backend_matches_known_answers_and_the_portable_implementation() {
        // FIPS 202 SHA3-256("") and SHA3-256("abc")
        assert_eq!(
            hex::encode(digest(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex::encode(digest(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );

        let data: Vec<u8> = (0..=u8::MAX).cycle().take(4 * 1024 + 7).collect();
        for length in (0..=200).chain([4096, data.len()]) {
            let message = &data[..length];
            let portable = sha3::Sha3_256::digest(message);
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
