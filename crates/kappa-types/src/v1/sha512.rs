//! SHA-512 for content addresses, one backend per target.
//!
//! Follows the same dual-backend pattern as `sha256.rs`: x86-64 and
//! aarch64 hash through aws-lc (AVX2 message-schedule interleaving on
//! x86-64, `ARMv8` SHA-2 on aarch64); every other target keeps the
//! portable `RustCrypto` implementation.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod backend {
    use aws_lc_rs::digest;

    fn bytes(digest: &digest::Digest) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(digest.as_ref());
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 64] {
        bytes(&digest::digest(&digest::SHA512, data))
    }

    #[derive(Clone)]
    pub struct Hasher(digest::Context);

    impl Hasher {
        pub fn new() -> Self {
            Self(digest::Context::new(&digest::SHA512))
        }

        pub fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }

        pub fn finalize(self) -> [u8; 64] {
            bytes(&self.0.finish())
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod backend {
    use sha2::Digest as _;

    fn bytes(digest: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(digest);
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 64] {
        bytes(&sha2::Sha512::digest(data))
    }

    #[derive(Clone)]
    pub struct Hasher(sha2::Sha512);

    impl Hasher {
        pub fn new() -> Self {
            Self(sha2::Sha512::new())
        }

        pub fn update(&mut self, data: &[u8]) {
            sha2::Digest::update(&mut self.0, data);
        }

        pub fn finalize(self) -> [u8; 64] {
            bytes(&self.0.finalize())
        }
    }
}

/// SHA-512 of `data`.
pub fn digest(data: &[u8]) -> [u8; 64] {
    backend::digest(data)
}

/// Incremental SHA-512.
#[derive(Clone)]
pub struct Hasher(backend::Hasher);

impl Hasher {
    pub fn new() -> Self {
        Self(backend::Hasher::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; 64] {
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
    "sha2"
};

#[cfg(test)]
mod tests {
    use sha2::Digest as _;

    use super::*;

    #[test]
    fn backend_matches_known_answers_and_the_portable_implementation() {
        // FIPS 180-4 SHA-512("") and SHA-512("abc")
        assert_eq!(
            hex::encode(digest(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            hex::encode(digest(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );

        let data: Vec<u8> = (0..=u8::MAX).cycle().take(4 * 1024 + 7).collect();
        for length in (0..=200).chain([4096, data.len()]) {
            let message = &data[..length];
            let portable = sha2::Sha512::digest(message);
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
