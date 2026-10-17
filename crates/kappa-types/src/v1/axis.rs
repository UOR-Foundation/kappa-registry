/// Digest algorithm axis for content addressing.
///
/// SHA-256 is the mandatory secondary axis. Every ingest computes
/// SHA-256 regardless of which axis the client chose, so every
/// blob is discoverable by its SHA-256 address across all protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Axis {
    Sha256,
    Sha512,
    Blake3,
    Sha1,
    Sha3_256,
    Keccak256,
}

impl Axis {
    /// Wire-format name used in kappa-label strings ("sha256:abcd...").
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Blake3 => "blake3",
            Self::Sha1 => "sha1",
            Self::Sha3_256 => "sha3-256",
            Self::Keccak256 => "keccak256",
        }
    }

    /// Number of hex characters in the wire-format digest string.
    pub const fn hex_len(&self) -> usize {
        self.digest_len() * 2
    }

    /// Number of raw digest bytes produced by this hash function.
    /// This is the length stored in Kappa's internal representation.
    pub const fn digest_len(&self) -> usize {
        self.digest_len_u8() as usize
    }

    /// Digest length for the compact internal representation.
    pub const fn digest_len_u8(&self) -> u8 {
        match self {
            Self::Sha256 | Self::Blake3 | Self::Sha3_256 | Self::Keccak256 => 32,
            Self::Sha512 => 64,
            Self::Sha1 => 20,
        }
    }

    /// Parse an axis name from a wire-format string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            "blake3" => Some(Self::Blake3),
            "sha1" => Some(Self::Sha1),
            "sha3-256" => Some(Self::Sha3_256),
            "keccak256" => Some(Self::Keccak256),
            _ => None,
        }
    }

    /// Single-byte discriminant for compact binary encoding.
    /// Used as the first byte when serializing Kappa to redb keys.
    pub const fn discriminant(&self) -> u8 {
        match self {
            Self::Sha256 => 0,
            Self::Sha512 => 1,
            Self::Blake3 => 2,
            Self::Sha1 => 3,
            Self::Sha3_256 => 4,
            Self::Keccak256 => 5,
        }
    }

    /// Reconstruct from a discriminant byte.
    pub const fn from_discriminant(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Sha256),
            1 => Some(Self::Sha512),
            2 => Some(Self::Blake3),
            3 => Some(Self::Sha1),
            4 => Some(Self::Sha3_256),
            5 => Some(Self::Keccak256),
            _ => None,
        }
    }
}

impl std::fmt::Display for Axis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
