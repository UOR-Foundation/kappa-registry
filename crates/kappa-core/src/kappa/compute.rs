//! Hash computation for kappa-labels.
//!
//! Each supported algorithm has a one-shot compute function on KappaLabel
//! and a dispatch function compute_kappa(axis, content). SHA-1 uses
//! collision detection (sha1-checked crate) and is fallible.
//!
//! dCBOR-aware computation: kappa_from_value() serializes a structured
//! value to canonical dCBOR bytes before hashing with SHA-256.

use sha1_checked::Sha1 as Sha1Checked;
use sha2::{Digest, Sha256, Sha512};
use sha3::{Keccak256, Sha3_256};

use super::label::{KappaLabel, LabelError, HEX};

impl KappaLabel {
    /// Compute the SHA-256 kappa-label of content. Infallible.
    pub fn sha256(content: &[u8]) -> Self {
        let hash = Sha256::digest(content);
        let mut buf = [0u8; 135];
        buf[..7].copy_from_slice(b"sha256:");
        for (i, &byte) in hash.iter().enumerate() {
            buf[7 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[7 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        Self::from_parts(buf, 71)
    }

    /// Compute the BLAKE3 kappa-label of content. Infallible.
    pub fn blake3(content: &[u8]) -> Self {
        let hash = blake3::hash(content);
        let mut buf = [0u8; 135];
        buf[..7].copy_from_slice(b"blake3:");
        for (i, &byte) in hash.as_bytes().iter().enumerate() {
            buf[7 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[7 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        Self::from_parts(buf, 71)
    }

    /// Compute the SHA-512 kappa-label of content. Infallible.
    pub fn sha512(content: &[u8]) -> Self {
        let hash = Sha512::digest(content);
        let mut buf = [0u8; 135];
        buf[..7].copy_from_slice(b"sha512:");
        for (i, &byte) in hash.iter().enumerate() {
            buf[7 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[7 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        Self::from_parts(buf, 135)
    }

    /// Compute the SHA-3-256 kappa-label of content. Infallible.
    ///
    /// SHA-3-256 is the FIPS 202 standardized version of Keccak with
    /// domain separation padding (pad byte 0x06). 32-byte output.
    pub fn sha3_256(content: &[u8]) -> Self {
        let hash = Sha3_256::digest(content);
        let mut buf = [0u8; 135];
        buf[..9].copy_from_slice(b"sha3-256:");
        for (i, &byte) in hash.iter().enumerate() {
            buf[9 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[9 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        Self::from_parts(buf, 73)
    }

    /// Compute the Keccak-256 kappa-label of content. Infallible.
    ///
    /// Keccak-256 is the original Keccak submission (pad byte 0x01),
    /// used by Ethereum and other blockchain systems. 32-byte output.
    /// Distinct from SHA-3-256 despite both using the Keccak permutation.
    pub fn keccak256(content: &[u8]) -> Self {
        let hash = Keccak256::digest(content);
        let mut buf = [0u8; 135];
        buf[..10].copy_from_slice(b"keccak256:");
        for (i, &byte) in hash.iter().enumerate() {
            buf[10 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[10 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        Self::from_parts(buf, 74)
    }

    /// Compute a SHA-1 kappa-label with collision detection.
    ///
    /// Returns Err(LabelError::CollisionDetected) if the content
    /// triggers the SHA-1 collision detection algorithm. Legitimate
    /// content never triggers this -- only crafted collision attacks.
    ///
    /// The sha1-checked crate wraps Marc Stevens' sha1collisiondetection.
    /// safe_hash mode is enabled by default: when a collision block is
    /// detected, the block is hashed 3x (240 rounds instead of 80),
    /// producing a different hash than standard SHA-1. Double protection.
    pub fn sha1(content: &[u8]) -> Result<Self, LabelError> {
        let result = Sha1Checked::try_digest(content);
        if result.has_collision() {
            return Err(LabelError::CollisionDetected);
        }
        let hash = result.hash();
        let mut buf = [0u8; 135];
        buf[..5].copy_from_slice(b"sha1:");
        for (i, &byte) in hash.iter().enumerate() {
            buf[5 + 2 * i] = HEX[(byte >> 4) as usize];
            buf[5 + 2 * i + 1] = HEX[(byte & 0x0f) as usize];
        }
        Ok(Self::from_parts(buf, 45))
    }
}

/// Compute the kappa-label of content under the given axis.
///
/// Dispatches to the correct hash algorithm. Returns LabelError::UnknownAxis
/// for unrecognized algorithm names.
pub fn compute_kappa(axis: &str, content: &[u8]) -> Result<KappaLabel, LabelError> {
    match axis {
        "sha1" => KappaLabel::sha1(content),
        "sha256" => Ok(KappaLabel::sha256(content)),
        "blake3" => Ok(KappaLabel::blake3(content)),
        "sha3-256" => Ok(KappaLabel::sha3_256(content)),
        "keccak256" => Ok(KappaLabel::keccak256(content)),
        "sha512" => Ok(KappaLabel::sha512(content)),
        _ => Err(LabelError::UnknownAxis),
    }
}

/// Verify that content hashes to the claimed kappa-label under its own axis.
///
/// Parses the kappa-label to determine the algorithm, recomputes the hash,
/// and compares. Returns Ok(false) on mismatch, Err on parse/compute failure.
pub fn verify_kappa(kappa: &str, content: &[u8]) -> Result<bool, LabelError> {
    let parsed = KappaLabel::parse(kappa)?;
    let computed = compute_kappa(parsed.axis(), content)?;
    Ok(computed.as_str() == kappa)
}

/// Compute the kappa-label of raw bytes using SHA-256.
///
/// Blobs are opaque bytes -- they are not dCBOR-encoded before hashing.
/// The default axis for blob storage is SHA-256.
pub fn kappa_from_bytes(bytes: &[u8]) -> String {
    KappaLabel::sha256(bytes).as_str().to_string()
}

/// Compute the kappa-label of a structured value.
///
/// The value is first serialized to canonical dCBOR bytes via
/// canonical_bytes(), then SHA-256 hashed. This ensures the kappa-label
/// is deterministic across implementations and architectures.
pub fn kappa_from_value<T: Into<dcbor::CBOR> + Clone>(value: &T) -> String {
    let bytes = crate::canonical::canonical_bytes(value);
    kappa_from_bytes(&bytes)
}

/// Streaming kappa computation from a reader. 16 KiB incremental hashing.
///
/// SSOT for streaming digest verification. Every path that needs to hash
/// a file without reading it entirely into memory calls this function.
/// Supports all six axes. SHA-1 uses collision-detecting incremental hasher.
///
/// Returns a `StreamingVerificationProof` -- a sealed proof type that
/// can only be produced by this function and consumed by `upload_complete`.
/// The compiler enforces that no unverified kappa reaches storage via
/// the streaming path.
pub fn streaming_compute_kappa(
    axis: &str,
    reader: &mut dyn std::io::Read,
) -> Result<crate::verified::StreamingVerificationProof, LabelError> {
    let mut buf = [0u8; 16384];
    match axis {
        "sha256" => {
            let mut h = Sha256::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| LabelError::DigestMismatch {
                    expected: String::new(), computed: e.to_string(), axis: axis.to_string(),
                })?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(crate::verified::StreamingVerificationProof::single(format!("sha256:{}", hex::encode(h.finalize()))))
        }
        "sha512" => {
            let mut h = Sha512::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| LabelError::DigestMismatch {
                    expected: String::new(), computed: e.to_string(), axis: axis.to_string(),
                })?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(crate::verified::StreamingVerificationProof::single(format!("sha512:{}", hex::encode(h.finalize()))))
        }
        "blake3" => {
            let mut h = blake3::Hasher::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| LabelError::DigestMismatch {
                    expected: String::new(), computed: e.to_string(), axis: axis.to_string(),
                })?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(crate::verified::StreamingVerificationProof::single(format!("blake3:{}", h.finalize().to_hex())))
        }
        "sha3-256" => {
            let mut h = Sha3_256::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| LabelError::DigestMismatch {
                    expected: String::new(), computed: e.to_string(), axis: axis.to_string(),
                })?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(crate::verified::StreamingVerificationProof::single(format!("sha3-256:{}", hex::encode(h.finalize()))))
        }
        "keccak256" => {
            let mut h = Keccak256::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| LabelError::DigestMismatch {
                    expected: String::new(), computed: e.to_string(), axis: axis.to_string(),
                })?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            Ok(crate::verified::StreamingVerificationProof::single(format!("keccak256:{}", hex::encode(h.finalize()))))
        }
        "sha1" => {
            use sha1_checked::Sha1 as Sha1Checked;
            use sha1_checked::Digest as _;
            let mut h = Sha1Checked::new();
            loop {
                let n = reader.read(&mut buf).map_err(|e| LabelError::DigestMismatch {
                    expected: String::new(), computed: e.to_string(), axis: axis.to_string(),
                })?;
                if n == 0 { break; }
                h.update(&buf[..n]);
            }
            let result = h.try_finalize();
            if result.has_collision() {
                return Err(LabelError::CollisionDetected);
            }
            Ok(crate::verified::StreamingVerificationProof::single(format!("sha1:{}", hex::encode(result.hash()))))
        }
        _ => Err(LabelError::UnknownAxis),
    }
}

/// Multi-axis streaming hash. One read pass, N hashers running in parallel.
///
/// The first axis in `axes` is the primary. Additional axes produce
/// additional verified kappas carried inside the proof. Returns a single
/// `StreamingVerificationProof` carrying all results.
///
/// The primary use is `upload_complete` computing the client's claimed
/// axis plus all mandatory axes (at minimum sha256) in a single pass.
pub fn streaming_compute_multi(
    axes: &[&str],
    reader: &mut dyn std::io::Read,
) -> Result<crate::verified::StreamingVerificationProof, LabelError> {
    use sha1_checked::Sha1 as Sha1Checked;
    use sha1_checked::Digest as Sha1Digest;

    // Initialize all hashers
    let mut sha256_h: Option<Sha256> = None;
    let mut sha512_h: Option<Sha512> = None;
    let mut blake3_h: Option<blake3::Hasher> = None;
    let mut sha3_256_h: Option<Sha3_256> = None;
    let mut keccak256_h: Option<Keccak256> = None;
    let mut sha1_h: Option<Sha1Checked> = None;

    for axis in axes {
        match *axis {
            "sha256" => { sha256_h.get_or_insert_with(Sha256::new); }
            "sha512" => { sha512_h.get_or_insert_with(Sha512::new); }
            "blake3" => { blake3_h.get_or_insert_with(blake3::Hasher::new); }
            "sha3-256" => { sha3_256_h.get_or_insert_with(Sha3_256::new); }
            "keccak256" => { keccak256_h.get_or_insert_with(Keccak256::new); }
            "sha1" => { sha1_h.get_or_insert_with(Sha1Checked::new); }
            _ => return Err(LabelError::UnknownAxis),
        }
    }

    // Single read loop feeding all hashers
    let mut buf = [0u8; 16384];
    loop {
        let n = reader.read(&mut buf).map_err(|e| LabelError::DigestMismatch {
            expected: String::new(),
            computed: e.to_string(),
            axis: "multi".to_string(),
        })?;
        if n == 0 { break; }
        let chunk = &buf[..n];
        if let Some(ref mut h) = sha256_h { h.update(chunk); }
        if let Some(ref mut h) = sha512_h { h.update(chunk); }
        if let Some(ref mut h) = blake3_h { h.update(chunk); }
        if let Some(ref mut h) = sha3_256_h { h.update(chunk); }
        if let Some(ref mut h) = keccak256_h { h.update(chunk); }
        if let Some(ref mut h) = sha1_h { Sha1Digest::update(h, chunk); }
    }

    // Finalize all hashers
    let mut results = Vec::with_capacity(axes.len());
    if let Some(h) = sha256_h {
        results.push(("sha256".to_string(), format!("sha256:{}", hex::encode(h.finalize()))));
    }
    if let Some(h) = sha512_h {
        results.push(("sha512".to_string(), format!("sha512:{}", hex::encode(h.finalize()))));
    }
    if let Some(h) = blake3_h {
        results.push(("blake3".to_string(), format!("blake3:{}", h.finalize().to_hex())));
    }
    if let Some(h) = sha3_256_h {
        results.push(("sha3-256".to_string(), format!("sha3-256:{}", hex::encode(h.finalize()))));
    }
    if let Some(h) = keccak256_h {
        results.push(("keccak256".to_string(), format!("keccak256:{}", hex::encode(h.finalize()))));
    }
    if let Some(h) = sha1_h {
        let result = h.try_finalize();
        if result.has_collision() {
            return Err(LabelError::CollisionDetected);
        }
        results.push(("sha1".to_string(), format!("sha1:{}", hex::encode(result.hash()))));
    }

    // Find the primary by matching the first input axis against results.
    // Results are built in hasher-check order (sha256 first), not input order.
    if results.is_empty() {
        return Err(LabelError::UnknownAxis);
    }
    let primary_axis = axes[0];
    let primary_idx = results.iter().position(|(a, _)| a == primary_axis)
        .unwrap_or(0);
    let (_, primary_kappa) = results.remove(primary_idx);
    Ok(crate::verified::StreamingVerificationProof::multi(primary_kappa, results))
}

/// Compute the raw SHA-256 hash of bytes, returning 32 bytes.
pub fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}
