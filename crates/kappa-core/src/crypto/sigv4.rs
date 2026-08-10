//! AWS Signature Version 4 server-side verification.
//!
//! Covers header auth, presigned URLs, streaming chunk signature chaining,
//! and trailer signature verification. Protocol-free: no HTTP types, no
//! async, no platform dependencies. WASM-portable.
//!
//! References:
//! - https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
//! - https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
//! - https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html
//! - s3s/crates/s3s/src/sig_v4/methods.rs (verified test vectors)

use hmac::{Hmac, Mac, KeyInit};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

// =============================================================================
// Constants -- derived from computation, not hardcoded
// =============================================================================

/// SHA-256 of empty string. Computed at first use and debug-asserted.
fn empty_sha256() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        let h = sha256_hex(b"");
        debug_assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        h
    })
}

const AWS4_REQUEST: &str = "aws4_request";
const ALGORITHM_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";
const ALGORITHM_CHUNK: &str = "AWS4-HMAC-SHA256-PAYLOAD";
const ALGORITHM_TRAILER: &str = "AWS4-HMAC-SHA256-TRAILER";

/// Well-known x-amz-content-sha256 values.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const STREAMING_UNSIGNED_PAYLOAD_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
pub const STREAMING_AWS4_HMAC_SHA256_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
pub const STREAMING_AWS4_HMAC_SHA256_PAYLOAD_TRAILER: &str =
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";

/// Maximum chunk data size (5 GiB -- S3 max object = 5 TiB, max part = 5 GiB).
pub const MAX_CHUNK_SIZE: usize = 5 * 1024 * 1024 * 1024;

/// Maximum number of chunks per request. S3 max parts = 10,000;
/// streaming chunks are analogous. Prevents infinite 1-byte chunk attack.
pub const MAX_CHUNK_COUNT: usize = 100_000;

/// Maximum trailer block size in bytes.
pub const MAX_TRAILER_BYTES: usize = 16 * 1024;

// =============================================================================
// Error types
// =============================================================================

#[derive(Debug, thiserror::Error)]
pub enum SigV4Error {
    #[error("missing authorization header")]
    MissingAuth,
    #[error("malformed authorization: {0}")]
    MalformedAuth(String),
    #[error("missing required header: {0}")]
    MissingHeader(String),
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("invalid access key")]
    InvalidAccessKey,
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("chunk parse failed: {0}")]
    ChunkParseFailed(String),
    #[error("presigned URL expired")]
    Expired,
    #[error("chunk count exceeded maximum ({0})")]
    ChunkCountExceeded(usize),
    #[error("chunk size {0} exceeds maximum {1}")]
    ChunkSizeExceeded(usize, usize),
    #[error("trailer block too large: {0} bytes (max {1})")]
    TrailerTooLarge(usize, usize),
}

// =============================================================================
// Credential lookup trait
// =============================================================================

/// Result of a credential lookup. Contains current and optionally
/// previous secret for rotation grace period support.
#[derive(Debug, Clone)]
pub struct CredentialResult {
    pub current_secret: String,
    pub previous_secret: Option<String>,
    pub principal_anchor: String,
}

/// Credential store abstraction. The S3 module implements this over the
/// redb credential table. kappa-core defines the trait; kappa-server wires it.
pub trait CredentialLookup: Send + Sync {
    /// Look up credentials for an access key ID.
    /// Returns current + previous secret (if within rotation grace period).
    /// Returns None if the access key is not found or deactivated.
    fn lookup_credential(&self, access_key_id: &str) -> Option<CredentialResult>;
}

// =============================================================================
// Parsed auth structures
// =============================================================================

/// Parsed Authorization header.
#[derive(Debug, Clone)]
pub struct SigV4Authorization {
    pub access_key: String,
    pub date: String,
    pub region: String,
    pub service: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
    pub security_token: Option<String>,
}

/// Parsed presigned URL parameters.
#[derive(Debug, Clone)]
pub struct PresignedUrl {
    pub access_key: String,
    pub date: String,
    pub region: String,
    pub service: String,
    pub datetime: String,
    pub expires_secs: u64,
    pub signed_headers: Vec<String>,
    pub signature: String,
    pub security_token: Option<String>,
}

/// Parsed chunk metadata from aws-chunked encoding.
#[derive(Debug)]
pub struct ChunkMeta {
    pub size: usize,
    pub signature: Option<String>,
}

// =============================================================================
// Authorization header parsing
// =============================================================================

pub fn parse_authorization(
    auth_header: &str,
    security_token: Option<&str>,
) -> Result<SigV4Authorization, SigV4Error> {
    let rest = auth_header
        .trim()
        .strip_prefix(ALGORITHM_HMAC_SHA256)
        .ok_or_else(|| SigV4Error::UnsupportedAlgorithm(auth_header.to_string()))?
        .trim();

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;

    for part in rest.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("Credential=") {
            credential = Some(val.trim());
        } else if let Some(val) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(val.trim());
        } else if let Some(val) = part.strip_prefix("Signature=") {
            signature = Some(val.trim());
        }
    }

    let cred_str = credential.ok_or_else(|| SigV4Error::MalformedAuth("missing Credential".into()))?;
    let sig = signature.ok_or_else(|| SigV4Error::MalformedAuth("missing Signature".into()))?;
    let sh = signed_headers.ok_or_else(|| SigV4Error::MalformedAuth("missing SignedHeaders".into()))?;

    let cred_parts: Vec<&str> = cred_str.splitn(5, '/').collect();
    if cred_parts.len() != 5 || cred_parts[4] != AWS4_REQUEST {
        return Err(SigV4Error::MalformedAuth(format!(
            "credential scope malformed: {}", cred_str
        )));
    }

    Ok(SigV4Authorization {
        access_key: cred_parts[0].to_string(),
        date: cred_parts[1].to_string(),
        region: cred_parts[2].to_string(),
        service: cred_parts[3].to_string(),
        signed_headers: sh.split(';').map(|s| s.to_string()).collect(),
        signature: sig.to_string(),
        security_token: security_token.map(|s| s.to_string()),
    })
}

// =============================================================================
// Signing key derivation
// =============================================================================

pub fn derive_signing_key(secret_key: &str, date: &str, region: &str, service: &str) -> Zeroizing<Vec<u8>> {
    let mut k_secret = Zeroizing::new(format!("AWS4{}", secret_key).into_bytes());
    let k_date = hmac_sha256(&k_secret, date.as_bytes());
    k_secret.fill(0);
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    Zeroizing::new(hmac_sha256(&k_service, AWS4_REQUEST.as_bytes()))
}

// =============================================================================
// Canonical request construction
// =============================================================================

pub fn build_canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    canonical_headers: &str,
    signed_headers: &str,
    payload_hash: &str,
) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_query, canonical_headers,
        signed_headers, payload_hash
    )
}

pub fn build_string_to_sign(
    datetime: &str,
    credential_scope: &str,
    canonical_request: &str,
) -> String {
    let hash = sha256_hex(canonical_request.as_bytes());
    format!("{}\n{}\n{}\n{}", ALGORITHM_HMAC_SHA256, datetime, credential_scope, hash)
}

pub fn compute_signature(signing_key: &[u8], string_to_sign: &str) -> String {
    hex::encode(hmac_sha256(signing_key, string_to_sign.as_bytes()))
}

pub fn build_canonical_headers(headers: &[(&str, &str)]) -> String {
    let mut result = String::new();
    for (name, value) in headers {
        result.push_str(&name.to_lowercase());
        result.push(':');
        result.push_str(value.trim());
        result.push('\n');
    }
    result
}

pub fn build_canonical_query(params: &[(&str, &str)]) -> String {
    let mut sorted: Vec<_> = params
        .iter()
        .filter(|(name, _)| *name != "X-Amz-Signature")
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    sorted
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

pub fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut result = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                result.push(byte as char);
            }
            b'/' if !encode_slash => result.push('/'),
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

// =============================================================================
// Signature verification (constant-time)
// =============================================================================

pub fn verify_signature(computed: &str, provided: &str) -> Result<(), SigV4Error> {
    use subtle::ConstantTimeEq;
    let a = computed.as_bytes();
    let b = provided.as_bytes();
    if a.len() != b.len() {
        return Err(SigV4Error::SignatureMismatch);
    }
    if a.ct_eq(b).into() {
        Ok(())
    } else {
        Err(SigV4Error::SignatureMismatch)
    }
}

// =============================================================================
// Streaming chunk signature chaining
// =============================================================================

pub fn create_chunk_string_to_sign(
    datetime: &str,
    date: &str,
    region: &str,
    service: &str,
    prev_signature: &str,
    chunk_data: &[u8],
) -> String {
    let chunk_hash = if chunk_data.is_empty() {
        empty_sha256().to_string()
    } else {
        sha256_hex(chunk_data)
    };
    format!(
        "{}\n{}\n{}/{}/{}/{}\n{}\n{}\n{}",
        ALGORITHM_CHUNK, datetime, date, region, service, AWS4_REQUEST,
        prev_signature, empty_sha256(), chunk_hash
    )
}

pub fn compute_chunk_signature(
    signing_key: &[u8],
    datetime: &str,
    date: &str,
    region: &str,
    service: &str,
    prev_signature: &str,
    chunk_data: &[u8],
) -> String {
    let sts = create_chunk_string_to_sign(datetime, date, region, service, prev_signature, chunk_data);
    compute_signature(signing_key, &sts)
}

pub fn verify_chunk_signature(
    signing_key: &[u8],
    datetime: &str,
    date: &str,
    region: &str,
    service: &str,
    prev_signature: &str,
    chunk_data: &[u8],
    claimed_signature: &str,
) -> Result<(), SigV4Error> {
    let computed = compute_chunk_signature(
        signing_key, datetime, date, region, service, prev_signature, chunk_data,
    );
    verify_signature(&computed, claimed_signature)
}

// =============================================================================
// Trailer signature
// =============================================================================

pub fn create_trailer_string_to_sign(
    datetime: &str,
    date: &str,
    region: &str,
    service: &str,
    prev_signature: &str,
    canonical_trailers: &[u8],
) -> String {
    let trailers_hash = sha256_hex(canonical_trailers);
    format!(
        "{}\n{}\n{}/{}/{}/{}\n{}\n{}",
        ALGORITHM_TRAILER, datetime, date, region, service, AWS4_REQUEST,
        prev_signature, trailers_hash
    )
}

pub fn compute_trailer_signature(
    signing_key: &[u8],
    datetime: &str,
    date: &str,
    region: &str,
    service: &str,
    prev_signature: &str,
    canonical_trailers: &[u8],
) -> String {
    let sts = create_trailer_string_to_sign(datetime, date, region, service, prev_signature, canonical_trailers);
    compute_signature(signing_key, &sts)
}

pub fn verify_trailer_signature(
    signing_key: &[u8],
    datetime: &str,
    date: &str,
    region: &str,
    service: &str,
    prev_signature: &str,
    canonical_trailers: &[u8],
    claimed_signature: &str,
) -> Result<(), SigV4Error> {
    let computed = compute_trailer_signature(
        signing_key, datetime, date, region, service, prev_signature, canonical_trailers,
    );
    verify_signature(&computed, claimed_signature)
}

// =============================================================================
// aws-chunked wire format parser
// =============================================================================

pub fn parse_chunk_meta(line: &[u8]) -> Result<ChunkMeta, SigV4Error> {
    let line = line.strip_suffix(b"\r\n")
        .ok_or_else(|| SigV4Error::ChunkParseFailed("missing CRLF".into()))?;

    let (size_part, sig_part) = match line.iter().position(|&b| b == b';') {
        Some(pos) => (&line[..pos], Some(&line[pos + 1..])),
        None => (line, None),
    };

    let size_str = std::str::from_utf8(size_part)
        .map_err(|_| SigV4Error::ChunkParseFailed("size not utf8".into()))?;
    let size = usize::from_str_radix(size_str, 16)
        .map_err(|e| SigV4Error::ChunkParseFailed(format!("invalid hex size '{}': {}", size_str, e)))?;

    if size > MAX_CHUNK_SIZE {
        return Err(SigV4Error::ChunkSizeExceeded(size, MAX_CHUNK_SIZE));
    }

    let signature = match sig_part {
        Some(ext) => {
            let ext_str = std::str::from_utf8(ext)
                .map_err(|_| SigV4Error::ChunkParseFailed("extension not utf8".into()))?;
            // Accept chunk-signature= prefix (future: chunk-signature-sha256= etc)
            let sig = if let Some(s) = ext_str.strip_prefix("chunk-signature=") {
                s
            } else if let Some(s) = ext_str.strip_prefix("chunk-signature-sha256=") {
                s
            } else {
                return Err(SigV4Error::ChunkParseFailed(format!(
                    "unknown chunk extension: {}", ext_str
                )));
            };
            if !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(SigV4Error::ChunkParseFailed("signature not hex".into()));
            }
            Some(sig.to_string())
        }
        None => None,
    };

    Ok(ChunkMeta { size, signature })
}

// =============================================================================
// Chunk stream parser -- stateful Read adapter
// =============================================================================

/// Stateful parser for aws-chunked transfer encoding.
///
/// Wraps a `Read` and yields verified plaintext chunks. Each chunk's
/// signature is verified against the chain before the data is returned.
/// Memory bounded: one chunk buffer at a time.
pub struct ChunkStreamParser<R: std::io::Read> {
    reader: R,
    signing_key: Zeroizing<Vec<u8>>,
    datetime: String,
    date: String,
    region: String,
    service: String,
    prev_signature: String,
    signed: bool,
    chunk_count: usize,
    finished: bool,
    line_buf: Vec<u8>,
}

impl<R: std::io::Read> ChunkStreamParser<R> {
    pub fn new(
        reader: R,
        signing_key: Zeroizing<Vec<u8>>,
        datetime: String,
        date: String,
        region: String,
        service: String,
        seed_signature: String,
        signed: bool,
    ) -> Self {
        Self {
            reader,
            signing_key,
            datetime,
            date,
            region,
            service,
            prev_signature: seed_signature,
            signed,
            chunk_count: 0,
            finished: false,
            line_buf: Vec::with_capacity(256),
        }
    }

    /// Read the next chunk. Returns Ok(Some(data)) for data chunks,
    /// Ok(None) when the final 0-size chunk is reached.
    /// Err on parse failure, signature mismatch, or limits exceeded.
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, SigV4Error> {
        if self.finished {
            return Ok(None);
        }

        self.chunk_count += 1;
        if self.chunk_count > MAX_CHUNK_COUNT {
            return Err(SigV4Error::ChunkCountExceeded(MAX_CHUNK_COUNT));
        }

        // Read meta line (up to \n)
        self.line_buf.clear();
        let mut byte = [0u8; 1];
        loop {
            match self.reader.read(&mut byte) {
                Ok(0) => {
                    self.finished = true;
                    if self.line_buf.is_empty() {
                        return Ok(None);
                    }
                    return Err(SigV4Error::ChunkParseFailed("unexpected EOF in chunk meta".into()));
                }
                Ok(_) => {
                    self.line_buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                    if self.line_buf.len() > 1024 {
                        return Err(SigV4Error::ChunkParseFailed("chunk meta line too long".into()));
                    }
                }
                Err(e) => return Err(SigV4Error::ChunkParseFailed(e.to_string())),
            }
        }

        let meta = parse_chunk_meta(&self.line_buf)?;

        if meta.size == 0 {
            self.finished = true;
            // Verify 0-chunk signature if signed
            if self.signed {
                let claimed = meta.signature
                    .ok_or_else(|| SigV4Error::ChunkParseFailed("signed mode requires chunk signature".into()))?;
                verify_chunk_signature(
                    &self.signing_key, &self.datetime, &self.date, &self.region,
                    &self.service, &self.prev_signature, &[], &claimed,
                )?;
                self.prev_signature = claimed;
            }
            return Ok(None);
        }

        // Read chunk data
        let mut data = vec![0u8; meta.size];
        self.reader.read_exact(&mut data)
            .map_err(|e| SigV4Error::ChunkParseFailed(format!("reading chunk data: {}", e)))?;

        // Read trailing \r\n after chunk data
        let mut crlf = [0u8; 2];
        self.reader.read_exact(&mut crlf)
            .map_err(|e| SigV4Error::ChunkParseFailed(format!("reading chunk CRLF: {}", e)))?;
        if crlf != *b"\r\n" {
            return Err(SigV4Error::ChunkParseFailed("missing CRLF after chunk data".into()));
        }

        // Verify chunk signature if signed
        if self.signed {
            let claimed = meta.signature
                .ok_or_else(|| SigV4Error::ChunkParseFailed("signed mode requires chunk signature".into()))?;
            verify_chunk_signature(
                &self.signing_key, &self.datetime, &self.date, &self.region,
                &self.service, &self.prev_signature, &data, &claimed,
            )?;
            self.prev_signature = claimed;
        }

        Ok(Some(data))
    }

    /// After next_chunk returns None, read and verify trailing headers.
    /// Returns the parsed headers as (name, value) pairs.
    /// Verifies trailer signature if present.
    pub fn read_trailers(&mut self) -> Result<Vec<(String, String)>, SigV4Error> {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match self.reader.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    buf.push(byte[0]);
                    if buf.len() > MAX_TRAILER_BYTES {
                        return Err(SigV4Error::TrailerTooLarge(buf.len(), MAX_TRAILER_BYTES));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(SigV4Error::ChunkParseFailed(e.to_string())),
            }
        }

        if buf.is_empty() || buf == b"\r\n" {
            return Ok(Vec::new());
        }

        // Parse header lines
        let mut entries = Vec::new();
        let mut trailer_signature = None;

        for line in buf.split(|&b| b == b'\n') {
            let line = if line.ends_with(b"\r") { &line[..line.len() - 1] } else { line };
            if line.is_empty() { continue; }

            let colon = line.iter().position(|&b| b == b':')
                .ok_or_else(|| SigV4Error::ChunkParseFailed("trailer header missing colon".into()))?;
            let name = std::str::from_utf8(&line[..colon])
                .map_err(|_| SigV4Error::ChunkParseFailed("trailer name not utf8".into()))?
                .to_ascii_lowercase();
            let value = std::str::from_utf8(&line[colon + 1..])
                .map_err(|_| SigV4Error::ChunkParseFailed("trailer value not utf8".into()))?
                .trim()
                .to_string();

            if name == "x-amz-trailer-signature" {
                trailer_signature = Some(value);
            } else {
                entries.push((name, value));
            }
        }

        // Verify trailer signature if present
        if let Some(claimed) = trailer_signature {
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut canonical = Vec::new();
            for (n, v) in &entries {
                canonical.extend_from_slice(n.as_bytes());
                canonical.push(b':');
                canonical.extend_from_slice(v.as_bytes());
                canonical.push(b'\n');
            }
            verify_trailer_signature(
                &self.signing_key, &self.datetime, &self.date, &self.region,
                &self.service, &self.prev_signature, &canonical, &claimed,
            )?;
        }

        Ok(entries)
    }

    /// The current chain signature (for the next step, e.g. trailer verification).
    pub fn prev_signature(&self) -> &str {
        &self.prev_signature
    }
}

// =============================================================================
// Presigned URL
// =============================================================================

pub fn parse_presigned_url(params: &[(&str, &str)]) -> Result<PresignedUrl, SigV4Error> {
    let mut algorithm = None;
    let mut credential = None;
    let mut date = None;
    let mut expires = None;
    let mut signed_headers = None;
    let mut signature = None;
    let mut security_token = None;

    for &(name, value) in params {
        match name {
            "X-Amz-Algorithm" => algorithm = Some(value),
            "X-Amz-Credential" => credential = Some(value),
            "X-Amz-Date" => date = Some(value),
            "X-Amz-Expires" => expires = Some(value),
            "X-Amz-SignedHeaders" => signed_headers = Some(value),
            "X-Amz-Signature" => signature = Some(value),
            "X-Amz-Security-Token" => security_token = Some(value),
            _ => {}
        }
    }

    let algo = algorithm.ok_or_else(|| SigV4Error::MissingHeader("X-Amz-Algorithm".into()))?;
    if algo != ALGORITHM_HMAC_SHA256 {
        return Err(SigV4Error::UnsupportedAlgorithm(algo.to_string()));
    }

    let cred = credential.ok_or_else(|| SigV4Error::MissingHeader("X-Amz-Credential".into()))?;
    let cred_parts: Vec<&str> = cred.splitn(5, '/').collect();
    if cred_parts.len() != 5 || cred_parts[4] != AWS4_REQUEST {
        return Err(SigV4Error::MalformedAuth(format!("presigned credential malformed: {}", cred)));
    }

    let datetime = date.ok_or_else(|| SigV4Error::MissingHeader("X-Amz-Date".into()))?;
    let exp_str = expires.ok_or_else(|| SigV4Error::MissingHeader("X-Amz-Expires".into()))?;
    let expires_secs: u64 = exp_str.parse()
        .map_err(|_| SigV4Error::MalformedAuth(format!("X-Amz-Expires not integer: {}", exp_str)))?;
    let sh = signed_headers.ok_or_else(|| SigV4Error::MissingHeader("X-Amz-SignedHeaders".into()))?;
    let sig = signature.ok_or_else(|| SigV4Error::MissingHeader("X-Amz-Signature".into()))?;

    Ok(PresignedUrl {
        access_key: cred_parts[0].to_string(),
        date: cred_parts[1].to_string(),
        region: cred_parts[2].to_string(),
        service: cred_parts[3].to_string(),
        datetime: datetime.to_string(),
        expires_secs,
        signed_headers: sh.split(';').map(|s| s.to_string()).collect(),
        signature: sig.to_string(),
        security_token: security_token.map(|s| s.to_string()),
    })
}

/// Check if a presigned URL has expired.
/// `now_secs` is current Unix epoch seconds (from Clock or test fixture).
/// `signing_datetime` is X-Amz-Date (e.g. "20130524T000000Z").
/// `expires_secs` is X-Amz-Expires value.
///
/// Uses `clock::parse_datetime_to_epoch_secs` -- the workspace SSOT for
/// datetime parsing. No hand-rolled calendar math.
pub fn check_presigned_expiration(
    signing_datetime: &str,
    expires_secs: u64,
    now_secs: u64,
) -> Result<(), SigV4Error> {
    let signing_epoch = crate::clock::parse_datetime_to_epoch_secs(signing_datetime)
        .map_err(|e| SigV4Error::MalformedAuth(e.to_string()))?;
    if now_secs > signing_epoch + expires_secs {
        return Err(SigV4Error::Expired);
    }
    Ok(())
}

pub fn build_presigned_canonical_request(
    method: &str,
    canonical_uri: &str,
    query_params: &[(&str, &str)],
    canonical_headers: &str,
    signed_headers: &str,
) -> String {
    let canonical_query = build_canonical_query(query_params);
    build_canonical_request(
        method, canonical_uri, &canonical_query,
        canonical_headers, signed_headers, UNSIGNED_PAYLOAD,
    )
}

// =============================================================================
// Internal helpers
// =============================================================================

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sha256_computed_correctly() {
        assert_eq!(
            empty_sha256(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn parse_authorization_valid() {
        let auth = "AWS4-HMAC-SHA256 \
            Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
            SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
            Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024";
        let parsed = parse_authorization(auth, None).unwrap();
        assert_eq!(parsed.access_key, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(parsed.date, "20130524");
        assert_eq!(parsed.region, "us-east-1");
        assert_eq!(parsed.service, "s3");
        assert_eq!(parsed.signed_headers.len(), 4);
        assert!(parsed.security_token.is_none());
    }

    #[test]
    fn parse_authorization_with_security_token() {
        let auth = "AWS4-HMAC-SHA256 \
            Credential=ASIA/20130524/us-east-1/s3/aws4_request, \
            SignedHeaders=host, Signature=abc123";
        let parsed = parse_authorization(auth, Some("my-session-token")).unwrap();
        assert_eq!(parsed.security_token.as_deref(), Some("my-session-token"));
    }

    #[test]
    fn derive_signing_key_produces_32_bytes() {
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20130524", "us-east-1", "s3",
        );
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn chunk_string_to_sign_matches_aws_example() {
        // From s3s test: example_put_object_multiple_chunks_chunk_signature
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let chunk1_data = vec![b'a'; 64 * 1024];

        let sts = create_chunk_string_to_sign(
            "20130524T000000Z", "20130524", "us-east-1", "s3", seed, &chunk1_data,
        );
        assert!(sts.starts_with("AWS4-HMAC-SHA256-PAYLOAD\n"));
        assert!(sts.contains(seed));
        assert!(sts.contains(empty_sha256()));
        // chunk hash of 64KB of 'a'
        assert!(sts.contains("bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a"));
    }

    #[test]
    fn chunk_signature_chain_matches_aws_example() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let key = derive_signing_key(secret, "20130524", "us-east-1", "s3");
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";

        let sig1 = compute_chunk_signature(
            &key, "20130524T000000Z", "20130524", "us-east-1", "s3",
            seed, &vec![b'a'; 64 * 1024],
        );
        assert_eq!(sig1, "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648");

        let sig2 = compute_chunk_signature(
            &key, "20130524T000000Z", "20130524", "us-east-1", "s3",
            &sig1, &vec![b'a'; 1024],
        );
        assert_eq!(sig2, "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497");

        let sig3 = compute_chunk_signature(
            &key, "20130524T000000Z", "20130524", "us-east-1", "s3",
            &sig2, &[],
        );
        assert_eq!(sig3, "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9");
    }

    #[test]
    fn trailer_signature_matches_aws_example() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let key = derive_signing_key(secret, "20130524", "us-east-1", "s3");
        let prev_sig = "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992";
        let canonical_trailers = b"x-amz-checksum-crc32c:sOO8/Q==\n";

        let sig = compute_trailer_signature(
            &key, "20130524T000000Z", "20130524", "us-east-1", "s3",
            prev_sig, canonical_trailers,
        );
        assert_eq!(sig, "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435");
    }

    #[test]
    fn verify_chunk_signature_succeeds() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let key = derive_signing_key(secret, "20130524", "us-east-1", "s3");
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let data = vec![b'a'; 64 * 1024];
        let expected = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648";

        assert!(verify_chunk_signature(
            &key, "20130524T000000Z", "20130524", "us-east-1", "s3",
            seed, &data, expected,
        ).is_ok());
    }

    #[test]
    fn verify_chunk_signature_rejects_wrong() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let key = derive_signing_key(secret, "20130524", "us-east-1", "s3");
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";

        assert!(verify_chunk_signature(
            &key, "20130524T000000Z", "20130524", "us-east-1", "s3",
            seed, &[b'a'; 64 * 1024],
            "0000000000000000000000000000000000000000000000000000000000000000",
        ).is_err());
    }

    #[test]
    fn parse_chunk_meta_signed() {
        let line = b"10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n";
        let meta = parse_chunk_meta(line).unwrap();
        assert_eq!(meta.size, 0x10000);
        assert_eq!(
            meta.signature.as_deref(),
            Some("ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648")
        );
    }

    #[test]
    fn parse_chunk_meta_unsigned() {
        let line = b"400\r\n";
        let meta = parse_chunk_meta(line).unwrap();
        assert_eq!(meta.size, 0x400);
        assert!(meta.signature.is_none());
    }

    #[test]
    fn parse_chunk_meta_zero() {
        let line = b"0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n";
        let meta = parse_chunk_meta(line).unwrap();
        assert_eq!(meta.size, 0);
        assert!(meta.signature.is_some());
    }

    #[test]
    fn parse_chunk_meta_missing_crlf() {
        assert!(parse_chunk_meta(b"10000").is_err());
    }

    #[test]
    fn parse_chunk_meta_invalid_hex() {
        assert!(parse_chunk_meta(b"ZZZZ\r\n").is_err());
    }

    #[test]
    fn parse_presigned_url_valid() {
        let params = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"),
            ("X-Amz-Date", "20130524T000000Z"),
            ("X-Amz-Expires", "86400"),
            ("X-Amz-SignedHeaders", "host"),
            ("X-Amz-Signature", "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"),
        ];
        let parsed = parse_presigned_url(&params).unwrap();
        assert_eq!(parsed.access_key, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(parsed.expires_secs, 86400);
        assert!(parsed.security_token.is_none());
    }

    #[test]
    fn parse_presigned_url_with_token() {
        let params = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", "ASIA/20130524/us-east-1/s3/aws4_request"),
            ("X-Amz-Date", "20130524T000000Z"),
            ("X-Amz-Expires", "3600"),
            ("X-Amz-SignedHeaders", "host"),
            ("X-Amz-Signature", "abc"),
            ("X-Amz-Security-Token", "session-token-123"),
        ];
        let parsed = parse_presigned_url(&params).unwrap();
        assert_eq!(parsed.security_token.as_deref(), Some("session-token-123"));
    }

    #[test]
    fn presigned_url_expiration_check() {
        // Signing time: 2013-05-24 00:00:00Z, expires in 86400 seconds (1 day)
        // At 2013-05-25 00:00:01Z it should be expired
        let signing_dt = "20130524T000000Z";
        // 2013-05-24 00:00:00 UTC = 1369353600
        let signing_epoch = 1369353600u64;

        // Within expiry window
        assert!(check_presigned_expiration(signing_dt, 86400, signing_epoch + 1000).is_ok());

        // At exact expiry boundary
        assert!(check_presigned_expiration(signing_dt, 86400, signing_epoch + 86400).is_ok());

        // Past expiry
        assert!(check_presigned_expiration(signing_dt, 86400, signing_epoch + 86401).is_err());
    }

    #[test]
    fn chunk_stream_parser_signed() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let key = derive_signing_key(secret, "20130524", "us-east-1", "s3");
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";

        // Build a signed chunked body: 5 bytes + 0-chunk
        let chunk_data = b"hello";
        let sig1 = compute_chunk_signature(
            &key, "20130524T000000Z", "20130524", "us-east-1", "s3",
            seed, chunk_data,
        );
        let sig_final = compute_chunk_signature(
            &key, "20130524T000000Z", "20130524", "us-east-1", "s3",
            &sig1, &[],
        );

        let mut body = Vec::new();
        body.extend_from_slice(format!("5;chunk-signature={}\r\n", sig1).as_bytes());
        body.extend_from_slice(chunk_data);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("0;chunk-signature={}\r\n", sig_final).as_bytes());

        let mut parser = ChunkStreamParser::new(
            std::io::Cursor::new(body),
            key, "20130524T000000Z".into(), "20130524".into(),
            "us-east-1".into(), "s3".into(), seed.into(), true,
        );

        let chunk = parser.next_chunk().unwrap().unwrap();
        assert_eq!(chunk, b"hello");

        let end = parser.next_chunk().unwrap();
        assert!(end.is_none());
    }

    #[test]
    fn chunk_stream_parser_unsigned() {
        let mut body = Vec::new();
        body.extend_from_slice(b"3\r\n");
        body.extend_from_slice(b"abc");
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(b"0\r\n");

        let mut parser = ChunkStreamParser::new(
            std::io::Cursor::new(body),
            Zeroizing::new(Vec::new()), String::new(), String::new(),
            String::new(), String::new(), String::new(), false,
        );

        let chunk = parser.next_chunk().unwrap().unwrap();
        assert_eq!(chunk, b"abc");

        assert!(parser.next_chunk().unwrap().is_none());
    }

    #[test]
    fn chunk_stream_parser_wrong_signature_rejected() {
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "20130524", "us-east-1", "s3",
        );
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let bad_sig = "0".repeat(64);

        let mut body = Vec::new();
        body.extend_from_slice(format!("5;chunk-signature={}\r\n", bad_sig).as_bytes());
        body.extend_from_slice(b"hello\r\n");

        let mut parser = ChunkStreamParser::new(
            std::io::Cursor::new(body),
            key, "20130524T000000Z".into(), "20130524".into(),
            "us-east-1".into(), "s3".into(), seed.into(), true,
        );

        assert!(parser.next_chunk().is_err());
    }

    #[test]
    fn uri_encode_unreserved_passthrough() {
        assert_eq!(uri_encode("ABCabc123-._~", true), "ABCabc123-._~");
    }

    #[test]
    fn uri_encode_encodes_special() {
        assert_eq!(uri_encode("hello world", true), "hello%20world");
        assert_eq!(uri_encode("/path/to", true), "%2Fpath%2Fto");
        assert_eq!(uri_encode("/path/to", false), "/path/to");
    }

    #[test]
    fn end_to_end_header_auth() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let key = derive_signing_key(secret, "20130524", "us-east-1", "s3");
        let payload_hash = sha256_hex(b"");
        let canonical_headers = build_canonical_headers(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", &payload_hash),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let cr = build_canonical_request("GET", "/test.txt", "", &canonical_headers, signed_headers, &payload_hash);
        let scope = "20130524/us-east-1/s3/aws4_request";
        let sts = build_string_to_sign("20130524T000000Z", scope, &cr);
        let sig = compute_signature(&key, &sts);

        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(verify_signature(&sig, &sig).is_ok());

        let mut bad = sig.clone();
        bad.replace_range(0..1, if &sig[0..1] == "0" { "1" } else { "0" });
        assert!(verify_signature(&sig, &bad).is_err());
    }
}
