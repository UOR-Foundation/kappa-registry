use std::str;
use std::sync::OnceLock;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use kappa_types::kappa::Kappa;

#[path = "sigv4_presigned.rs"]
mod presigned;
pub use presigned::{build_presigned_canonical_request, check_presigned_expiration};

type HmacSha256 = Hmac<Sha256>;

fn empty_sha256() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| sha256_hex(b""))
}

const AWS4_REQUEST: &str = "aws4_request";
const ALGORITHM_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";
const ALGORITHM_CHUNK: &str = "AWS4-HMAC-SHA256-PAYLOAD";
const ALGORITHM_TRAILER: &str = "AWS4-HMAC-SHA256-TRAILER";

pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const STREAMING_AWS4_HMAC_SHA256_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
pub const STREAMING_UNSIGNED_PAYLOAD_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
pub const STREAMING_AWS4_HMAC_SHA256_PAYLOAD_TRAILER: &str =
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
pub const MAX_CHUNK_SIZE: usize = 5 * 1024 * 1024 * 1024;
pub const MAX_CHUNK_COUNT: usize = 100_000;
pub const MAX_TRAILER_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SigV4Error {
    #[error("missing authorization header")]
    MissingAuth,

    #[error("malformed authorization: {field}: {reason}")]
    MalformedAuth { field: String, reason: String },

    #[error("missing required header: {header}")]
    MissingHeader { header: String },

    #[error("signature mismatch")]
    SignatureMismatch,

    #[error("invalid access key: {access_key}")]
    InvalidAccessKey { access_key: String },

    #[error("unsupported algorithm: {algorithm}")]
    UnsupportedAlgorithm { algorithm: String },

    #[error("chunk parse failed: {reason}")]
    ChunkParseFailed { reason: String },

    #[error("presigned URL expired")]
    Expired,

    #[error("chunk count exceeded maximum ({count})")]
    ChunkCountExceeded { count: usize },

    #[error("chunk size {size} exceeds maximum {max}")]
    ChunkSizeExceeded { size: usize, max: usize },

    #[error("trailer block too large: {size} bytes (max {max})")]
    TrailerTooLarge { size: usize, max: usize },
}

#[derive(Clone)]
pub struct CredentialResult {
    pub current_secret: Zeroizing<String>,
    pub previous_secret: Option<Zeroizing<String>>,
    pub principal_anchor: Kappa,
}

impl std::fmt::Debug for CredentialResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialResult")
            .field("current_secret", &"[REDACTED]")
            .field(
                "previous_secret",
                &self.previous_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("principal_anchor", &self.principal_anchor)
            .finish()
    }
}

pub trait CredentialLookup: Send + Sync {
    fn lookup_credential(
        &self,
        access_key_id: &str,
        now: kappa_types::clock::ClockMs,
    ) -> Option<CredentialResult>;
}

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

#[derive(Debug)]
pub struct ChunkMeta {
    pub size: usize,
    pub signature: Option<String>,
}

pub fn parse_authorization(
    auth_header: &str,
    security_token: Option<&str>,
) -> Result<SigV4Authorization, SigV4Error> {
    let rest = auth_header
        .trim()
        .strip_prefix(ALGORITHM_HMAC_SHA256)
        .ok_or_else(|| SigV4Error::UnsupportedAlgorithm {
            algorithm: auth_header.to_string(),
        })?
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

    let cred_str = credential.ok_or(SigV4Error::MalformedAuth {
        field: "Credential".into(),
        reason: "missing from authorization header".into(),
    })?;
    let sig = signature.ok_or(SigV4Error::MalformedAuth {
        field: "Signature".into(),
        reason: "missing from authorization header".into(),
    })?;
    let sh = signed_headers.ok_or(SigV4Error::MalformedAuth {
        field: "SignedHeaders".into(),
        reason: "missing from authorization header".into(),
    })?;

    let cred_parts: Vec<&str> = cred_str.splitn(5, '/').collect();
    if cred_parts.len() != 5 || cred_parts[4] != AWS4_REQUEST {
        return Err(SigV4Error::MalformedAuth {
            field: "Credential".into(),
            reason: format!("scope malformed: {}", cred_str),
        });
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

pub fn derive_signing_key(
    secret_key: &str,
    date: &str,
    region: &str,
    service: &str,
) -> Zeroizing<Vec<u8>> {
    let mut k_secret = Zeroizing::new(format!("AWS4{}", secret_key).into_bytes());
    let k_date = hmac_sha256(&k_secret, date.as_bytes());
    k_secret.fill(0);
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    Zeroizing::new(hmac_sha256(&k_service, AWS4_REQUEST.as_bytes()))
}

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
        method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash,
    )
}

pub fn build_string_to_sign(
    datetime: &str,
    credential_scope: &str,
    canonical_request: &str,
) -> String {
    let hash = sha256_hex(canonical_request.as_bytes());
    format!(
        "{}\n{}\n{}\n{}",
        ALGORITHM_HMAC_SHA256, datetime, credential_scope, hash
    )
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

pub fn verify_signature(computed: &str, provided: &str) -> Result<(), SigV4Error> {
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

pub fn compute_chunk_signature(
    signing_key: &[u8],
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
    let sts = format!(
        "{}\n{}\n{}/{}/{}/{}\n{}\n{}\n{}",
        ALGORITHM_CHUNK,
        datetime,
        date,
        region,
        service,
        AWS4_REQUEST,
        prev_signature,
        empty_sha256(),
        chunk_hash,
    );
    compute_signature(signing_key, &sts)
}

pub struct SigningScope<'a> {
    pub datetime: &'a str,
    pub date: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

pub fn verify_chunk_signature(
    signing_key: &[u8],
    scope: &SigningScope<'_>,
    prev_signature: &str,
    chunk_data: &[u8],
    claimed: &str,
) -> Result<(), SigV4Error> {
    let computed = compute_chunk_signature(
        signing_key,
        scope.datetime,
        scope.date,
        scope.region,
        scope.service,
        prev_signature,
        chunk_data,
    );
    verify_signature(&computed, claimed)
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
    let trailers_hash = sha256_hex(canonical_trailers);
    let sts = format!(
        "{}\n{}\n{}/{}/{}/{}\n{}\n{}",
        ALGORITHM_TRAILER,
        datetime,
        date,
        region,
        service,
        AWS4_REQUEST,
        prev_signature,
        trailers_hash,
    );
    compute_signature(signing_key, &sts)
}

pub fn verify_trailer_signature(
    signing_key: &[u8],
    scope: &SigningScope<'_>,
    prev_signature: &str,
    canonical_trailers: &[u8],
    claimed: &str,
) -> Result<(), SigV4Error> {
    let computed = compute_trailer_signature(
        signing_key,
        scope.datetime,
        scope.date,
        scope.region,
        scope.service,
        prev_signature,
        canonical_trailers,
    );
    verify_signature(&computed, claimed)
}

pub fn parse_chunk_meta(line: &[u8]) -> Result<ChunkMeta, SigV4Error> {
    let line = line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| SigV4Error::ChunkParseFailed {
            reason: "missing CRLF".into(),
        })?;
    let (size_part, sig_part) = match line.iter().position(|&b| b == b';') {
        Some(pos) => (&line[..pos], Some(&line[pos + 1..])),
        None => (line, None),
    };
    let size_str = str::from_utf8(size_part).map_err(|_| SigV4Error::ChunkParseFailed {
        reason: "size not utf8".into(),
    })?;
    let size = usize::from_str_radix(size_str, 16).map_err(|e| SigV4Error::ChunkParseFailed {
        reason: format!("invalid hex size '{}': {}", size_str, e),
    })?;
    if size > MAX_CHUNK_SIZE {
        return Err(SigV4Error::ChunkSizeExceeded {
            size,
            max: MAX_CHUNK_SIZE,
        });
    }

    let signature = match sig_part {
        Some(ext) => {
            let ext_str = str::from_utf8(ext).map_err(|_| SigV4Error::ChunkParseFailed {
                reason: "extension not utf8".into(),
            })?;
            let sig = ext_str
                .strip_prefix("chunk-signature=")
                .or_else(|| ext_str.strip_prefix("chunk-signature-sha256="))
                .ok_or_else(|| SigV4Error::ChunkParseFailed {
                    reason: format!("unknown chunk extension: {}", ext_str),
                })?;
            if !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(SigV4Error::ChunkParseFailed {
                    reason: "signature not hex".into(),
                });
            }
            Some(sig.to_string())
        }
        None => None,
    };
    Ok(ChunkMeta { size, signature })
}

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

    let algo = algorithm.ok_or_else(|| SigV4Error::MissingHeader {
        header: "X-Amz-Algorithm".into(),
    })?;
    if algo != ALGORITHM_HMAC_SHA256 {
        return Err(SigV4Error::UnsupportedAlgorithm {
            algorithm: algo.to_string(),
        });
    }
    let cred = credential.ok_or_else(|| SigV4Error::MissingHeader {
        header: "X-Amz-Credential".into(),
    })?;
    let cred_parts: Vec<&str> = cred.splitn(5, '/').collect();
    if cred_parts.len() != 5 || cred_parts[4] != AWS4_REQUEST {
        return Err(SigV4Error::MalformedAuth {
            field: "X-Amz-Credential".into(),
            reason: format!("presigned scope malformed: {}", cred),
        });
    }
    let datetime = date.ok_or_else(|| SigV4Error::MissingHeader {
        header: "X-Amz-Date".into(),
    })?;
    let exp_str = expires.ok_or_else(|| SigV4Error::MissingHeader {
        header: "X-Amz-Expires".into(),
    })?;
    let expires_secs: u64 = exp_str.parse().map_err(|_| SigV4Error::MalformedAuth {
        field: "X-Amz-Expires".into(),
        reason: format!("not an integer: {}", exp_str),
    })?;
    let sh = signed_headers.ok_or_else(|| SigV4Error::MissingHeader {
        header: "X-Amz-SignedHeaders".into(),
    })?;
    let sig = signature.ok_or_else(|| SigV4Error::MissingHeader {
        header: "X-Amz-Signature".into(),
    })?;

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

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC-SHA256 accepts any key length per RFC 2104 section 2.
    // Keys shorter than the block size are zero-padded. Keys longer
    // are hashed first. There is no invalid key length.
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length per RFC 2104");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Parser lifecycle state. Transitions are one-directional: once
/// `Failed`, every subsequent operation returns the stored error.
#[derive(Debug)]
enum ChunkStreamState {
    /// Accepting data chunks. Initial state.
    Reading,
    /// Zero-size terminal chunk received and verified. Trailers may
    /// be read in this state.
    Terminal,
    /// Trailers processed (or skipped). No further operations.
    Complete,
    /// An error occurred. Sticky: every subsequent call returns this.
    Failed(String),
}

/// Stateful parser for aws-chunked transfer encoding with explicit
/// lifecycle states and authenticated finality.
///
/// State machine: `Reading -> Terminal -> Complete`. Any error
/// transitions to `Failed` permanently. `next_chunk` is valid only
/// in `Reading`. `read_trailers` is valid only in `Terminal`.
/// Premature EOF without a terminal chunk is an error.
pub struct ChunkStreamParser<R: std::io::Read> {
    reader: R,
    signing_key: Zeroizing<Vec<u8>>,
    datetime: String,
    date: String,
    region: String,
    service: String,
    prev_signature: String,
    signed: bool,
    require_trailer_signature: bool,
    chunk_count: usize,
    state: ChunkStreamState,
    line_buf: Vec<u8>,
}

impl<R: std::io::Read> ChunkStreamParser<R> {
    #[allow(clippy::too_many_arguments)]
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
        let require_trailer_signature = false;
        Self {
            reader,
            signing_key,
            datetime,
            date,
            region,
            service,
            prev_signature: seed_signature,
            signed,
            require_trailer_signature,
            chunk_count: 0,
            state: ChunkStreamState::Reading,
            line_buf: Vec::with_capacity(256),
        }
    }

    /// Enable required trailer signature verification. When set,
    /// `read_trailers` fails if no `x-amz-trailer-signature` is present.
    pub fn require_trailer_signature(&mut self) {
        self.require_trailer_signature = true;
    }

    /// Transition to failed state and return the error.
    fn fail(&mut self, reason: String) -> SigV4Error {
        self.state = ChunkStreamState::Failed(reason.clone());
        SigV4Error::ChunkParseFailed { reason }
    }

    fn scope(&self) -> SigningScope<'_> {
        SigningScope {
            datetime: &self.datetime,
            date: &self.date,
            region: &self.region,
            service: &self.service,
        }
    }

    /// Read the next chunk. Returns `Ok(Some(data))` for data chunks,
    /// `Ok(None)` when the verified terminal chunk completes payload
    /// reading. Only valid in `Reading` state.
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, SigV4Error> {
        match &self.state {
            ChunkStreamState::Failed(reason) => {
                return Err(SigV4Error::ChunkParseFailed {
                    reason: reason.clone(),
                });
            }
            ChunkStreamState::Terminal | ChunkStreamState::Complete => return Ok(None),
            ChunkStreamState::Reading => {}
        }
        self.chunk_count += 1;
        if self.chunk_count > MAX_CHUNK_COUNT {
            return Err(self.fail(format!("chunk count exceeded maximum ({MAX_CHUNK_COUNT})")));
        }
        self.line_buf.clear();
        let mut byte = [0u8; 1];
        loop {
            match self.reader.read(&mut byte) {
                Ok(0) => {
                    // EOF without terminal chunk is always an error.
                    return Err(self.fail(
                        "unexpected EOF: stream ended without terminal zero-size chunk".into(),
                    ));
                }
                Ok(_) => {
                    self.line_buf.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                    if self.line_buf.len() > 1024 {
                        return Err(self.fail("chunk meta line too long".into()));
                    }
                }
                Err(e) => return Err(self.fail(e.to_string())),
            }
        }
        let meta = match parse_chunk_meta(&self.line_buf) {
            Ok(m) => m,
            Err(e) => {
                self.state = ChunkStreamState::Failed(e.to_string());
                return Err(e);
            }
        };
        if meta.size == 0 {
            // Terminal chunk. Verify signature before transitioning.
            if self.signed {
                let claimed = match meta.signature {
                    Some(s) => s,
                    None => {
                        return Err(
                            self.fail("signed mode requires chunk signature on terminal".into())
                        );
                    }
                };
                if let Err(e) = verify_chunk_signature(
                    &self.signing_key,
                    &self.scope(),
                    &self.prev_signature,
                    &[],
                    &claimed,
                ) {
                    self.state = ChunkStreamState::Failed(e.to_string());
                    return Err(e);
                }
                self.prev_signature = claimed;
            }
            self.state = ChunkStreamState::Terminal;
            return Ok(None);
        }
        let mut data = vec![0u8; meta.size];
        if let Err(e) = self.reader.read_exact(&mut data) {
            return Err(self.fail(format!("reading chunk data: {e}")));
        }
        let mut crlf = [0u8; 2];
        if let Err(e) = self.reader.read_exact(&mut crlf) {
            return Err(self.fail(format!("reading chunk CRLF: {e}")));
        }
        if crlf != *b"\r\n" {
            return Err(self.fail("missing CRLF after chunk data".into()));
        }
        if self.signed {
            let claimed = match meta.signature {
                Some(s) => s,
                None => return Err(self.fail("signed mode requires chunk signature".into())),
            };
            if let Err(e) = verify_chunk_signature(
                &self.signing_key,
                &self.scope(),
                &self.prev_signature,
                &data,
                &claimed,
            ) {
                self.state = ChunkStreamState::Failed(e.to_string());
                return Err(e);
            }
            self.prev_signature = claimed;
        }
        Ok(Some(data))
    }

    /// Read and verify trailing headers. Only valid after `next_chunk`
    /// returned `Ok(None)` (terminal state). Transitions to `Complete`.
    pub fn read_trailers(&mut self) -> Result<Vec<(String, String)>, SigV4Error> {
        match &self.state {
            ChunkStreamState::Failed(reason) => {
                return Err(SigV4Error::ChunkParseFailed {
                    reason: reason.clone(),
                });
            }
            ChunkStreamState::Reading => {
                return Err(
                    self.fail("read_trailers called before terminal chunk was received".into())
                );
            }
            ChunkStreamState::Complete => {
                return Err(self.fail("read_trailers already called".into()));
            }
            ChunkStreamState::Terminal => {}
        }
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match self.reader.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    buf.push(byte[0]);
                    if buf.len() > MAX_TRAILER_BYTES {
                        return Err(self.fail(format!(
                            "trailer block too large: {} bytes (max {MAX_TRAILER_BYTES})",
                            buf.len()
                        )));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(self.fail(e.to_string())),
            }
        }
        if buf.is_empty() || buf == b"\r\n" {
            if self.require_trailer_signature {
                return Err(self.fail("required trailer signature not present".into()));
            }
            self.state = ChunkStreamState::Complete;
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        let mut trailer_signature = None;
        for line in buf.split(|&b| b == b'\n') {
            let line = if line.ends_with(b"\r") {
                &line[..line.len() - 1]
            } else {
                line
            };
            if line.is_empty() {
                continue;
            }
            let colon = line
                .iter()
                .position(|&b| b == b':')
                .ok_or_else(|| self.fail("trailer header missing colon".into()))?;
            let name = str::from_utf8(&line[..colon])
                .map_err(|_| self.fail("trailer name not utf8".into()))?
                .to_ascii_lowercase();
            let value = str::from_utf8(&line[colon + 1..])
                .map_err(|_| self.fail("trailer value not utf8".into()))?
                .trim()
                .to_string();
            if name == "x-amz-trailer-signature" {
                trailer_signature = Some(value);
            } else {
                entries.push((name, value));
            }
        }
        if let Some(claimed) = trailer_signature {
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut canonical = Vec::new();
            for (n, v) in &entries {
                canonical.extend_from_slice(n.as_bytes());
                canonical.push(b':');
                canonical.extend_from_slice(v.as_bytes());
                canonical.push(b'\n');
            }
            if let Err(e) = verify_trailer_signature(
                &self.signing_key,
                &self.scope(),
                &self.prev_signature,
                &canonical,
                &claimed,
            ) {
                self.state = ChunkStreamState::Failed(e.to_string());
                return Err(e);
            }
        } else if self.require_trailer_signature {
            return Err(self.fail("required trailer signature not present".into()));
        }
        self.state = ChunkStreamState::Complete;
        Ok(entries)
    }

    /// Whether the parser completed successfully (terminal chunk
    /// verified and trailers processed).
    pub fn is_complete(&self) -> bool {
        matches!(self.state, ChunkStreamState::Complete)
    }

    /// Whether the parser is in a failed state.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, ChunkStreamState::Failed(_))
    }

    /// The current chain signature.
    pub fn prev_signature(&self) -> &str {
        &self.prev_signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_empty() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn sha256_hex_hello() {
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        );
    }

    #[test]
    fn derive_signing_key_produces_32_bytes() {
        let key = derive_signing_key("secret", "20260101", "us-east-1", "s3");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_signing_key_is_deterministic() {
        let a = derive_signing_key("secret", "20260101", "us-east-1", "s3");
        let b = derive_signing_key("secret", "20260101", "us-east-1", "s3");
        assert_eq!(*a, *b);
    }

    #[test]
    fn derive_signing_key_differs_by_date() {
        let a = derive_signing_key("secret", "20260101", "us-east-1", "s3");
        let b = derive_signing_key("secret", "20260102", "us-east-1", "s3");
        assert_ne!(*a, *b);
    }

    #[test]
    fn verify_signature_constant_time_accepts_match() {
        verify_signature("abcdef", "abcdef").expect("must accept matching signatures");
    }

    #[test]
    fn verify_signature_constant_time_rejects_mismatch() {
        let result = verify_signature("abcdef", "ghijkl");
        assert!(matches!(result, Err(SigV4Error::SignatureMismatch)));
    }

    #[test]
    fn verify_signature_rejects_different_lengths() {
        let result = verify_signature("abc", "abcdef");
        assert!(matches!(result, Err(SigV4Error::SignatureMismatch)));
    }

    #[test]
    fn parse_authorization_header() {
        let header = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef1234";
        let auth = parse_authorization(header, None).expect("parse");
        assert_eq!(auth.access_key, "AKID");
        assert_eq!(auth.date, "20260101");
        assert_eq!(auth.region, "us-east-1");
        assert_eq!(auth.service, "s3");
        assert_eq!(auth.signed_headers, vec!["host", "x-amz-date"]);
        assert_eq!(auth.signature, "abcdef1234");
        assert!(auth.security_token.is_none());
    }

    #[test]
    fn parse_authorization_with_security_token() {
        let header = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc";
        let auth = parse_authorization(header, Some("session-token")).expect("parse");
        assert_eq!(auth.security_token.as_deref(), Some("session-token"));
    }

    #[test]
    fn parse_authorization_rejects_unknown_algorithm() {
        let result = parse_authorization("AWS4-RSA-SHA256 Credential=...", None);
        assert!(matches!(
            result,
            Err(SigV4Error::UnsupportedAlgorithm { .. })
        ));
    }

    #[test]
    fn uri_encode_unreserved_passthrough() {
        assert_eq!(uri_encode("abc-._~123", true), "abc-._~123");
    }

    #[test]
    fn uri_encode_special_chars() {
        assert_eq!(uri_encode("a b", true), "a%20b");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("a/b", false), "a/b");
    }

    #[test]
    fn build_canonical_headers_sorted() {
        let headers = vec![("host", "example.com"), ("x-amz-date", "20260101T000000Z")];
        let result = build_canonical_headers(&headers);
        assert_eq!(result, "host:example.com\nx-amz-date:20260101T000000Z\n");
    }

    #[test]
    fn parse_chunk_meta_with_signature() {
        let line = b"400;chunk-signature=abcdef1234\r\n";
        let meta = parse_chunk_meta(line).expect("parse");
        assert_eq!(meta.size, 0x400);
        assert_eq!(meta.signature.as_deref(), Some("abcdef1234"));
    }

    #[test]
    fn parse_chunk_meta_without_signature() {
        let line = b"0\r\n";
        let meta = parse_chunk_meta(line).expect("parse");
        assert_eq!(meta.size, 0);
        assert!(meta.signature.is_none());
    }

    #[test]
    fn parse_chunk_meta_rejects_oversized() {
        let line = format!("{:x}\r\n", MAX_CHUNK_SIZE + 1);
        let result = parse_chunk_meta(line.as_bytes());
        assert!(matches!(result, Err(SigV4Error::ChunkSizeExceeded { .. })));
    }

    #[test]
    fn chunk_signature_chain() {
        let key = derive_signing_key("secret", "20260101", "us-east-1", "s3");
        let seed_sig = "seed0000";
        let chunk1_sig = compute_chunk_signature(
            &key,
            "20260101T000000Z",
            "20260101",
            "us-east-1",
            "s3",
            seed_sig,
            b"chunk1data",
        );
        let chunk2_sig = compute_chunk_signature(
            &key,
            "20260101T000000Z",
            "20260101",
            "us-east-1",
            "s3",
            &chunk1_sig,
            b"chunk2data",
        );
        let chunk2_again = compute_chunk_signature(
            &key,
            "20260101T000000Z",
            "20260101",
            "us-east-1",
            "s3",
            &chunk1_sig,
            b"chunk2data",
        );
        assert_eq!(chunk2_sig, chunk2_again);
        let chunk2_tampered = compute_chunk_signature(
            &key,
            "20260101T000000Z",
            "20260101",
            "us-east-1",
            "s3",
            &chunk1_sig,
            b"TAMPERED",
        );
        assert_ne!(chunk2_sig, chunk2_tampered);
    }

    #[test]
    fn trailer_signature_verification() -> Result<(), SigV4Error> {
        let key = derive_signing_key("secret", "20260101", "us-east-1", "s3");
        let prev_sig = "prev0000";
        let trailers = b"x-amz-checksum-sha256:abcdef\n";
        let sig = compute_trailer_signature(
            &key,
            "20260101T000000Z",
            "20260101",
            "us-east-1",
            "s3",
            prev_sig,
            trailers,
        );
        verify_trailer_signature(
            &key,
            &SigningScope {
                datetime: "20260101T000000Z",
                date: "20260101",
                region: "us-east-1",
                service: "s3",
            },
            prev_sig,
            trailers,
            &sig,
        )?;
        Ok(())
    }

    #[test]
    fn presigned_url_parsing() {
        let params = vec![
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            (
                "X-Amz-Credential",
                "AKID/20260101/us-east-1/s3/aws4_request",
            ),
            ("X-Amz-Date", "20260101T000000Z"),
            ("X-Amz-Expires", "3600"),
            ("X-Amz-SignedHeaders", "host"),
            ("X-Amz-Signature", "abcdef"),
        ];
        let presigned = parse_presigned_url(&params).expect("parse");
        assert_eq!(presigned.access_key, "AKID");
        assert_eq!(presigned.expires_secs, 3600);
        assert_eq!(presigned.signature, "abcdef");
    }

    #[test]
    fn presigned_url_rejects_missing_algorithm() {
        let params = vec![(
            "X-Amz-Credential",
            "AKID/20260101/us-east-1/s3/aws4_request",
        )];
        let result = parse_presigned_url(&params);
        assert!(matches!(result, Err(SigV4Error::MissingHeader { .. })));
    }

    #[test]
    fn end_to_end_header_auth() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let signing_key = derive_signing_key(secret, "20260101", "us-east-1", "s3");
        let canonical_request = build_canonical_request(
            "GET",
            "/test.txt",
            "",
            "host:examplebucket.s3.amazonaws.com\nx-amz-date:20260101T000000Z\n",
            "host;x-amz-date",
            &sha256_hex(b""),
        );
        let string_to_sign = build_string_to_sign(
            "20260101T000000Z",
            "20260101/us-east-1/s3/aws4_request",
            &canonical_request,
        );
        let signature = compute_signature(&signing_key, &string_to_sign);
        verify_signature(&signature, &signature).expect("self-verify must pass");
    }
}
