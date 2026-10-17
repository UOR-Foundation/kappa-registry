use crate::error::HandlerError;
use std::collections::HashMap;
use topcoat::context::Cx;
use topcoat::router::raw_path_params;

/// Extract a path parameter by name from the matched route.
pub fn path_param(cx: &Cx, name: &str) -> Result<String, HandlerError> {
    raw_path_params(cx)
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.as_str().to_string())
        .ok_or_else(|| HandlerError::Internal {
            reason: format!("missing path parameter: {name}"),
        })
}

/// Percent-decode a URL-encoded string.
pub fn percent_decode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(hex_val);
            let lo = bytes.next().and_then(hex_val);
            match (hi, lo) {
                (Some(h), Some(l)) => output.push((h << 4 | l) as char),
                _ => output.push('%'),
            }
        } else if b == b'+' {
            output.push(' ');
        } else {
            output.push(b as char);
        }
    }
    output
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Extract a bearer or `DPoP` token from the Authorization header.
/// Validates token format: exactly 64 lowercase hex characters.
/// Rejects oversized or malformed tokens before any `HashMap` lookup.
pub fn extract_bearer_token(cx: &Cx) -> Option<String> {
    let parts: &http::request::Parts = topcoat::context::request_context(cx);
    let token = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("DPoP "))
        })?;
    if is_valid_session_token(token) {
        Some(token.to_string())
    } else {
        None
    }
}

/// Validate that a string is a well-formed session token.
/// Exactly 64 lowercase hex characters [0-9a-f].
pub fn is_valid_session_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Generate a cryptographically random session token.
/// 32 bytes of OS entropy, hex-encoded to 64 characters.
/// Substrate infrastructure — every protocol that authenticates
/// sessions uses this function.
pub fn generate_session_token() -> Result<String, HandlerError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| HandlerError::internal(format!("CSPRNG unavailable: {e}")))?;
    Ok(hex::encode(bytes))
}

// -- Base64 -------------------------------------------------------------------

/// Base64url encode (RFC 4648 section 5, no padding).
/// SSOT for all base64url operations across all protocol modules.
pub fn base64url_encode(data: &[u8]) -> String {
    base64_simd::URL_SAFE_NO_PAD.encode_to_string(data)
}

/// Base64url decode (RFC 4648 section 5, no padding).
/// Returns the decoded bytes or a `HandlerError` on malformed input.
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, HandlerError> {
    base64_simd::URL_SAFE_NO_PAD
        .decode_to_vec(input.as_bytes())
        .map_err(|e| HandlerError::BadRequest {
            reason: format!("invalid base64url: {e}"),
        })
}

/// Standard base64 encode (RFC 4648 section 4, with padding).
/// Used by Nix signatures, S3 credentials, Fulcio certificates.
pub fn base64_encode(data: &[u8]) -> String {
    base64_simd::STANDARD.encode_to_string(data)
}

/// Standard base64 decode (RFC 4648 section 4, with padding).
pub fn base64_decode(input: &str) -> Result<Vec<u8>, HandlerError> {
    base64_simd::STANDARD
        .decode_to_vec(input.as_bytes())
        .map_err(|e| HandlerError::BadRequest {
            reason: format!("invalid base64: {e}"),
        })
}

/// Base64url-encode the SHA-256 hash of data. Used by `DPoP` ATH
/// and JWK thumbprint computation.
pub fn base64url_sha256(data: &[u8]) -> String {
    use sha2::Digest;
    base64url_encode(&sha2::Sha256::digest(data))
}

// -- Query map ----------------------------------------------------------------

/// Extract a query parameter map from the request URI.
pub fn parse_query_map(cx: &Cx) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let parts: &http::request::Parts = topcoat::context::request_context(cx);
    if let Some(query) = parts.uri.query() {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                map.insert(percent_decode(k), percent_decode(v));
            } else {
                map.insert(percent_decode(pair), String::new());
            }
        }
    }
    map
}
