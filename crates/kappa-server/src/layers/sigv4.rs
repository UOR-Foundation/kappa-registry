//! SigV4 authentication middleware layer for S3-compatible requests.
//!
//! Intercepts requests with AWS4-HMAC-SHA256 Authorization headers or
//! X-Amz-Algorithm presigned URL query parameters. Verifies the signature
//! against the credential store. Non-S3 requests (no AWS4 auth) pass
//! through to the next layer (bearer auth).
//!
//! Covers items 38, 40, 41 from the implementation spec.

use std::sync::Arc;

use topcoat::context::{try_app_context, Cx};
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use kappa_core::crypto::sigv4;

/// Authenticated S3 principal, inserted into request context after
/// successful SigV4 verification. Downstream handlers read this to
/// determine the caller identity.
pub struct S3Principal {
    pub access_key_id: String,
    pub principal_anchor: String,
}

/// S3 region configuration, registered as app_context.
pub struct S3Region(pub String);

/// Run SigV4 verification on the request. Returns Ok(None) if the request
/// has no SigV4 auth (non-S3 request, pass through). Returns Ok(Some(principal))
/// on successful verification. Returns Err(Response) on auth failure.
pub fn verify_request(
    cx: &Cx,
    _body_bytes: Option<&[u8]>,
) -> Result<Option<S3Principal>, Response> {
    let cred_store = match try_app_context::<Arc<dyn sigv4::CredentialLookup>>(cx) {
        Some(cs) => cs.clone(),
        None => return Ok(None), // No credential store configured -- pass through
    };

    let region = try_app_context::<S3Region>(cx)
        .map(|r| r.0.clone())
        .unwrap_or_else(|| "us-east-1".to_string());

    // Extract Authorization header
    let parts: &http::request::Parts = topcoat::context::request_context(cx);
    let auth_header = parts.headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Check for presigned URL
    let query = parts.uri.query().unwrap_or("");
    let has_presigned = query.contains("X-Amz-Algorithm");

    if auth_header.is_none() && !has_presigned {
        return Ok(None); // Not an S3 request -- pass through
    }

    if let Some(ref auth) = auth_header {
        if !auth.starts_with("AWS4-HMAC-SHA256") {
            return Ok(None); // Not SigV4 -- pass through (could be bearer)
        }
    }

    // Extract datetime and security token from headers
    let datetime = parts.headers.get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let security_token = parts.headers.get("x-amz-security-token")
        .and_then(|v| v.to_str().ok());

    if let Some(auth) = auth_header {
        // Header-based auth
        let parsed = sigv4::parse_authorization(&auth, security_token)
            .map_err(|_| s3_error_response(StatusCode::FORBIDDEN, "InvalidSignature", "malformed Authorization header"))?;

        let cred_result = cred_store.lookup_credential(&parsed.access_key)
            .ok_or_else(|| s3_error_response(StatusCode::FORBIDDEN, "InvalidAccessKeyId", "access key not found"))?;

        // Try current secret
        let signing_key = sigv4::derive_signing_key(
            &cred_result.current_secret, &parsed.date, &parsed.region, &parsed.service,
        );

        // Build canonical request
        let payload_hash = parts.headers.get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(sigv4::UNSIGNED_PAYLOAD);

        let mut sorted_headers: Vec<(&str, &str)> = parsed.signed_headers.iter()
            .filter_map(|name| {
                parts.headers.get(name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .map(|v| (name.as_str(), v))
            })
            .collect();
        sorted_headers.sort_by(|a, b| a.0.cmp(b.0));

        let canonical_headers = sigv4::build_canonical_headers(&sorted_headers);
        let signed_headers_str = parsed.signed_headers.join(";");

        let query_params: Vec<(&str, &str)> = query.split('&')
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.split_once('='))
            .collect();
        let canonical_query = sigv4::build_canonical_query(&query_params);

        let path = parts.uri.path();
        let canonical_request = sigv4::build_canonical_request(
            parts.method.as_str(), path, &canonical_query,
            &canonical_headers, &signed_headers_str, payload_hash,
        );

        let scope = format!("{}/{}/{}/aws4_request", parsed.date, parsed.region, parsed.service);
        let string_to_sign = sigv4::build_string_to_sign(datetime, &scope, &canonical_request);
        let computed = sigv4::compute_signature(&signing_key, &string_to_sign);

        // Constant-time comparison
        if sigv4::verify_signature(&computed, &parsed.signature).is_ok() {
            return Ok(Some(S3Principal {
                access_key_id: parsed.access_key,
                principal_anchor: cred_result.principal_anchor,
            }));
        }

        // Try previous secret (rotation grace period)
        if let Some(prev) = &cred_result.previous_secret {
            let prev_key = sigv4::derive_signing_key(
                prev, &parsed.date, &parsed.region, &parsed.service,
            );
            let prev_computed = sigv4::compute_signature(&prev_key, &string_to_sign);
            if sigv4::verify_signature(&prev_computed, &parsed.signature).is_ok() {
                return Ok(Some(S3Principal {
                    access_key_id: parsed.access_key,
                    principal_anchor: cred_result.principal_anchor,
                }));
            }
        }

        return Err(s3_error_response(
            StatusCode::FORBIDDEN, "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided.",
        ));
    }

    if has_presigned {
        // Presigned URL auth
        let query_params: Vec<(&str, &str)> = query.split('&')
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.split_once('='))
            .collect();

        let parsed = sigv4::parse_presigned_url(&query_params)
            .map_err(|_| s3_error_response(StatusCode::FORBIDDEN, "InvalidSignature", "malformed presigned URL"))?;

        // Check expiration
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        sigv4::check_presigned_expiration(&parsed.datetime, parsed.expires_secs, now_secs)
            .map_err(|_| s3_error_response(StatusCode::FORBIDDEN, "ExpiredToken", "presigned URL has expired"))?;

        let cred_result = cred_store.lookup_credential(&parsed.access_key)
            .ok_or_else(|| s3_error_response(StatusCode::FORBIDDEN, "InvalidAccessKeyId", "access key not found"))?;

        let signing_key = sigv4::derive_signing_key(
            &cred_result.current_secret, &parsed.date, &region, "s3",
        );

        // Build canonical request for presigned URL
        let mut sorted_headers: Vec<(&str, &str)> = parsed.signed_headers.iter()
            .filter_map(|name| {
                parts.headers.get(name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .map(|v| (name.as_str(), v))
            })
            .collect();
        sorted_headers.sort_by(|a, b| a.0.cmp(b.0));
        let canonical_headers = sigv4::build_canonical_headers(&sorted_headers);
        let signed_headers_str = parsed.signed_headers.join(";");

        let canonical_request = sigv4::build_presigned_canonical_request(
            parts.method.as_str(), parts.uri.path(),
            &query_params, &canonical_headers, &signed_headers_str,
        );

        let scope = format!("{}/{}/{}/aws4_request", parsed.date, parsed.region, parsed.service);
        let string_to_sign = sigv4::build_string_to_sign(&parsed.datetime, &scope, &canonical_request);
        let computed = sigv4::compute_signature(&signing_key, &string_to_sign);

        if sigv4::verify_signature(&computed, &parsed.signature).is_ok() {
            return Ok(Some(S3Principal {
                access_key_id: parsed.access_key,
                principal_anchor: cred_result.principal_anchor,
            }));
        }

        return Err(s3_error_response(
            StatusCode::FORBIDDEN, "SignatureDoesNotMatch",
            "presigned URL signature mismatch",
        ));
    }

    Ok(None)
}

fn s3_error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let xml = kappa_module_s3::encode_s3_error_xml(code, message);
    let mut response = Response::new(Body::from(xml));
    *response.status_mut() = status;
    response.headers_mut().insert("content-type", "application/xml".parse().unwrap());
    response
}
