use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use kappa_crypto::sigv4;

pub struct S3Principal {
    pub access_key_id: String,
    pub principal_anchor: String,
}

pub struct S3Region(pub String);

pub fn verify_request(
    cx: &Cx,
    _body_bytes: Option<&[u8]>,
) -> Result<Option<S3Principal>, Box<Response>> {
    let cred_store = match kappa_handler::try_service::<Arc<dyn sigv4::CredentialLookup>>(cx) {
        Some(cs) => cs.clone(),
        None => return Ok(None),
    };
    let region = kappa_handler::try_service::<S3Region>(cx)
        .map(|r| r.0.clone())
        .unwrap_or_else(|| "us-east-1".to_string());

    let parts: &http::request::Parts = topcoat::context::request_context(cx);
    let auth_header = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let query = parts.uri.query().unwrap_or("");
    let has_presigned = query.contains("X-Amz-Algorithm");

    if auth_header.is_none() && !has_presigned {
        return Ok(None);
    }
    if let Some(ref auth) = auth_header
        && !auth.starts_with("AWS4-HMAC-SHA256")
    {
        return Ok(None);
    }
    let now = kappa_handler::clock_now(cx).map_err(|_| {
        s3_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "time authority unavailable",
        )
    })?;

    let datetime = parts
        .headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let security_token = parts
        .headers
        .get("x-amz-security-token")
        .and_then(|v| v.to_str().ok());

    if let Some(auth) = auth_header {
        let parsed = sigv4::parse_authorization(&auth, security_token).map_err(|_| {
            s3_err(
                StatusCode::FORBIDDEN,
                "InvalidSignature",
                "malformed Authorization header",
            )
        })?;

        let cred = cred_store
            .lookup_credential(&parsed.access_key, now)
            .ok_or_else(|| {
                s3_err(
                    StatusCode::FORBIDDEN,
                    "InvalidAccessKeyId",
                    "access key not found",
                )
            })?;

        let payload_hash = parts
            .headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(sigv4::UNSIGNED_PAYLOAD);

        let mut sorted_headers: Vec<(&str, &str)> = parsed
            .signed_headers
            .iter()
            .filter_map(|name| {
                parts
                    .headers
                    .get(name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .map(|v| (name.as_str(), v))
            })
            .collect();
        sorted_headers.sort_by(|a, b| a.0.cmp(b.0));

        let canonical_headers = sigv4::build_canonical_headers(&sorted_headers);
        let signed_headers_str = parsed.signed_headers.join(";");
        let query_params: Vec<(&str, &str)> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.split_once('='))
            .collect();
        let canonical_query = sigv4::build_canonical_query(&query_params);
        let canonical_request = sigv4::build_canonical_request(
            parts.method.as_str(),
            parts.uri.path(),
            &canonical_query,
            &canonical_headers,
            &signed_headers_str,
            payload_hash,
        );
        let scope = format!(
            "{}/{}/{}/aws4_request",
            parsed.date, parsed.region, parsed.service
        );
        let string_to_sign = sigv4::build_string_to_sign(datetime, &scope, &canonical_request);

        let signing_key = sigv4::derive_signing_key(
            &cred.current_secret,
            &parsed.date,
            &parsed.region,
            &parsed.service,
        );
        let computed = sigv4::compute_signature(&signing_key, &string_to_sign);
        if sigv4::verify_signature(&computed, &parsed.signature).is_ok() {
            return Ok(Some(S3Principal {
                access_key_id: parsed.access_key,
                principal_anchor: cred.principal_anchor.to_string(),
            }));
        }

        if let Some(prev) = &cred.previous_secret {
            let prev_key =
                sigv4::derive_signing_key(prev, &parsed.date, &parsed.region, &parsed.service);
            let prev_computed = sigv4::compute_signature(&prev_key, &string_to_sign);
            if sigv4::verify_signature(&prev_computed, &parsed.signature).is_ok() {
                return Ok(Some(S3Principal {
                    access_key_id: parsed.access_key,
                    principal_anchor: cred.principal_anchor.to_string(),
                }));
            }
        }

        return Err(s3_err(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "the request signature does not match",
        ));
    }

    if has_presigned {
        let query_params: Vec<(&str, &str)> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.split_once('='))
            .collect();
        let parsed = sigv4::parse_presigned_url(&query_params).map_err(|_| {
            s3_err(
                StatusCode::FORBIDDEN,
                "InvalidSignature",
                "malformed presigned URL",
            )
        })?;

        let physical_secs = kappa_handler::physical_now(cx)
            .map_err(|_| {
                s3_err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ServiceUnavailable",
                    "time authority unavailable",
                )
            })?
            .unix_seconds();
        let now_secs = u64::try_from(physical_secs).map_err(|_| {
            s3_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "physical time precedes Unix epoch",
            )
        })?;
        sigv4::check_presigned_expiration(&parsed.datetime, parsed.expires_secs, now_secs)
            .map_err(|_| {
                s3_err(
                    StatusCode::FORBIDDEN,
                    "ExpiredToken",
                    "presigned URL expired",
                )
            })?;

        let cred = cred_store
            .lookup_credential(&parsed.access_key, now)
            .ok_or_else(|| {
                s3_err(
                    StatusCode::FORBIDDEN,
                    "InvalidAccessKeyId",
                    "access key not found",
                )
            })?;

        let signing_key =
            sigv4::derive_signing_key(&cred.current_secret, &parsed.date, &region, "s3");
        let mut sorted_headers: Vec<(&str, &str)> = parsed
            .signed_headers
            .iter()
            .filter_map(|name| {
                parts
                    .headers
                    .get(name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .map(|v| (name.as_str(), v))
            })
            .collect();
        sorted_headers.sort_by(|a, b| a.0.cmp(b.0));
        let canonical_headers = sigv4::build_canonical_headers(&sorted_headers);
        let signed_headers_str = parsed.signed_headers.join(";");
        let canonical_request = sigv4::build_presigned_canonical_request(
            parts.method.as_str(),
            parts.uri.path(),
            &query_params,
            &canonical_headers,
            &signed_headers_str,
        );
        let scope = format!(
            "{}/{}/{}/aws4_request",
            parsed.date, parsed.region, parsed.service
        );
        let string_to_sign =
            sigv4::build_string_to_sign(&parsed.datetime, &scope, &canonical_request);
        let computed = sigv4::compute_signature(&signing_key, &string_to_sign);

        if sigv4::verify_signature(&computed, &parsed.signature).is_ok() {
            return Ok(Some(S3Principal {
                access_key_id: parsed.access_key,
                principal_anchor: cred.principal_anchor.to_string(),
            }));
        }
        return Err(s3_err(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "presigned URL signature mismatch",
        ));
    }

    Ok(None)
}

fn s3_err(status: StatusCode, code: &str, message: &str) -> Box<Response> {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Error><Code>{code}</Code><Message>{message}</Message></Error>"
    );
    let mut response = Response::new(Body::from(xml));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", "application/xml".parse().unwrap());
    Box::new(response)
}
