use kappa_handler::detect::{BodyClass, DetectedOperation, ProtocolDetector, ProtocolMatch};

pub struct S3HeaderDetector;

impl ProtocolDetector for S3HeaderDetector {
    fn protocol(&self) -> &'static str {
        "s3"
    }
    fn priority(&self) -> u32 {
        100
    }

    fn detect(
        &self,
        path: &str,
        query: &str,
        headers: &http::HeaderMap,
        _host: Option<&str>,
    ) -> Option<ProtocolMatch> {
        let has_amz = headers.contains_key("x-amz-content-sha256");
        let has_sigv4 = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256"));
        if !has_amz && !has_sigv4 {
            return None;
        }
        let ns = extract_s3_bucket(path);
        Some(ProtocolMatch {
            protocol: "s3",
            namespace: ns,
            rewrite: None,
            operation: DetectedOperation::Read,
            body: body_class(path, query),
        })
    }
}

/// Requests addressing an object key carry object bytes (PutObject,
/// UploadPart, CompleteMultipartUpload). DeleteObjects (`POST /{bucket}?delete`)
/// carries a document of up to `MAX_BATCH_DELETE_BODY`, above the API body
/// limit. Other bucket-level bodies are configuration documents.
fn body_class(path: &str, query: &str) -> BodyClass {
    let has_key = path
        .strip_prefix('/')
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(bucket, key)| !bucket.is_empty() && !key.is_empty());
    let batch_delete = query
        .split('&')
        .any(|pair| pair.split_once('=').map_or(pair, |(name, _)| name) == "delete");
    if has_key || batch_delete {
        BodyClass::Content
    } else {
        BodyClass::Control
    }
}

fn extract_s3_bucket(path: &str) -> Option<String> {
    let rest = path.strip_prefix('/')?;
    if rest.is_empty() {
        return None;
    }
    let bucket = rest.split('/').next()?;
    if bucket.is_empty() {
        return None;
    }
    Some(bucket.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_amz_header() {
        let mut hdrs = http::HeaderMap::new();
        hdrs.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        let m = S3HeaderDetector
            .detect("/mybucket/mykey", "", &hdrs, None)
            .unwrap();
        assert_eq!(m.protocol, "s3");
        assert_eq!(m.namespace.as_deref(), Some("mybucket"));
    }

    #[test]
    fn detects_sigv4_auth() {
        let mut hdrs = http::HeaderMap::new();
        hdrs.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=...".parse().unwrap(),
        );
        let m = S3HeaderDetector
            .detect("/mybucket/mykey", "", &hdrs, None)
            .unwrap();
        assert_eq!(m.protocol, "s3");
    }

    #[test]
    fn no_match_without_headers() {
        assert!(
            S3HeaderDetector
                .detect("/mybucket/mykey", "", &http::HeaderMap::new(), None)
                .is_none()
        );
    }

    #[test]
    fn body_classes() {
        assert_eq!(body_class("/bucket/key", ""), BodyClass::Content);
        assert_eq!(
            body_class("/bucket/a/b", "partNumber=2&uploadId=x"),
            BodyClass::Content
        );
        assert_eq!(body_class("/bucket", "delete"), BodyClass::Content);
        assert_eq!(body_class("/bucket", "delete="), BodyClass::Content);
        assert_eq!(body_class("/bucket", "versioning"), BodyClass::Control);
        assert_eq!(body_class("/bucket", "deleted"), BodyClass::Control);
        assert_eq!(body_class("/bucket/", ""), BodyClass::Control);
        assert_eq!(body_class("/", ""), BodyClass::Control);
    }

    #[test]
    fn root_path_no_bucket() {
        let mut hdrs = http::HeaderMap::new();
        hdrs.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        let m = S3HeaderDetector.detect("/", "", &hdrs, None).unwrap();
        assert!(m.namespace.is_none());
    }
}
