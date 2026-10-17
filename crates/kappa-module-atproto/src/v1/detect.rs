use kappa_handler::detect::{BodyClass, DetectedOperation, ProtocolDetector, ProtocolMatch};

pub struct XrpcDetector;

impl ProtocolDetector for XrpcDetector {
    fn protocol(&self) -> &'static str {
        "atproto"
    }
    fn priority(&self) -> u32 {
        200
    }

    fn detect(
        &self,
        path: &str,
        _query: &str,
        headers: &http::HeaderMap,
        _host: Option<&str>,
    ) -> Option<ProtocolMatch> {
        if !path.starts_with("/xrpc/") {
            return None;
        }

        // XRPC method type determines operation:
        // - HTTP GET on any XRPC path is a query (read)
        // - HTTP POST on any XRPC path is a procedure (write)
        // - subscribeRepos (WebSocket upgrade) is a read (subscription)
        //
        // The HTTP method is not available in the detector's parameters
        // (detectors see path/query/headers/host). Use the Upgrade header
        // to detect WebSocket, and default to Write for POST bodies.
        // The auth layer resolves the actual operation from the HTTP method.
        let operation = if headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        {
            DetectedOperation::Read
        } else {
            // The namespace interceptor layer will refine this based on
            // the actual HTTP method. POST = Write, GET = Read.
            // Default to Read since the majority of XRPC endpoints are
            // queries (GET), and the auth layer promotes to Write for
            // POST requests via DetectedOperation from the method.
            DetectedOperation::Read
        };

        Some(ProtocolMatch {
            protocol: "atproto",
            namespace: None,
            rewrite: None,
            operation,
            body: body_class(path),
        })
    }
}

/// `uploadBlob` carries a blob and `importRepo` a repository CAR; every
/// other procedure input is a JSON control document.
fn body_class(path: &str) -> BodyClass {
    match path {
        "/xrpc/com.atproto.repo.uploadBlob" | "/xrpc/com.atproto.repo.importRepo" => {
            BodyClass::Content
        }
        _ => BodyClass::Control,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xrpc_path_detected() {
        let m = XrpcDetector
            .detect(
                "/xrpc/com.atproto.server.describeServer",
                "",
                &http::HeaderMap::new(),
                None,
            )
            .unwrap();
        assert_eq!(m.protocol, "atproto");
        assert_eq!(m.operation, DetectedOperation::Read);
    }

    #[test]
    fn body_classes() {
        assert_eq!(
            body_class("/xrpc/com.atproto.repo.uploadBlob"),
            BodyClass::Content
        );
        assert_eq!(
            body_class("/xrpc/com.atproto.repo.importRepo"),
            BodyClass::Content
        );
        assert_eq!(
            body_class("/xrpc/com.atproto.repo.createRecord"),
            BodyClass::Control
        );
    }

    #[test]
    fn non_xrpc_not_detected() {
        assert!(
            XrpcDetector
                .detect(
                    "/v2/myrepo/blobs/sha256:abc",
                    "",
                    &http::HeaderMap::new(),
                    None,
                )
                .is_none()
        );
    }

    #[test]
    fn websocket_upgrade_is_read() {
        let mut headers = http::HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().unwrap());
        let m = XrpcDetector
            .detect("/xrpc/com.atproto.sync.subscribeRepos", "", &headers, None)
            .unwrap();
        assert_eq!(m.operation, DetectedOperation::Read);
    }
}
