use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use crate::sync::crawl::PdsHostname;
use kappa_crypto::NodeIdentity;
use kappa_handler::{HandlerError, try_service};

/// GET /xrpc/com.atproto.server.describeServer
///
/// Returns the node's DID, available user domains (from PDS hostname
/// configuration), and configuration flags per the AT Protocol lexicon.
pub async fn describe_server(
    cx: &Cx,
    _body: Body, // GET — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ni = try_service::<Arc<NodeIdentity>>(cx)
        .ok_or_else(|| HandlerError::internal("node identity not bootstrapped"))?;

    let did = ni
        .anchor()
        .map_err(|error| HandlerError::internal(format!("node identity: {error}")))?
        .to_string();

    let available_domains: Vec<String> = match try_service::<PdsHostname>(cx) {
        Some(pds) => {
            let host = pds
                .0
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");
            if host.is_empty() {
                Vec::new()
            } else {
                vec![format!(".{}", host)]
            }
        }
        None => Vec::new(),
    };

    kappa_handler::json_response(
        StatusCode::OK,
        &serde_json::json!({
            "did": did,
            "availableUserDomains": available_domains,
            "inviteCodeRequired": false,
            "phoneVerificationRequired": false,
            "links": {},
        }),
    )
}
