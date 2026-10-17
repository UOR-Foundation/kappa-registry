use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::HandlerError;

/// Nix binary cache priority. Registered in app context by the server
/// from KAPPA_NIX_PRIORITY env var at startup. Default 30.
pub struct NixPriority(pub u32);

pub async fn handler(
    cx: &Cx,
    _body: Body, // GET — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let priority = kappa_handler::try_service::<NixPriority>(cx)
        .map(|p| p.0)
        .unwrap_or(30);
    let body = format!(
        "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: {}\n",
        priority,
    );
    kappa_handler::binary_response(StatusCode::OK, "text/x-nix-cache-info", body.into_bytes())
}
