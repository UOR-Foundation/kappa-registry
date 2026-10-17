use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_crypto::NodeIdentity;
use kappa_handler::{HandlerError, blocking, store};

pub async fn handler(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let node = kappa_handler::try_service::<Arc<NodeIdentity>>(cx)
        .cloned()
        .ok_or_else(|| HandlerError::internal("node identity not bootstrapped"))?;
    let s = store(cx);
    // Anchor and algorithm from one authority snapshot: a rotation between
    // two reads cannot pair one key's anchor with another's algorithm.
    let (node_anchor, algorithm) = node
        .with_authority(|authority| {
            (
                authority.anchor().clone(),
                authority.signer().algorithm().to_string(),
            )
        })
        .map_err(|error| HandlerError::internal(format!("node identity: {error}")))?;

    let body = blocking(move || {
        let anchor = node_anchor.to_string();
        let position = node.position().as_str().to_string();

        // Resolve the identity namespace by name through the store.
        // The namespace was created by bootstrap with the anchor string
        // as its display name and a UUIDv7 as its identity.
        let ns = s.namespace_resolve(&anchor, None).ok();

        let epoch = match ns.as_ref().and_then(|ns| s.epoch_current(ns).ok()) {
            Some((num, _kappa)) => serde_json::Value::Number(num.into()),
            None => serde_json::Value::Null,
        };

        let self_assertions = match ns.as_ref().and_then(|ns| {
            s.tag_list(ns, Some("node/"), &kappa_store::PageRequest::first(100))
                .ok()
                .map(|tags| (ns.clone(), tags))
        }) {
            Some((ns, tags)) => {
                let mut map = serde_json::Map::new();
                for tag in &tags.items {
                    let key = tag.name.strip_prefix("node/").unwrap_or(&tag.name);
                    match s.blob_get_in(&ns, &tag.kappa) {
                        Ok(bytes) => {
                            let val =
                                String::from_utf8(bytes).unwrap_or_else(|_| tag.kappa.to_string());
                            map.insert(key.to_string(), serde_json::Value::String(val));
                        }
                        Err(_) => {
                            map.insert(
                                key.to_string(),
                                serde_json::Value::String(tag.kappa.to_string()),
                            );
                        }
                    }
                }
                serde_json::Value::Object(map)
            }
            None => serde_json::Value::Object(serde_json::Map::new()),
        };

        Ok::<_, kappa_store::StoreError>(serde_json::json!({
            "anchor": anchor,
            "algorithm": algorithm,
            "trust_position": position,
            "epoch": epoch,
            "self_assertions": self_assertions,
        }))
    })
    .await?;

    kappa_handler::json_response(StatusCode::OK, &body)
}
