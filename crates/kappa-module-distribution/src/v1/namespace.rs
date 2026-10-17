use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, Method, RouterBuilder, StatusCode};

use kappa_crypto::node::NodeIdentity;
use kappa_handler::{
    HandlerError, blocking, clock_now, json_response, path_param, query_optional, resolve_ns_read,
    store,
};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(dist_route!(
            Method::GET,
            "/v2/{*ns}/_root/proof/{name}",
            proof
        ))
        .route(dist_route!(Method::GET, "/v2/{*ns}/_root", root))
}

async fn root(cx: &Cx, _body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let s = store(cx);
    let want_signed = query_optional(cx, "signed").as_deref() == Some("true");

    let (epoch_num, root_kappa, tag_count) = blocking({
        let s = s.clone();
        let n = ns.clone();
        move || -> Result<_, HandlerError> {
            let epoch = match s.epoch_current(&n) {
                Ok((num, kappa)) => Some((num, kappa)),
                Err(kappa_store::StoreError::NotFound(_)) => None,
                Err(e) => return Err(e.into()),
            };
            let tags = public_tags(s.as_ref(), &n)?;
            let count = tags.iter().filter(|t| !t.name.starts_with('_')).count();
            match epoch {
                Some((num, kappa)) => Ok((num, Some(kappa), count)),
                None => Ok((0, None, count)),
            }
        }
    })
    .await?;

    if want_signed {
        let ni = kappa_handler::try_service::<Arc<NodeIdentity>>(cx).ok_or_else(|| {
            HandlerError::Internal {
                reason: "node identity not bootstrapped".into(),
            }
        })?;
        let root_str = root_kappa
            .as_ref()
            .map(|k| k.to_string())
            .unwrap_or_default();
        let now = clock_now(cx)?;
        let timestamp_ms = now.as_i64();
        let message = format!("{}\n{}\n{}", ns.display_name(), root_str, timestamp_ms);
        // Signature, key, algorithm and anchor come from one authority held
        // for the whole response, so a concurrent rotation cannot mix them.
        let signing_error = |e: kappa_crypto::CryptoError| HandlerError::Internal {
            reason: format!("signing: {e}"),
        };
        let body = ni
            .with_authority(|authority| {
                let signer = authority.signer();
                let signature = signer.sign(message.as_bytes())?;
                Ok::<_, kappa_crypto::CryptoError>(serde_json::json!({
                    "namespace": ns.display_name(),
                    "root": root_str,
                    "count": tag_count,
                    "epoch": epoch_num,
                    "timestamp_ms": timestamp_ms,
                    "algorithm": signer.algorithm(),
                    "public_key": hex::encode(signer.public_key()),
                    "signature": hex::encode(&signature),
                    "signer_anchor": authority.anchor().to_string(),
                }))
            })
            .map_err(signing_error)?
            .map_err(signing_error)?;
        return json_response(StatusCode::OK, &body);
    }

    let root_str = root_kappa
        .as_ref()
        .map(|k| k.to_string())
        .unwrap_or_default();
    let body = serde_json::json!({
        "root": root_str,
        "count": tag_count,
        "epoch": epoch_num,
    });
    json_response(StatusCode::OK, &body)
}

async fn proof(cx: &Cx, _body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let name = path_param(cx, "name")?;

    let s = store(cx);
    let result = blocking(move || -> Result<_, HandlerError> {
        let (epoch_num, root_kappa) = s.epoch_current(&ns)?;
        let epoch_root = s.epoch_get(&root_kappa)?;
        let tags = public_tags(s.as_ref(), &ns)?;
        let public_tags: Vec<&kappa_store::tag::TagEntry> =
            tags.iter().filter(|t| !t.name.starts_with('_')).collect();
        let index = public_tags
            .iter()
            .position(|t| t.name == name)
            .ok_or_else(|| HandlerError::NotFound {
                reason: format!("tag {} not found in epoch {}", name, epoch_num),
            })?;
        Ok(serde_json::json!({
            "root": root_kappa.to_string(),
            "epoch_number": epoch_num,
            "tag_name": name,
            "tag_index": index,
            "timestamp_ms": epoch_root.timestamp().as_i64(),
        }))
    })
    .await?;

    json_response(StatusCode::OK, &result)
}

fn public_tags(
    store: &dyn kappa_store::TagStore,
    namespace: &kappa_store::NamespaceRef,
) -> Result<Vec<kappa_store::TagEntry>, kappa_store::StoreError> {
    Ok(crate::listing::tags(store, namespace, None)?
        .into_iter()
        .filter(|tag| !tag.name.starts_with('_'))
        .collect())
}
