use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    Clock, HandlerError, ResolvedIdentity, ResolverRegistry, blocking, execute, path_param,
    read_body, service, store,
};
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;

use crate::handlers::{nix_ns, nix_target};
use crate::publish::{
    MAX_NARINFO_BYTES, ParsedNarinfo, bind_signer, check_stored_nar, narinfo_tag, write_narinfo,
};

fn extract_hash(cx: &Cx) -> Result<String, HandlerError> {
    let h = path_param(cx, "hash")?;
    if h.is_empty() {
        return Err(HandlerError::bad_request("missing hash parameter"));
    }
    Ok(h)
}

/// GET /_nix/narinfo/{hash}: return narinfo text.
pub async fn get(
    cx: &Cx,
    _body: Body, // GET: body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let nix_ns = nix_ns(cx)?;
    let hash = extract_hash(cx)?;
    let s = store(cx);
    let tag_name = narinfo_tag(&hash);

    let content = blocking(move || {
        let entry = s.tag_get(&nix_ns, &tag_name)?;
        s.blob_get_in(&nix_ns, &entry.kappa)
    })
    .await?;

    let mut resp = kappa_handler::binary_response(StatusCode::OK, "text/x-nix-narinfo", content)?;
    resp.headers_mut().insert(
        "cache-control",
        topcoat::router::HeaderValue::from_static("max-age=600"),
    );
    Ok(resp)
}

/// HEAD /_nix/narinfo/{hash}: existence check with content-length.
pub async fn head(
    cx: &Cx,
    _body: Body, // HEAD: body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let nix_ns = nix_ns(cx)?;
    let hash = extract_hash(cx)?;
    let s = store(cx);
    let tag_name = narinfo_tag(&hash);

    let size = blocking(move || {
        let entry = s.tag_get(&nix_ns, &tag_name)?;
        s.blob_size_in(&nix_ns, &entry.kappa)
    })
    .await?;

    let mut resp = kappa_handler::empty_response(StatusCode::OK);
    resp.headers_mut().insert(
        "content-type",
        topcoat::router::HeaderValue::from_static("text/x-nix-narinfo"),
    );
    resp.headers_mut()
        .insert("content-length", topcoat::router::HeaderValue::from(size));
    Ok(resp)
}

/// PUT /_nix/narinfo/{hash}: admit a narinfo and publish it.
///
/// The narinfo is parsed, matched to its URL, and its signatures by trusted
/// keys verified before any write; a NAR already uploaded is verified
/// against it. Its content, tag, NAR reverse index, edges, and signature
/// metadata then publish in one execution of `_nix`, so a rejected narinfo
/// publishes nothing. Verified signing keys are bound to their anchors
/// afterwards.
pub async fn put(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let url_hash = extract_hash(cx)?;
    let bytes = read_body(body, MAX_NARINFO_BYTES).await?;
    let parsed = ParsedNarinfo::parse(&url_hash, bytes.to_vec())?;
    let trusted = resolve_signing_keys(cx, parsed.key_names()).await;
    let valid = parsed.verify(&trusted)?;

    let target = nix_target(cx).await?;
    let s = store(cx);
    let namespace = target.namespace().clone();
    let deadline = std::time::Instant::now() + kappa_handler::PREPARATION_DEADLINE;
    let (valid, verified_nar) = blocking(move || {
        let verified_nar = check_stored_nar(&*s, &namespace, &valid, deadline)?;
        Ok::<_, StoreError>((valid, verified_nar))
    })
    .await?;

    let signers = valid.signers().to_vec();
    let mut verified_nar = verified_nar;
    let committed = execute(cx, target, &bytes, move |execution| {
        write_narinfo(execution, &valid, verified_nar.as_mut())
    })
    .await?;

    // A replayed or unchanged narinfo was bound when it first published.
    if committed.epoch.is_some() && !committed.replayed {
        bind_signers(cx, signers, &committed.value).await;
    }

    let mut response = kappa_handler::empty_response(StatusCode::CREATED);
    committed.annotate(&mut response);
    Ok(response)
}

/// Resolve signing key names through the server's resolver registry. A key
/// that does not resolve leaves its signature unverified, as before any
/// trusted key is configured.
async fn resolve_signing_keys(cx: &Cx, key_names: Vec<String>) -> Vec<(String, ResolvedIdentity)> {
    let Some(registry) = kappa_handler::try_service::<Arc<ResolverRegistry>>(cx).cloned() else {
        return Vec::new();
    };
    let mut trusted = Vec::with_capacity(key_names.len());
    for key_name in key_names {
        match registry.resolve(&key_name).await {
            Ok(Some(identity)) => trusted.push((key_name, identity)),
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(
                    key_name = key_name.as_str(),
                    error = %error,
                    "nix signing key resolution failed",
                );
            }
        }
    }
    trusted
}

/// Bind each verified signing key to its anchor in the anchor's namespace.
///
/// The narinfo has already published; a binding failure cannot undo it and
/// does not change the 201 response, so failures are logged.
async fn bind_signers(cx: &Cx, signers: Vec<(String, ResolvedIdentity)>, narinfo: &Kappa) {
    for (key_name, identity) in signers {
        let s = store(cx);
        let clock = service::<Arc<dyn Clock>>(cx).clone();
        let narinfo = narinfo.clone();
        let name = key_name.clone();
        let bound = blocking(move || bind_signer(&*s, &name, &identity, &narinfo, &*clock)).await;
        if let Err(error) = bound {
            tracing::warn!(
                key_name = key_name.as_str(),
                error = %error,
                "nix signing key identity binding failed",
            );
        }
    }
}
