use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, blocking, path_param, query_optional, resolve_ns_read, store};
use kappa_store::edge::{Direction, Edge, EdgeQuery, EdgeRelation};
use kappa_store::kappa::Kappa;

const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

pub async fn list(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let digest = path_param(cx, "digest")?;
    let artifact_type_filter = query_optional(cx, "artifactType");
    let anchor = Kappa::parse(&digest)?;

    let s = store(cx);
    let query = EdgeQuery {
        anchor,
        direction: Direction::Inbound,
        relation: Some(EdgeRelation::Semantic(kappa_store::edge::SemanticRelation(
            kappa_store::edge::semantic::REFERENCES.into(),
        ))),
        asserter: None,
    };

    let edges = blocking({
        let s = s.clone();
        let ns = ns.clone();
        move || {
            let mut edges = Vec::new();
            let mut request = kappa_store::PageRequest::first(1024);
            loop {
                let page = s.edge_query(&ns, &query, &request)?;
                edges.extend(page.items);
                let Some(after) = page.next_after else { break };
                if request
                    .after
                    .as_ref()
                    .is_some_and(|previous| after <= *previous)
                {
                    return Err(kappa_store::StoreError::Internal(
                        "referrer cursor did not advance".into(),
                    ));
                }
                request.after = Some(after);
            }
            Ok::<_, kappa_store::StoreError>(edges)
        }
    })
    .await?;

    let mut descriptors: Vec<serde_json::Value> = Vec::new();
    for edge in edges {
        let source_kappa = edge.source().clone();
        let body = blocking({
            let s = s.clone();
            let ns = ns.clone();
            move || s.blob_get_in(&ns, &source_kappa)
        })
        .await?;
        if let Some(descriptor) = descriptor(&edge, &body, artifact_type_filter.as_deref())? {
            descriptors.push(descriptor);
        }
    }

    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": INDEX_MEDIA_TYPE,
        "manifests": descriptors,
    });

    let body_bytes = serde_json::to_vec(&index)
        .map_err(|e| HandlerError::internal(format!("referrers index serialize: {e}")))?;
    let mut response = Response::new(Body::from(body_bytes));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static(INDEX_MEDIA_TYPE),
    );
    if artifact_type_filter.is_some() {
        response.headers_mut().insert(
            "oci-filters-applied",
            http::HeaderValue::from_static("artifactType"),
        );
    }
    Ok(response)
}

/// Index descriptor of one referrer manifest; `None` when an `artifactType`
/// filter excludes it.
fn descriptor(
    edge: &Edge,
    body: &[u8],
    artifact_type_filter: Option<&str>,
) -> Result<Option<serde_json::Value>, HandlerError> {
    let manifest: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| HandlerError::Internal {
            reason: format!("referrer manifest {} is not valid JSON: {e}", edge.source()),
        })?;

    let media_type = manifest
        .get("mediaType")
        .and_then(|m| m.as_str())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json");

    let artifact_type = manifest
        .get("artifactType")
        .and_then(|a| a.as_str())
        .or_else(|| {
            manifest
                .get("config")
                .and_then(|c| c.get("mediaType"))
                .and_then(|m| m.as_str())
        })
        .unwrap_or("");

    if artifact_type_filter.is_some_and(|filter| artifact_type != filter) {
        return Ok(None);
    }

    let annotations = manifest
        .get("annotations")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(Some(serde_json::json!({
        "mediaType": media_type,
        "digest": edge.source().to_string(),
        "size": body.len(),
        "artifactType": artifact_type,
        "annotations": annotations,
    })))
}
