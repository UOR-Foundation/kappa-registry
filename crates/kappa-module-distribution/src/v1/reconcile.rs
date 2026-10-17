use topcoat::context::{Cx, try_request_context};
use topcoat::router::{Body, RouterBuilder, StatusCode};

use kappa_handler::{HandlerError, ResolvedNamespace, blocking, json_response, read_json, store};
use kappa_store::namespace::NamespaceRef;
use kappa_store::page::PageRequest;
use kappa_store::traits::KappaStore;

/// Items at or below this count are sent directly instead of subdividing.
const PAYLOAD_THRESHOLD: usize = 32;

/// Number of sub-ranges for subdivision.
const RANGE_DIVISION: usize = 4;

/// Maximum items per range query batch during cursor iteration.
const RANGE_BATCH_SIZE: usize = 1000;

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder.route(dist_route!(
        topcoat::router::Method::POST,
        "/v2/{*ns}/_reconcile",
        handler
    ))
}

async fn handler(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let req: serde_json::Value = read_json(body, 1024 * 1024).await?;
    let ns = range_source(cx)?;
    let msg_type = req["type"]
        .as_str()
        .ok_or_else(|| HandlerError::bad_request("missing type field"))?;

    match msg_type {
        "fingerprint" => handle_fingerprint(cx, ns, &req).await,
        "items_request" => handle_items_request(cx, ns, &req).await,
        "items" => handle_items(cx, ns, &req).await,
        _ => Err(HandlerError::bad_request(format!(
            "unknown reconcile message type: {msg_type}",
        ))),
    }
}

/// The namespace whose tags the exchange ranges over.
///
/// Every message type only reads, so a namespace that does not exist yet is
/// answered as the empty set rather than refused: a peer bootstrapping a
/// replica reconciles against it and receives the empty fingerprint and an
/// empty item list. Nothing is created on its behalf.
fn range_source(cx: &Cx) -> Result<Option<NamespaceRef>, HandlerError> {
    match try_request_context::<ResolvedNamespace>(cx) {
        Some(ResolvedNamespace::Exists(ns)) => Ok(Some(ns.clone())),
        Some(ResolvedNamespace::NotFound { .. }) => Ok(None),
        Some(ResolvedNamespace::NoNamespace) | None => {
            Err(HandlerError::bad_request("no namespace in request path"))
        }
    }
}

/// Collect (name, kappa_string) pairs in [lower, upper) via cursor-based
/// iteration in batches of RANGE_BATCH_SIZE. An absent namespace holds no
/// pairs. An empty `upper` leaves the range unbounded above.
fn collect_range(
    s: &dyn KappaStore,
    ns: Option<&NamespaceRef>,
    lower: &str,
    upper: &str,
) -> Result<Vec<(String, String)>, HandlerError> {
    let mut result = Vec::new();
    let Some(ns) = ns else {
        return Ok(result);
    };
    // tag_list returns names strictly after the cursor, and no string is
    // constructible as the immediate predecessor of `lower`, so iteration
    // starts at the first tag and names below `lower` are skipped.
    let mut cursor: Option<String> = None;

    loop {
        let page = s.tag_list(
            ns,
            None,
            &PageRequest {
                limit: RANGE_BATCH_SIZE,
                after: cursor.clone(),
            },
        )?;
        if page.items.is_empty() {
            break;
        }

        for tag in &page.items {
            if tag.name.starts_with('_') {
                continue;
            }
            if tag.name.as_str() < lower {
                continue;
            }
            if !upper.is_empty() && tag.name.as_str() >= upper {
                break;
            }
            result.push((tag.name.clone(), tag.kappa.to_string()));
        }

        // If the last tag in the page is >= upper, we are done.
        if let Some(last) = page.items.last()
            && !upper.is_empty()
            && last.name.as_str() >= upper
        {
            break;
        }

        match page.next_after {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    Ok(result)
}

/// Compute the shared additive fingerprint over (name=kappa) pairs.
/// Two nodes with identical tags in the same range produce the
/// same fingerprint. The fingerprint includes both name and kappa
/// so two namespaces with the same kappas under different names
/// produce different fingerprints.
fn range_fingerprint(items: &[(String, String)]) -> Result<[u8; 32], HandlerError> {
    let mut digest = kappa_types::StateDigest::default();
    for (name, kappa) in items {
        let kappa = kappa_types::Kappa::parse(kappa)
            .map_err(|error| HandlerError::bad_request(error.to_string()))?;
        digest.insert(name, &kappa);
    }
    Ok(digest.into_bytes())
}

async fn handle_fingerprint(
    cx: &Cx,
    ns: Option<NamespaceRef>,
    v: &serde_json::Value,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| HandlerError::bad_request("missing lower"))?
        .to_string();
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| HandlerError::bad_request("missing upper"))?
        .to_string();
    let peer_fp_hex = v["fingerprint"]
        .as_str()
        .ok_or_else(|| HandlerError::bad_request("missing fingerprint"))?
        .to_string();

    let s = store(cx);
    let lo = lower.clone();
    let up = upper.clone();

    let (our_fp, items) = blocking(move || -> Result<_, HandlerError> {
        let items = collect_range(&*s, ns.as_ref(), &lo, &up)?;
        let fp = range_fingerprint(&items)?;
        Ok((fp, items))
    })
    .await?;

    let peer_fp = hex::decode(&peer_fp_hex)
        .map_err(|_| HandlerError::bad_request("invalid fingerprint hex"))?;

    if peer_fp.len() == 32 && our_fp[..] == peer_fp[..] {
        return json_response(
            StatusCode::OK,
            &serde_json::json!({"type": "done", "lower": lower, "upper": upper}),
        );
    }

    if items.len() <= PAYLOAD_THRESHOLD {
        let kappas: Vec<&str> = items.iter().map(|(_, k)| k.as_str()).collect();
        return json_response(
            StatusCode::OK,
            &serde_json::json!({
                "type": "items",
                "lower": lower,
                "upper": upper,
                "items": kappas,
            }),
        );
    }

    // Subdivide into RANGE_DIVISION sub-ranges with lexicographic boundaries.
    let chunk_size = items.len().div_ceil(RANGE_DIVISION);
    let chunks: Vec<&[(String, String)]> = items.chunks(chunk_size).collect();
    let mut sub_ranges = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let sub_lower = if i == 0 {
            lower.clone()
        } else {
            chunk[0].0.clone()
        };
        let sub_upper = match chunks.get(i + 1) {
            Some(next) => next[0].0.clone(),
            None => upper.clone(),
        };
        let sub_fp = range_fingerprint(chunk)?;
        sub_ranges.push(serde_json::json!({
            "type": "fingerprint",
            "lower": sub_lower,
            "upper": sub_upper,
            "fingerprint": hex::encode(sub_fp),
            "count": chunk.len(),
        }));
    }

    json_response(
        StatusCode::OK,
        &serde_json::json!({"type": "subdivide", "ranges": sub_ranges}),
    )
}

async fn handle_items_request(
    cx: &Cx,
    ns: Option<NamespaceRef>,
    v: &serde_json::Value,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| HandlerError::bad_request("lower must be a string"))?
        .to_string();
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| HandlerError::bad_request("upper must be a string"))?
        .to_string();

    let s = store(cx);

    let kappas = blocking(move || -> Result<_, HandlerError> {
        let items = collect_range(&*s, ns.as_ref(), &lower, &upper)?;
        let kappas: Vec<String> = items.into_iter().map(|(_, k)| k).collect();
        Ok(kappas)
    })
    .await?;

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "type": "items",
            "lower": v["lower"],
            "upper": v["upper"],
            "items": kappas,
        }),
    )
}

async fn handle_items(
    cx: &Cx,
    ns: Option<NamespaceRef>,
    v: &serde_json::Value,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| HandlerError::bad_request("lower must be a string"))?
        .to_string();
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| HandlerError::bad_request("upper must be a string"))?
        .to_string();
    let peer_items: Vec<String> = v["items"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let s = store(cx);

    let new_for_peer = blocking(move || -> Result<_, HandlerError> {
        let our_items = collect_range(&*s, ns.as_ref(), &lower, &upper)?;
        let peer_set: std::collections::HashSet<&str> =
            peer_items.iter().map(String::as_str).collect();
        Ok(our_items
            .into_iter()
            .map(|(_, k)| k)
            .filter(|k| !peer_set.contains(k.as_str()))
            .collect::<Vec<_>>())
    })
    .await?;

    json_response(
        StatusCode::OK,
        &serde_json::json!({
            "type": "items",
            "lower": v["lower"],
            "upper": v["upper"],
            "items": new_for_peer,
        }),
    )
}
