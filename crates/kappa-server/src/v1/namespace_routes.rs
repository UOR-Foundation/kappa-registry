use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::{Body, Method, Path, RouterBuilder, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, WriteTarget, blocking, caller_anchor, clock_now, empty_response,
    execute, json_response, page_request_from, query_optional, query_optional_parsed,
    read_json_with_bytes, resolve_ns_read, store,
};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::ProtocolId;
use kappa_store::page::NamespaceFilter;

fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

/// Namespace management route macro. Uses the shared handler_route!
/// with kappa-handler's error_response as the error formatter.
/// Namespace endpoints use {"error":"..."} format — the same format
/// error_response produces.
macro_rules! ns_route {
    ($method:expr, $path:expr, $handler:ident) => {
        kappa_handler::handler_route!($method, p($path), $handler, kappa_handler::error_response)
    };
}

// ---------------------------------------------------------------------------
// GET /v2/{*ns}/_namespace/info
// Body: not consumed. GET endpoint.
// ---------------------------------------------------------------------------

async fn namespace_info_handler(
    cx: &Cx,
    _body: Body, // GET — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let s = store(cx);
    let info = blocking(move || s.namespace_info(&ns)).await?;
    json_response(StatusCode::OK, &info)
}

// ---------------------------------------------------------------------------
// POST /v2/{*ns}/_namespace/create
// Body: {"owner": "sha256:...", "protocol": "oci", "metadata": {"key": "value"}}
// All fields optional. Owner defaults to caller anchor. Protocol defaults
// to interceptor detection. Metadata stored via namespace_put_meta after creation.
// ---------------------------------------------------------------------------

async fn namespace_create_handler(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let bytes = kappa_handler::read_body(body, 64 * 1024).await?;
    let req: Option<serde_json::Value> = if bytes.is_empty() {
        None
    } else {
        Some(
            serde_json::from_slice(&bytes)
                .map_err(|error| HandlerError::bad_request(error.to_string()))?,
        )
    };

    let body_owner: Option<Kappa> = req
        .as_ref()
        .and_then(|v| v.get("owner"))
        .and_then(|v| v.as_str())
        .map(Kappa::parse)
        .transpose()?;

    let body_protocol: Option<ProtocolId> = req
        .as_ref()
        .and_then(|v| v.get("protocol"))
        .and_then(|v| v.as_str())
        .map(|s| {
            ProtocolId::new(s)
                .map_err(|_| HandlerError::bad_request(format!("invalid protocol: {s}")))
        })
        .transpose()?;

    let metadata: Option<serde_json::Map<String, serde_json::Value>> = req
        .as_ref()
        .and_then(|v| v.get("metadata"))
        .and_then(|v| v.as_object())
        .cloned();

    // Owner priority: body > caller anchor > None (anonymous)
    let owner = body_owner.or_else(|| caller_anchor(cx));

    // Protocol priority: body > interceptor detection
    let resolved = topcoat::context::try_request_context::<kappa_handler::ResolvedNamespace>(cx)
        .cloned()
        .unwrap_or(kappa_handler::ResolvedNamespace::NoNamespace);

    let (name, detected_protocol) = match resolved {
        kappa_handler::ResolvedNamespace::NotFound { name, protocol } => (name, protocol),
        kappa_handler::ResolvedNamespace::Exists(_) => {
            return Err(HandlerError::Conflict {
                reason: "namespace already exists".into(),
            });
        }
        kappa_handler::ResolvedNamespace::NoNamespace => {
            return Err(HandlerError::bad_request("no namespace in path"));
        }
    };

    let protocol = body_protocol.or(detected_protocol);
    let target = WriteTarget::create(&name, owner.clone(), protocol, clock_now(cx)?)?;
    let created = *target.namespace().id();

    // The namespace and its initial metadata publish in one epoch.
    let committed = execute(cx, target, &bytes, move |execution| {
        // A concurrent creator won the alias; this request did not create
        // the namespace and must not write into it.
        if execution.namespace().id() != &created {
            return Err(HandlerError::Conflict {
                reason: "namespace already exists".into(),
            });
        }
        for (key, value) in metadata.iter().flatten() {
            execution.namespace_put_meta(key, value.to_string().as_bytes())?;
        }
        Ok(Outcome::Publish(()))
    })
    .await?;

    let info = serde_json::json!({
        "uuid": committed.namespace.uuid_hex(),
        "name": committed.namespace.display_name(),
        "owner": owner,
    });
    let mut response = json_response(StatusCode::CREATED, &info)?;
    committed.annotate(&mut response);
    Ok(response)
}

/// Publish one namespace-lifecycle change against the request's existing
/// namespace and respond with `status`.
async fn lifecycle<F>(
    cx: &Cx,
    payload: &[u8],
    status: StatusCode,
    change: F,
) -> Result<topcoat::router::response::Response, HandlerError>
where
    F: FnMut(&mut dyn kappa_store::Execution) -> Result<(), kappa_store::StoreError>
        + Send
        + 'static,
{
    let target = WriteTarget::existing(resolve_ns_read(cx)?);
    let mut change = change;
    let committed = execute(cx, target, payload, move |execution| {
        change(execution)?;
        Ok(Outcome::Publish(()))
    })
    .await?;
    let mut response = empty_response(status);
    committed.annotate(&mut response);
    Ok(response)
}

// ---------------------------------------------------------------------------
// POST /v2/{*ns}/_namespace/rename
// Body: {"new_name": "..."}
// ---------------------------------------------------------------------------

async fn namespace_rename_handler(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, 64 * 1024).await?;
    let new_name = req
        .get("new_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::bad_request("missing new_name"))?
        .to_string();
    lifecycle(cx, &raw, StatusCode::OK, move |execution| {
        execution.namespace_rename(&new_name)
    })
    .await
}

// ---------------------------------------------------------------------------
// POST /v2/{*ns}/_namespace/transfer
// Body: {"new_owner": "sha256:..."}
// ---------------------------------------------------------------------------

async fn namespace_transfer_handler(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, 64 * 1024).await?;
    let new_owner_str = req
        .get("new_owner")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::bad_request("missing new_owner"))?;
    let new_owner = Kappa::parse(new_owner_str)?;
    lifecycle(cx, &raw, StatusCode::OK, move |execution| {
        execution.namespace_transfer(&new_owner)
    })
    .await
}

// ---------------------------------------------------------------------------
// DELETE /v2/{*ns}/_namespace
// Body: {"reason": "compliance-expired"} (optional)
// Reason stored as namespace metadata for audit trail.
// ---------------------------------------------------------------------------

async fn namespace_delete_handler(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let raw = kappa_handler::read_body(body, 64 * 1024).await?;
    // The body is optional; when present it must be a JSON object.
    let reason: Option<String> = if raw.is_empty() {
        None
    } else {
        serde_json::from_slice::<serde_json::Value>(&raw)
            .map_err(|error| HandlerError::bad_request(format!("invalid JSON: {error}")))?
            .get("reason")
            .and_then(|r| r.as_str())
            .map(str::to_string)
    };
    // The audit reason and the tombstone publish in the same epoch.
    lifecycle(cx, &raw, StatusCode::NO_CONTENT, move |execution| {
        if let Some(reason) = &reason {
            execution.namespace_put_meta("_delete_reason", reason.as_bytes())?;
        }
        execution.namespace_delete()
    })
    .await
}

// ---------------------------------------------------------------------------
// POST /v2/{*ns}/_namespace/alias
// Body: {"alias": "...", "protocol": "oci"} (protocol optional)
// ---------------------------------------------------------------------------

async fn namespace_add_alias_handler(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, 64 * 1024).await?;
    let alias = req
        .get("alias")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::bad_request("missing alias"))?
        .to_string();
    let protocol: Option<ProtocolId> = req
        .get("protocol")
        .and_then(|v| v.as_str())
        .map(|s| {
            ProtocolId::new(s)
                .map_err(|_| HandlerError::bad_request(format!("invalid protocol: {s}")))
        })
        .transpose()?;
    lifecycle(cx, &raw, StatusCode::CREATED, move |execution| {
        execution.namespace_add_alias(&alias, protocol.as_ref())
    })
    .await
}

// ---------------------------------------------------------------------------
// GET /v2/_namespaces
// Body: not consumed. GET endpoint.
// Query params: protocol, owner, tombstoned, created_after, last_epoch_after,
//               limit, cursor
// ---------------------------------------------------------------------------

async fn namespace_list_handler(
    cx: &Cx,
    _body: Body, // GET — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let page_req = page_request_from(cx, 100)?;

    let query_protocol: Option<ProtocolId> =
        query_optional(cx, "protocol").and_then(|s| ProtocolId::new(&s).ok());
    let query_owner: Option<Kappa> = query_optional(cx, "owner")
        .map(|s| Kappa::parse(&s))
        .transpose()?;
    let query_tombstoned: Option<bool> = query_optional_parsed(cx, "tombstoned")?;
    let query_created_after: Option<i64> = query_optional_parsed(cx, "created_after")?;
    let query_last_epoch_after: Option<u64> = query_optional_parsed(cx, "last_epoch_after")?;

    let filter = NamespaceFilter {
        protocol: query_protocol,
        owner_anchor: query_owner,
        tombstoned: query_tombstoned,
        created_after_ms: query_created_after,
        last_epoch_after: query_last_epoch_after,
    };

    let s = store(cx);
    let page = blocking(move || s.namespace_list(&filter, &page_req)).await?;

    let response = serde_json::json!({
        "items": page.items,
        "cursor": page.next_after,
    });
    json_response(StatusCode::OK, &response)
}

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(ns_route!(
            Method::POST,
            "/v2/{*ns}/_namespace/create",
            namespace_create_handler
        ))
        .route(ns_route!(
            Method::GET,
            "/v2/{*ns}/_namespace/info",
            namespace_info_handler
        ))
        .route(ns_route!(
            Method::POST,
            "/v2/{*ns}/_namespace/rename",
            namespace_rename_handler
        ))
        .route(ns_route!(
            Method::POST,
            "/v2/{*ns}/_namespace/transfer",
            namespace_transfer_handler
        ))
        .route(ns_route!(
            Method::DELETE,
            "/v2/{*ns}/_namespace",
            namespace_delete_handler
        ))
        .route(ns_route!(
            Method::POST,
            "/v2/{*ns}/_namespace/alias",
            namespace_add_alias_handler
        ))
        .route(ns_route!(
            Method::GET,
            "/v2/_namespaces",
            namespace_list_handler
        ))
}
