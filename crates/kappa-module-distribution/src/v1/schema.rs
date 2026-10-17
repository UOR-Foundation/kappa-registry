use topcoat::context::Cx;
use topcoat::router::{Body, Method, RouterBuilder, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, binary_response, blocking, empty_response, execute, json_response,
    path_param, prepare_body, principal, read_body, resolve_ns_read, store, take_prepared,
    write_target,
};
use kappa_store::ContentIdentity;
use kappa_store::axis::Axis;
use kappa_store::edge::{EdgeInput, EdgeRelation, SemanticRelation, semantic};
use kappa_store::tag::TagUpdate;

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(dist_route!(
            Method::PUT,
            "/v2/{*ns}/schemas/{scope}",
            put_schema
        ))
        .route(dist_route!(
            Method::GET,
            "/v2/{*ns}/schemas/{scope}",
            get_schema
        ))
        .route(dist_route!(Method::GET, "/v2/{*ns}/schemas/", list_schemas))
}

async fn put_schema(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let bytes = read_body(body, 256 * 1024).await?;
    let target = write_target(cx)?;
    let scope = path_param(cx, "scope")?;
    let asserter = principal(cx);

    let prepared =
        prepare_body(cx, ContentIdentity::Computed(Axis::Sha256), bytes.to_vec()).await?;
    // The schema content, its tag, its object type, and the derivation edge
    // from the schema it replaces publish in one epoch.
    let committed = execute(cx, target, &bytes, move |execution| {
        let tag_name = format!("_schema/{scope}");
        let old_kappa = execution.tag_get(&tag_name)?.map(|entry| entry.kappa);

        let ingest = execution.content_install(take_prepared(&prepared)?)?;
        execution.tag_put(
            &tag_name,
            &TagUpdate::Set {
                kappa: ingest.kappa.clone(),
            },
        )?;
        kappa_store::blob_meta_put_indexed(execution, &ingest.kappa, "object-type", "schema")?;

        if let Some(old_k) = old_kappa
            && old_k != ingest.kappa
        {
            let edge = EdgeInput {
                source: ingest.kappa.clone(),
                target: old_k,
                relation: EdgeRelation::Semantic(SemanticRelation(semantic::DERIVED_FROM.into())),
                created_at_ms: execution.now().as_i64(),
                asserter: asserter.clone(),
                metadata: None,
            };
            execution.edge_put(&edge)?;
        }

        Ok(Outcome::Publish(ingest.kappa))
    })
    .await?;

    let mut resp = empty_response(StatusCode::CREATED);
    resp.headers_mut().insert(
        "x-kappa-label",
        committed.value.to_string().parse().map_err(|error| {
            HandlerError::internal(format!("invalid kappa response header: {error}"))
        })?,
    );
    committed.annotate(&mut resp);
    Ok(resp)
}

async fn get_schema(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let scope = path_param(cx, "scope")?;

    let s = store(cx);
    let (kappa, content) = blocking(move || -> Result<_, kappa_store::StoreError> {
        let entry = s.tag_get(&ns, &format!("_schema/{}", scope))?;
        let data = s.blob_get_in(&ns, &entry.kappa)?;
        Ok((entry.kappa, data))
    })
    .await?;

    let mut resp = binary_response(StatusCode::OK, "application/octet-stream", content)?;
    resp.headers_mut().insert(
        "x-kappa-label",
        kappa.to_string().parse().map_err(|error| {
            HandlerError::internal(format!("invalid kappa response header: {error}"))
        })?,
    );
    Ok(resp)
}

async fn list_schemas(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;

    let s = store(cx);
    let schemas = blocking(move || -> Result<_, kappa_store::StoreError> {
        let tags = crate::listing::tags(&*s, &ns, Some("_schema/"))?;
        let records: Vec<serde_json::Value> = tags
            .iter()
            .map(|t| {
                let scope = t.name.strip_prefix("_schema/").unwrap_or(&t.name);
                serde_json::json!({"scope": scope, "kappa": t.kappa.to_string()})
            })
            .collect();
        Ok(serde_json::json!({"schemas": records}))
    })
    .await?;

    json_response(StatusCode::OK, &schemas)
}
