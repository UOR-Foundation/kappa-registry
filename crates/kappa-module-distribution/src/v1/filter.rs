use topcoat::context::Cx;
use topcoat::router::{Body, Method, RouterBuilder, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, Prepared, blocking, empty_response, execute, json_response, path_param,
    prepare_body, read_body, resolve_ns_read, store, take_prepared, write_target,
};
use kappa_store::axis::Axis;
use kappa_store::kappa::Kappa;
use kappa_store::tag::TagUpdate;
use kappa_store::{ContentIdentity, Execution};

const FILTER_PREFIX: &str = "_filter/";

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(dist_route!(
            Method::PUT,
            "/v2/{*ns}/filters/{filter_key}",
            put_filter
        ))
        .route(dist_route!(Method::GET, "/v2/{*ns}/filters/", list_filters))
        .route(dist_route!(
            Method::DELETE,
            "/v2/{*ns}/filters/{filter_key}",
            delete_filter
        ))
}

/// Execution work installing the `prepared` filter content and binding it
/// to `scope`. The content, its tag, and its object type publish in one
/// epoch.
pub fn install_filter(
    scope: String,
    prepared: Prepared,
) -> impl FnMut(&mut dyn Execution) -> Result<Outcome<Kappa>, HandlerError> + Send + 'static {
    move |execution| {
        let ingest = execution.content_install(take_prepared(&prepared)?)?;
        execution.tag_put(
            &format!("{FILTER_PREFIX}{scope}"),
            &TagUpdate::Set {
                kappa: ingest.kappa.clone(),
            },
        )?;
        kappa_store::blob_meta_put_indexed(execution, &ingest.kappa, "object-type", "filter")?;
        Ok(Outcome::Publish(ingest.kappa))
    }
}

/// Execution work removing the filter bound to `scope`. A filter that does
/// not exist is `NotFound`; the absence is read without latching, and the
/// discarded execution publishes nothing.
pub fn remove_filter(
    scope: String,
) -> impl FnMut(&mut dyn Execution) -> Result<Outcome<()>, HandlerError> + Send + 'static {
    move |execution| {
        let tag_name = format!("{FILTER_PREFIX}{scope}");
        if execution.tag_get_raw(&tag_name)?.is_none() {
            return Err(HandlerError::not_found(format!("filter {scope} not found")));
        }
        execution.tag_delete(&tag_name)?;
        Ok(Outcome::Publish(()))
    }
}

async fn put_filter(
    cx: &Cx,
    body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let bytes = read_body(body, 256 * 1024).await?;
    let target = write_target(cx)?;
    let scope = path_param(cx, "filter_key")?;
    let prepared =
        prepare_body(cx, ContentIdentity::Computed(Axis::Sha256), bytes.to_vec()).await?;

    let committed = execute(cx, target, &bytes, install_filter(scope, prepared)).await?;

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

async fn list_filters(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;

    let s = store(cx);
    let filters = blocking(move || -> Result<_, kappa_store::StoreError> {
        let tags = crate::listing::tags(&*s, &ns, Some(FILTER_PREFIX))?;
        let records: Vec<serde_json::Value> = tags
            .iter()
            .map(|t| {
                let scope = t.name.strip_prefix(FILTER_PREFIX).unwrap_or(&t.name);
                serde_json::json!({"scope": scope, "kappa": t.kappa.to_string()})
            })
            .collect();
        Ok(serde_json::json!({"filters": records}))
    })
    .await?;

    json_response(StatusCode::OK, &filters)
}

async fn delete_filter(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = write_target(cx)?;
    let filter_key = path_param(cx, "filter_key")?;

    let committed = execute(cx, target, &[], remove_filter(filter_key)).await?;

    let mut response = empty_response(StatusCode::ACCEPTED);
    committed.annotate(&mut response);
    Ok(response)
}
