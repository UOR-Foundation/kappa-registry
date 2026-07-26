pub mod auth;
pub mod bundle;
pub mod config;
pub mod crypto;
pub mod delta;
pub mod events;
pub mod handlers;
pub mod identity;
pub mod kappa;
pub mod ratelimit;
pub mod reconcile;
pub mod store;
pub mod transaction;
pub mod urls;

use std::borrow::Cow;
use std::sync::Arc;

use topcoat::context::CxBuilder;
use topcoat::router::{Body, LayerFn, Method, Methods, Next, Path, RouteFn, Router};

use crate::handlers::upload::SessionStore;
use crate::ratelimit::{OpClass, TieredRateLimiter};
use crate::store::fs::FsStore;
use crate::transaction::TransactionManager;

/// Build the registry router with all routes, layers, and app context.
pub fn router(
    store: Arc<FsStore>,
    sessions: Arc<SessionStore>,
    transactions: Arc<TransactionManager>,
    rate_limiter: Option<TieredRateLimiter>,
    signer: Option<Arc<dyn crate::crypto::RegistrySigner>>,
    max_blob_size: usize,
    upload_timeout_secs: u64,
) -> Router {
    let mut builder = Router::builder();

    // App context: type-keyed singletons accessible from any handler via
    // app_context::<T>(cx).
    builder = builder
        .app_context(store)
        .app_context(sessions)
        .app_context(transactions)
        .app_context(MaxBlobSize(max_blob_size))
        .app_context(UploadTimeout(upload_timeout_secs))
        .app_context(SignerHolder(signer));

    if let Some(limiter) = rate_limiter {
        builder = builder.app_context(limiter);
    }

    // Warning header layer at root -- wraps every response.
    builder = builder.layer(LayerFn::new(Cow::Borrowed(Path::new("/")), warning_layer));

    // Rate limiting layer at root -- wraps every route.
    builder = builder.layer(LayerFn::new(
        Cow::Borrowed(Path::new("/")),
        rate_limit_layer,
    ));

    // -- Health and version (exempt from rate limiting by OpClass::Exempt) --
    builder = builder
        .route(RouteFn::new(Methods::Any, p("/v2"), handlers::version))
        .route(RouteFn::new(Methods::Any, p("/v2/"), handlers::version))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/_health/{probe}"),
            handlers::health,
        ));

    // -- Uploads (global, not namespace-scoped) --
    builder = builder
        .route(RouteFn::new(
            Method::PATCH,
            p("/v2/_uploads/{id}"),
            handlers::upload::chunk_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/_uploads/{id}"),
            handlers::upload::recovery_route,
        ))
        .route(RouteFn::new(
            Method::PUT,
            p("/v2/_uploads/{id}"),
            handlers::upload::complete_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            p("/v2/_uploads/{id}"),
            handlers::upload::cancel_route,
        ));

    // -- Blobs --
    builder = builder
        .route(RouteFn::new(
            Method::PUT,
            p("/v2/{*ns}/blobs/{kappa}"),
            handlers::blob::put_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/blobs/{kappa}"),
            handlers::blob::get_route,
        ))
        .route(RouteFn::new(
            Method::HEAD,
            p("/v2/{*ns}/blobs/{kappa}"),
            handlers::blob::head_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            p("/v2/{*ns}/blobs/{kappa}"),
            handlers::blob::delete_route,
        ));

    // -- Blob list, meta, cascade --
    builder = builder
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/blobs/"),
            handlers::blob::list_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/blobs/_meta"),
            handlers::blob::meta_list_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/blobs/_cascade"),
            handlers::cascade_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/blobs/uploads/"),
            handlers::upload::start_route,
        ));

    // -- Manifests --
    builder = builder
        .route(RouteFn::new(
            Method::PUT,
            p("/v2/{*ns}/manifests/{reference}"),
            handlers::tag::manifest_put_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/manifests/{reference}"),
            handlers::tag::manifest_get_route,
        ))
        .route(RouteFn::new(
            Method::HEAD,
            p("/v2/{*ns}/manifests/{reference}"),
            handlers::tag::manifest_head_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            p("/v2/{*ns}/manifests/{reference}"),
            handlers::tag::manifest_delete_route,
        ));

    // -- Tags --
    builder = builder
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/tags/list"),
            handlers::tag::tag_list_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/tags/_batch"),
            handlers::tag::tag_batch_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            p("/v2/{*ns}/tags/_prefix"),
            handlers::tag::tag_delete_prefix_route,
        ))
        .route(RouteFn::new(
            &[Method::POST, Method::GET, Method::DELETE],
            p("/v2/{*ns}/tags/"),
            handlers::tag::tag_crud_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/tags/{name}"),
            handlers::tag::tag_get_route,
        ))
        .route(RouteFn::new(
            Method::PUT,
            p("/v2/{*ns}/tags/{name}"),
            handlers::tag::tag_put_route,
        ));

    // -- Referrers --
    builder = builder.route(RouteFn::new(
        Method::GET,
        p("/v2/{*ns}/referrers/{digest}"),
        handlers::referrers::list_route,
    ));

    // -- Edges --
    builder = builder
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/edges/_diff"),
            handlers::edge::diff_route,
        ))
        .route(RouteFn::new(
            Method::PUT,
            p("/v2/{*ns}/edges/"),
            handlers::edge::put_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/edges/{edge_key}"),
            handlers::edge::query_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            p("/v2/{*ns}/edges/{edge_key}"),
            handlers::edge::delete_route,
        ));

    // -- Compose and witnesses --
    builder = builder
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/compose/{op}"),
            handlers::compose::compose_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/witnesses/{kappa}"),
            handlers::compose::witness_route,
        ));

    // -- Schemas --
    builder = builder
        .route(RouteFn::new(
            Method::PUT,
            p("/v2/{*ns}/schemas/{scope}"),
            handlers::schema::register_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/schemas/{scope}"),
            handlers::schema::get_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/schemas/"),
            handlers::schema::list_route,
        ));

    // -- GC --
    builder = builder
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/gc/pin"),
            handlers::gc::pin_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/gc/unpin"),
            handlers::gc::unpin_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/gc/sweep"),
            handlers::gc::sweep_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/gc/status"),
            handlers::gc::status_route,
        ));

    // -- Filters --
    builder = builder
        .route(RouteFn::new(
            Method::PUT,
            p("/v2/{*ns}/filters/{filter_key}"),
            handlers::filter::register_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/filters/"),
            handlers::filter::list_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            p("/v2/{*ns}/filters/{filter_key}"),
            handlers::filter::delete_route,
        ));

    // -- Bundles --
    builder = builder
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/_bundle/create"),
            handlers::bundle::create_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/_bundle/ingest"),
            handlers::bundle::ingest_route,
        ));

    // -- Transactions --
    builder = builder
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/_transaction/begin"),
            handlers::transaction::begin_route,
        ))
        .route(RouteFn::new(
            Method::PUT,
            p("/v2/{*ns}/_transaction/{id}/{kappa}"),
            handlers::transaction::put_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/_transaction/{id}/commit"),
            handlers::transaction::commit_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            p("/v2/{*ns}/_transaction/{id}"),
            handlers::transaction::abort_route,
        ));

    // -- Reconcile --
    builder = builder.route(RouteFn::new(
        Method::POST,
        p("/v2/{*ns}/_reconcile"),
        handlers::reconcile::handle_route,
    ));

    // -- Sequences --
    builder = builder
        .route(RouteFn::new(
            Method::POST,
            p("/v2/{*ns}/_sequence/{name}/next"),
            handlers::sequence_next_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/_sequence/{name}"),
            handlers::sequence_current_route,
        ));

    // -- Namespace root and proof --
    builder = builder
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/_root/proof/{name}"),
            handlers::namespace_proof_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/{*ns}/_root"),
            handlers::namespace_root_route,
        ));

    builder.build()
}

// -- App context wrapper types --

/// Wrapper so max_blob_size can be registered as app_context.
#[derive(Clone, Copy)]
pub struct MaxBlobSize(pub usize);

/// Wrapper so upload_timeout_secs can be registered as app_context.
#[derive(Clone, Copy)]
pub struct UploadTimeout(pub u64);

/// Wrapper for the optional signer so it can be registered as a single
/// app_context type regardless of whether signing is configured.
pub struct SignerHolder(pub Option<Arc<dyn crate::crypto::RegistrySigner>>);

// -- Helper --

fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

// -- Warning header layer --

fn warning_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let mut response = next.run(cx, body).await?;
        response
            .headers_mut()
            .insert("warning", "299 - \"kappa-registry\"".parse().unwrap());
        Ok(response)
    })
}

// -- Rate limiting layer --
//
// Classifies each request by HTTP method into an OpClass, extracts the
// client IP from headers, and checks the tiered rate limiter. Exempt
// paths (/v2/, /v2, /v2/_health/*) are identified by URI. If the limiter
// rejects the request, the 429 response is returned directly. On success,
// rate limit headers are attached to the response after the inner chain
// completes.

fn rate_limit_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        // Check if a limiter is registered (rate limiting may be disabled).
        let snapshot =
            if let Some(limiter) = topcoat::context::try_app_context::<TieredRateLimiter>(cx) {
                let ip = ratelimit::extract_ip(cx);
                let uri_path = topcoat::router::uri(cx).path();
                let method = topcoat::router::method(cx);
                let op_class = classify_request(method.as_str(), uri_path);
                match limiter.check(ip, op_class) {
                    Ok(snap) => snap,
                    Err(rejection) => {
                        return Ok(*rejection);
                    }
                }
            } else {
                None
            };

        let mut response = next.run(cx, body).await?;

        if let Some(snap) = snapshot {
            ratelimit::limiter::attach_headers(&mut response, &snap);
        }

        Ok(response)
    })
}

/// Classify an HTTP request into an OpClass based on method and path.
///
/// This is an exhaustive lookup covering every registered route.
/// Adding a route to router() without a corresponding entry here
/// defaults to method-based classification (GET/HEAD=Read,
/// PUT/POST/PATCH=Write, DELETE=Admin). To maintain parity with the
/// old compile-time enforcement, audit this function when adding routes.
fn classify_request(method: &str, path: &str) -> OpClass {
    // Exempt: version check and health probes
    if path == "/v2" || path == "/v2/" || path.starts_with("/v2/_health/") {
        return OpClass::Exempt;
    }

    // Admin paths (POST/DELETE that are administrative, not content writes)
    if path.contains("/gc/pin") || path.contains("/gc/unpin") || path.contains("/gc/sweep") {
        return OpClass::Admin;
    }
    if path.contains("/_transaction/begin")
        || path.ends_with("/commit")
        || (path.contains("/_transaction/") && method == "DELETE")
    {
        return OpClass::Admin;
    }
    if path.contains("/_reconcile") {
        return OpClass::Admin;
    }
    if path.contains("/blobs/_cascade") {
        return OpClass::Admin;
    }
    if path.contains("/tags/_prefix") {
        return OpClass::Admin;
    }

    // DELETE is always Admin
    if method == "DELETE" {
        return OpClass::Admin;
    }

    // Read: GET, HEAD (covers blob get/head, manifest get/head, tag list,
    // tag get, edge query, schema get/list, filter list, gc status,
    // referrers, namespace root/proof, sequence current, blob list,
    // meta list, upload status, bundle create)
    if matches!(method, "GET" | "HEAD") {
        return OpClass::Read;
    }

    // Write: PUT, POST, PATCH (covers blob put, manifest put, tag put,
    // tag batch, tag create, edge put, schema put, filter put,
    // upload start/chunk/complete, bundle ingest, compose,
    // transaction put, sequence next)
    OpClass::Write
}
