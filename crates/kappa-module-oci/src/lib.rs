//! OCI distribution protocol module for kappa-registry.

pub mod blob;
pub mod helpers;
pub mod manifests;
pub mod referrers;
pub mod tags;
pub mod upload;

use std::borrow::Cow;

use topcoat::router::{Method, Path, RouteFn, RouterBuilder};

pub use helpers::MaxBlobSize;

// Re-export helpers for use by handler modules via crate::
pub(crate) use helpers::{
    evaluate_filters, oci_error, path_param, query_param, query_params_multi, read_body,
    registry_anchor, resolve_ns_read_async,
    resolve_ns_write_async, store, store_err, validate_schemas,
};

/// Register all OCI distribution spec routes on the router builder.
///
/// Required app_context values:
/// - Arc<dyn KappaStore>
/// - MaxBlobSize
/// - UploadTimeout
pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        // Blob metadata query
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/_meta")),
            blob::meta_list_route,
        ))
        // Blob list
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/")),
            blob::list_route,
        ))
        // Blob operations
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/{kappa}")),
            blob::put_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/{kappa}")),
            blob::get_route,
        ))
        .route(RouteFn::new(
            Method::HEAD,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/{kappa}")),
            blob::head_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/{kappa}")),
            blob::delete_route,
        ))
        // Chunked upload start (namespace-scoped)
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/uploads/")),
            upload::start_route,
        ))
        // Upload operations (global, not namespace-scoped)
        .route(RouteFn::new(
            Method::PATCH,
            Cow::Borrowed(Path::new("/v2/_uploads/{id}")),
            upload::chunk_route,
        ))
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/_uploads/{id}")),
            upload::complete_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/_uploads/{id}")),
            upload::recovery_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/_uploads/{id}")),
            upload::cancel_route,
        ))
        // Manifest operations
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/{*ns}/manifests/{reference}")),
            manifests::put_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/manifests/{reference}")),
            manifests::get_route,
        ))
        .route(RouteFn::new(
            Method::HEAD,
            Cow::Borrowed(Path::new("/v2/{*ns}/manifests/{reference}")),
            manifests::head_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/manifests/{reference}")),
            manifests::delete_route,
        ))
        // Tag list
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/list")),
            manifests::tag_list_route,
        ))
        // Tag batch
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/_batch")),
            tags::tag_batch_route,
        ))
        // Tag prefix delete
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/_prefix")),
            tags::tag_delete_prefix_route,
        ))
        // Tag CRUD
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/")),
            tags::tag_crud_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/")),
            tags::tag_crud_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/")),
            tags::tag_crud_route,
        ))
        // Tag get/put by name
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/{name}")),
            tags::tag_get_route,
        ))
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/{name}")),
            tags::tag_put_route,
        ))
        // Referrers
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/referrers/{digest}")),
            referrers::list_route,
        ))
}
