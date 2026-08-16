//! S3 virtual-hosted-style routing via pre-routing URI rewrite.
//!
//! `topcoat::serve`/`start` route by path before any layer runs, so a
//! topcoat Layer cannot change which route matches. This module provides
//! `serve_with_vhost` which mirrors topcoat's `internal_serve` accept
//! loop but wraps `Router::handle` with a URI rewrite when the Host
//! header contains a subdomain of the configured base domain.
//!
//! Config: KAPPA_S3_BASE_DOMAIN env var.
//!   "localhost"        -> mybucket.localhost:5000/key -> /mybucket/key
//!   "s3.registry.local" -> mybucket.s3.registry.local/key -> /mybucket/key
//!   unset/empty        -> no rewrite, path-style only
//!
//! The rewrite prepends /{bucket} to the path so the router matches
//! /{bucket}/{key} normally. OCI paths (/v2/...), Git paths (/{repo}.git/...),
//! and system paths (/_status, /docs, /openapi.json) are never rewritten
//! because they don't arrive on the vhost subdomain.

use std::convert::Infallible;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use tokio::sync::watch;

use topcoat::router::response::Response;
use topcoat::router::{Body, Listener, Router};

/// Extract the bucket name from a Host header value given a base domain.
///
/// Returns Some(bucket) if Host is `{bucket}.{base_domain}` or
/// `{bucket}.{base_domain}:{port}`. Returns None otherwise.
/// Rejects nested subdomains (bucket cannot contain dots).
fn extract_bucket(host: &str, base_domain: &str) -> Option<String> {
    if base_domain.is_empty() {
        return None;
    }
    let host_no_port = host.split(':').next().unwrap_or(host);
    let suffix = format!(".{}", base_domain);
    host_no_port
        .strip_suffix(&suffix)
        .filter(|bucket| !bucket.is_empty() && !bucket.contains('.'))
        .map(|b| b.to_string())
}

/// Rewrite the URI of a request, prepending /{bucket} to the path.
fn rewrite_uri(
    parts: &mut http::request::Parts,
    bucket: &str,
) {
    let original_path = parts.uri.path().to_string();
    let original_query = parts.uri.query();
    let new_path = format!("/{}{}", bucket, original_path);
    let pq = match original_query {
        Some(q) => format!("{}?{}", new_path, q),
        None => new_path,
    };
    if let Ok(new_uri) = http::Uri::builder().path_and_query(pq).build() {
        parts.uri = new_uri;
    }
}

/// Serve a router with virtual-hosted-style S3 URI rewriting.
///
/// Mirrors topcoat's `internal_serve` accept loop but intercepts each
/// request before `router.handle()` to rewrite the URI when the Host
/// header contains a subdomain of `base_domain`.
///
/// When `base_domain` is empty, no rewriting occurs (path-style only).
/// In that case this is functionally identical to `topcoat::serve`.
pub async fn serve_with_vhost(
    mut listener: impl Listener,
    router: Router,
    base_domain: String,
    shutdown_timeout: Duration,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let router = Arc::new(router);
    let (drain_tx, drain_rx) = watch::channel(());
    let (cutoff_tx, cutoff_rx) = watch::channel(());
    let (done_tx, done_rx) = watch::channel(());

    let mut shutdown = pin!(shutdown);

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut shutdown => break,
        };
        let (stream, _remote) = accepted?;
        let io = TokioIo::new(stream);
        let router = router.clone();
        let base_domain = base_domain.clone();

        let mut drain_rx = drain_rx.clone();
        let mut cutoff_rx = cutoff_rx.clone();
        let done_rx = done_rx.clone();

        tokio::spawn(async move {
            let _done_rx = done_rx;

            let service = hyper::service::service_fn(move |request: http::Request<Incoming>| {
                let router = router.clone();
                let base_domain = base_domain.clone();
                async move {
                    let (mut parts, body) = request.into_parts();

                    // Vhost rewrite: if Host has a subdomain of base_domain,
                    // prepend /{bucket} to the path before routing.
                    if !base_domain.is_empty() {
                        if let Some(host) = parts.headers.get("host")
                            .and_then(|v| v.to_str().ok())
                        {
                            if let Some(bucket) = extract_bucket(host, &base_domain) {
                                rewrite_uri(&mut parts, &bucket);
                            }
                        }
                    }

                    // Git rewrite: .git/ paths -> /_git/ internal prefix.
                    // Must happen before routing because topcoat resolves
                    // the route from the URI before any layer runs.
                    if let Some(new_uri) = super::git_rewrite::rewrite_git_path(&parts.uri) {
                        parts.uri = new_uri;
                    }

                    // Nix rewrite: /nix/ paths -> /_nix/ internal prefix.
                    #[cfg(feature = "nix")]
                    if let Some(new_uri) = super::nix_rewrite::rewrite_nix_path(&parts.uri) {
                        parts.uri = new_uri;
                    }

                    let request = http::Request::from_parts(parts, body);
                    let response: Response = router.handle(request.map(Body::new)).await;
                    Ok::<_, Infallible>(response)
                }
            });

            let builder = auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            let mut connection = pin!(builder.serve_connection_with_upgrades(io, service));

            let result = tokio::select! {
                result = connection.as_mut() => result,
                _ = drain_rx.changed() => {
                    connection.as_mut().graceful_shutdown();
                    tokio::select! {
                        result = connection.as_mut() => result,
                        _ = cutoff_rx.changed() => return,
                    }
                }
            };

            if let Err(e) = result {
                tracing::debug!("connection error: {e}");
            }
        });
    }

    // Graceful shutdown: signal drain, wait for connections or timeout, signal cutoff.
    // Drop drain_tx to tell all connections to start graceful shutdown.
    // Then wait up to shutdown_timeout for them to finish. If all connections
    // are already done (no active senders on done_rx), skip the wait.
    drop(drain_tx);
    drop(done_tx);
    // If done_rx.has_changed() returns Err, all senders are gone (no connections).
    // Otherwise wait up to shutdown_timeout for connections to drain.
    if done_rx.has_changed().is_ok() {
        tokio::time::sleep(shutdown_timeout).await;
    }
    drop(cutoff_tx);
    // Yield until all connection tasks have exited
    while done_rx.has_changed().is_ok() {
        tokio::task::yield_now().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bucket_with_subdomain() {
        assert_eq!(extract_bucket("mybucket.localhost", "localhost"), Some("mybucket".into()));
        assert_eq!(extract_bucket("mybucket.localhost:5000", "localhost"), Some("mybucket".into()));
    }

    #[test]
    fn extract_bucket_no_subdomain() {
        assert_eq!(extract_bucket("localhost", "localhost"), None);
        assert_eq!(extract_bucket("localhost:5000", "localhost"), None);
    }

    #[test]
    fn extract_bucket_wrong_domain() {
        assert_eq!(extract_bucket("mybucket.other.com", "localhost"), None);
    }

    #[test]
    fn extract_bucket_empty_base() {
        assert_eq!(extract_bucket("mybucket.localhost", ""), None);
    }

    #[test]
    fn extract_bucket_nested_subdomain_rejected() {
        assert_eq!(extract_bucket("a.b.localhost", "localhost"), None);
    }

    #[test]
    fn extract_bucket_custom_domain() {
        assert_eq!(
            extract_bucket("mybucket.s3.registry.local", "s3.registry.local"),
            Some("mybucket".into()),
        );
        assert_eq!(
            extract_bucket("mybucket.s3.registry.local:9000", "s3.registry.local"),
            Some("mybucket".into()),
        );
    }

    #[test]
    fn rewrite_uri_prepends_bucket() {
        let (mut parts, _) = http::Request::builder()
            .uri("/mykey")
            .body(())
            .unwrap()
            .into_parts();
        rewrite_uri(&mut parts, "mybucket");
        assert_eq!(parts.uri.path(), "/mybucket/mykey");
    }

    #[test]
    fn rewrite_uri_preserves_query() {
        let (mut parts, _) = http::Request::builder()
            .uri("/mykey?uploads")
            .body(())
            .unwrap()
            .into_parts();
        rewrite_uri(&mut parts, "mybucket");
        assert_eq!(parts.uri.path_and_query().unwrap().as_str(), "/mybucket/mykey?uploads");
    }

    #[test]
    fn rewrite_uri_root_path() {
        let (mut parts, _) = http::Request::builder()
            .uri("/")
            .body(())
            .unwrap()
            .into_parts();
        rewrite_uri(&mut parts, "mybucket");
        assert_eq!(parts.uri.path(), "/mybucket/");
    }
}
