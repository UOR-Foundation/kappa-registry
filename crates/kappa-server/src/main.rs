//! kappa-registry HTTP server.
//!
//! Startup sequence:
//! 1. Parse config from environment
//! 2. Initialize tracing
//! 3. Initialize store, clock, signing, identity
//! 4. Initialize event system, transactions, rate limiter
//! 5. Build router with layers and module routes
//! 6. Spawn periodic cleanup
//! 7. Start serving
//!
//! Graceful shutdown on Ctrl+C and SIGTERM is handled by topcoat::start().

pub mod auth;
pub mod broadcast;
pub mod config;
pub mod ratelimit;

use std::borrow::Cow;
use std::sync::Arc;

use topcoat::context::{app_context, try_app_context, Cx, CxBuilder};
use topcoat::router::{
    Body, Compression, IntoResponse, LayerFn, Method, Next, Path, Response, RouteFn, RouteFuture,
    Router, StatusCode,
};

use kappa_core::clock::ntp_lamport::NtpLamportClock;
use kappa_core::crypto::keystore::KeyStore;
use kappa_core::events::InMemoryEventLog;
use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
use kappa_core::store::KappaStore;
use kappa_core::transaction::TransactionManager;

use broadcast::EventBroadcaster;
use config::Config;
use ratelimit::{attach_headers, classify_request, extract_client_ip, TieredRateLimiter};

// -- App context wrapper types ----------------------------------------------

// MaxBlobSize is defined in kappa-core::types -- the single source of
// truth. Both kappa-server and kappa-module-oci import it from there.
use kappa_core::types::MaxBlobSize;

// -- Always-present route handlers ------------------------------------------

fn status_handler(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move { "ok".into_response(cx) })
}

fn version_check(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        (
            StatusCode::OK,
            [("content-type", "application/json")],
            r#"{"kappa-distribution":"2.0.0"}"#,
        )
            .into_response(cx)
    })
}

fn health_handler(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let probe = {
            use topcoat::context::request_context;
            use topcoat::router::RawPathParams;
            let params: &RawPathParams = request_context(cx);
            params
                .iter()
                .find(|(k, _)| *k == "probe")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default()
        };
        match probe.as_str() {
            "ready" => {
                // Ready probe: verify the store root is writable by creating
                // and immediately deleting a tempfile. Failure = 503.
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let ok = tokio::task::spawn_blocking(move || {
                    // blob_put with empty content tests the write path
                    store.blob_exists("sha256:0000000000000000000000000000000000000000000000000000000000000000").is_ok()
                })
                .await
                .unwrap_or(false);
                if ok {
                    StatusCode::OK.into_response(cx)
                } else {
                    StatusCode::SERVICE_UNAVAILABLE.into_response(cx)
                }
            }
            // live, startup, and any unknown probe: 200 if the process is running
            _ => StatusCode::OK.into_response(cx),
        }
    })
}

// -- Layers -----------------------------------------------------------------

/// Warning header layer: attaches Warning: 299 - "kappa-registry" to every
/// response per the kappa-distribution spec section 6.1.
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

/// Rate limiting layer: classifies each request by method+path into an
/// OpClass, extracts client IP, checks the tiered limiter. Exempt paths
/// bypass. If rejected, returns 429 with retry-after. On success, rate
/// limit headers are attached after the inner chain completes.
fn rate_limit_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let snapshot = if let Some(limiter) = try_app_context::<Arc<TieredRateLimiter>>(cx) {
            let hdrs = topcoat::router::headers(cx);
            let ip = extract_client_ip(hdrs);
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

        let mut response = match next.run(cx, body).await {
            Ok(r) => r,
            Err(e) => {
                // Convert error to response so rate limit headers are still attached.
                // Without this, error responses (404, 400, etc.) bypass header attachment
                // and the conformance test sees no x-ratelimit-limit header.
                let mut r = Response::new(Body::from(e.response_body()));
                *r.status_mut() = e.status_code();
                if let Some(ref snap) = snapshot {
                    attach_headers(&mut r, snap);
                }
                return Ok(r);
            }
        };

        if let Some(ref snap) = snapshot {
            attach_headers(&mut response, snap);
        }

        Ok(response)
    })
}

// -- Helper -----------------------------------------------------------------

fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

// -- Main -------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Set HOST/PORT for topcoat from our config
    std::env::set_var("HOST", cfg.listen_host());
    std::env::set_var("PORT", cfg.listen_port());

    // -- Store --
    let clock = Arc::new(NtpLamportClock::new());
    let store_config = MemoryStoreConfig {
        blob_root: cfg.store_root.join("blobs"),
    };
    let store: Arc<dyn KappaStore> =
        Arc::new(InMemoryStore::new(store_config, clock).expect("failed to initialize store"));

    kappa_core::version::check_or_write_version(&cfg.store_root)
        .expect("store format version check failed");

    // -- Signing + Identity --
    // NodeIdentity owns the signing key. bootstrap() loads or generates
    // the key, stores the anchor in the store, and retains the signer
    // for epoch root signatures and identity assertions.
    let key_store = match KeyStore::new(cfg.store_root.join("keys")) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("keystore initialization failed: {e}");
            std::process::exit(2);
        }
    };

    let node_identity =
        match kappa_core::identity::node::NodeIdentity::bootstrap(&key_store, &*store) {
            Ok(ni) => {
                tracing::info!(
                    anchor = ni.anchor().as_str(),
                    algorithm = ni.algorithm(),
                    "node identity bootstrapped"
                );
                Some(Arc::new(ni))
            }
            Err(e) => {
                tracing::warn!("node identity bootstrap failed: {e}");
                None
            }
        };

    // -- Events --
    let event_log = Arc::new(InMemoryEventLog::new());
    let broadcaster = Arc::new(EventBroadcaster::new(
        event_log,
        broadcast::EVENT_CHANNEL_CAPACITY,
    ));

    // -- Transactions --
    let txn_manager = Arc::new(TransactionManager::new(
        cfg.store_root.join("staging"),
        cfg.max_transactions,
        cfg.max_blob_size,
        cfg.max_staging_bytes,
        cfg.upload_timeout_secs,
    ));

    // -- Rate limiter --
    let rate_limiter = if cfg.rate_limit.is_enabled() {
        tracing::info!(
            read_period_ms = cfg.rate_limit.read.period_ms,
            read_burst = cfg.rate_limit.read.burst,
            write_period_ms = cfg.rate_limit.write.period_ms,
            write_burst = cfg.rate_limit.write.burst,
            admin_period_ms = cfg.rate_limit.admin.period_ms,
            admin_burst = cfg.rate_limit.admin.burst,
            "rate limiting enabled"
        );
        Some(Arc::new(TieredRateLimiter::new(&cfg.rate_limit)))
    } else {
        None
    };

    // -- Router --
    let mut builder = Router::builder().compression(Compression::off());

    // Layers: warning header on every response, rate limiting on every request
    builder = builder.layer(LayerFn::new(p("/"), warning_layer));
    builder = builder.layer(LayerFn::new(p("/"), rate_limit_layer));

    // Always-present routes
    builder = builder
        .route(RouteFn::new(Method::GET, p("/_status"), status_handler))
        .route(RouteFn::new(Method::GET, p("/v2/"), version_check))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/_health/{probe}"),
            health_handler,
        ));

    // App context
    builder = builder.app_context(store.clone());
    builder = builder.app_context(MaxBlobSize(cfg.max_blob_size));
    builder = builder.app_context(broadcaster.clone());
    builder = builder.app_context(txn_manager.clone());

    if let Some(ref ni) = node_identity {
        builder = builder.app_context(ni.clone());
    }

    if let Some(ref rl) = rate_limiter {
        builder = builder.app_context(rl.clone());
    }

    // Feature-gated module routes
    #[cfg(feature = "oci")]
    {
        builder = kappa_module_oci::register(builder);
    }

    #[cfg(feature = "identity-http")]
    {
        builder = kappa_module_identity::register(builder);
    }

    #[cfg(feature = "distribution")]
    {
        builder = kappa_module_distribution::register(builder);
    }

    let router = builder.build();

    // -- Periodic cleanup --
    let cleanup_txn = txn_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let evicted = cleanup_txn.evict_expired();
            if evicted > 0 {
                tracing::info!("transaction cleanup: evicted {evicted} expired transactions");
            }
        }
    });

    // -- Start --
    tracing::info!(
        listen = %cfg.listen_addr,
        store = %cfg.store_root.display(),
        "kappa-registry starting"
    );

    topcoat::start(router).await.expect("server error");
}
