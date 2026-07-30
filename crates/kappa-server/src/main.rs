//! kappa-registry HTTP server.

pub mod auth;
pub mod broadcast;
pub mod config;
pub mod layers;
pub mod ratelimit;
pub mod tls;

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use topcoat::context::{app_context, try_app_context, Cx};
use topcoat::router::{
    Body, Compression, IntoResponse, LayerFn, Method, Path, RouteFn, RouteFuture, Router,
    StatusCode,
};

use kappa_core::clock::ntp_lamport::NtpLamportClock;
use kappa_core::crypto::keystore::KeyStore;
use kappa_core::events::InMemoryEventLog;
use kappa_core::store::KappaStore;
use kappa_core::transaction::TransactionManager;
use kappa_core::types::MaxBlobSize;
use kappa_store_redb::PersistentStore;

use broadcast::EventBroadcaster;
use config::Config;
use layers::*;
use ratelimit::TieredRateLimiter;

// -- Route handlers -----------------------------------------------------------

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
                #[cfg(feature = "oci")]
                if let Some(pressure) =
                    try_app_context::<Arc<kappa_module_oci::blob::DiskPressure>>(cx)
                {
                    if pressure
                        .0
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response(cx);
                    }
                }
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let ok = tokio::task::spawn_blocking(move || {
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
            _ => StatusCode::OK.into_response(cx),
        }
    })
}

fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

/// kappa-distribution spec section 6.1: Warning header on every response.
fn kappa_warning_header(mut response: topcoat::router::Response) -> topcoat::router::Response {
    response
        .headers_mut()
        .insert("warning", "299 - \"kappa-registry\"".parse().unwrap());
    response
}

#[cfg(unix)]
fn available_bytes(path: &std::path::Path) -> Option<u64> {
    let c_path = std::ffi::CString::new(path.to_str()?).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return None;
    }
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(not(unix))]
fn available_bytes(_path: &std::path::Path) -> Option<u64> {
    None
}

// -- Main ---------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    std::env::set_var("HOST", cfg.listen_host());
    std::env::set_var("PORT", cfg.listen_port());

    // -- Store --
    let clock = Arc::new(NtpLamportClock::new());
    let blob_root = cfg.store_root.join("blobs");
    let db_path = cfg.store_root.join("state.redb");
    let store: Arc<dyn KappaStore> = Arc::new(
        PersistentStore::new(blob_root, db_path, clock.clone(), cfg.fsync)
            .expect("failed to initialize persistent store"),
    );

    kappa_core::version::check_or_write_version(&cfg.store_root)
        .expect("store format version check failed");

    // -- Signing + Identity --
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

    // -- Bearer auth --
    let bearer_auth = Arc::new(auth::BearerAuth::new(
        cfg.auth_tokens.clone(),
        cfg.auth_required,
    ));

    // -- Disk pressure monitor --
    #[cfg(feature = "oci")]
    let disk_pressure = {
        let dp = Arc::new(kappa_module_oci::blob::DiskPressure(
            std::sync::atomic::AtomicBool::new(false),
        ));
        let pressure = dp.clone();
        let store_path = cfg.store_root.clone();
        let threshold_bytes = cfg.disk_pressure_threshold_mb * 1024 * 1024;
        let interval = cfg.disk_pressure_check_interval_secs;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(interval)).await;
                let under = available_bytes(&store_path)
                    .map(|avail| avail < threshold_bytes)
                    .unwrap_or(false);
                pressure
                    .0
                    .store(under, std::sync::atomic::Ordering::Relaxed);
            }
        });
        dp
    };

    // -- TLS detection --
    let tls_config = tls::TlsConfig::from_env();

    // -- Router --
    let mut builder = Router::builder()
        .compression(Compression::off())
        .response_hook(kappa_warning_header);

    // Layer chain: outermost to innermost
    builder = builder.layer(LayerFn::new(p("/"), cache_layer));
    builder = builder.layer(LayerFn::new(p("/"), response_compliance_layer));
    builder = builder.layer(LayerFn::new(p("/"), request_id_layer));
    builder = builder.layer(LayerFn::new(p("/"), proxy_trust_layer));
    builder = builder.layer(LayerFn::new(p("/"), request_log_layer));
    builder = builder.layer(LayerFn::new(p("/"), security_headers_layer));
    builder = builder.layer(LayerFn::new(p("/"), cors_layer));
    builder = builder.layer(LayerFn::new(p("/"), timeout_layer));
    builder = builder.layer(LayerFn::new(p("/"), rate_limit_layer));
    builder = builder.layer(LayerFn::new(p("/"), body_limit_layer));
    builder = builder.layer(LayerFn::new(p("/"), auth_layer));

    // Routes
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
    builder = builder.app_context(bearer_auth);
    builder = builder.app_context(broadcaster.clone());
    builder = builder.app_context(txn_manager.clone());
    builder = builder.app_context(RequestTimeout(Duration::from_secs(
        cfg.request_timeout_secs,
    )));
    builder = builder.app_context(MaxApiBodyBytes(cfg.max_api_body_bytes));

    if let Some(proxy_header) = &cfg.proxy_trusted_header {
        builder = builder.app_context(ProxyTrustConfig {
            trusted_header: Some(proxy_header.clone()),
        });
    }

    if tls_config.is_some() {
        builder = builder.app_context(TlsEnabled);
    }

    if let Some(ref ni) = node_identity {
        builder = builder.app_context(ni.clone());
    }

    if let Some(ref rl) = rate_limiter {
        builder = builder.app_context(rl.clone());
    }

    // -- Upload session store --
    #[cfg(feature = "oci")]
    {
        builder = builder.app_context(disk_pressure.clone());
        let staging_root = cfg.store_root.join("upload-staging");
        let session_store = Arc::new(
            kappa_module_oci::upload_session::SessionStore::new(staging_root, cfg.max_blob_size),
        );
        let eviction_store = session_store.clone();
        let upload_timeout_secs = cfg.upload_timeout_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                eviction_store.evict_expired(upload_timeout_secs);
            }
        });
        builder = builder.app_context(session_store);
        builder = builder.app_context(kappa_module_oci::upload::UploadTimeout(
            cfg.upload_timeout_secs,
        ));
        builder = builder.app_context(kappa_module_oci::upload::BlobRoot(
            cfg.store_root.join("blobs"),
        ));
    }

    // Feature-gated module routes
    #[cfg(feature = "oci")]
    {
        builder = kappa_module_oci::register(builder);
    }
    #[cfg(feature = "identity-http")]
    {
        // Initialize AKD directory for identity proof generation
        let akd_manager = match kappa_akd::AkdManager::new(
            store.clone(),
            "_akd/identity".to_string(),
        )
        .await
        {
            Ok(mgr) => {
                tracing::info!("AKD directory initialized for identity proofs");
                Some(Arc::new(mgr))
            }
            Err(e) => {
                tracing::warn!("AKD directory initialization failed: {e}");
                None
            }
        };
        if let Some(ref akd) = akd_manager {
            builder = builder.app_context(akd.clone());
        }
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
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let evicted = cleanup_txn.evict_expired();
            if evicted > 0 {
                tracing::info!("transaction cleanup: evicted {evicted} expired transactions");
            }
        }
    });

    // -- Start --
    match tls_config {
        Some(tls_cfg) => {
            let acceptor = tls::build_acceptor(&tls_cfg);
            let tcp = tokio::net::TcpListener::bind(&cfg.listen_addr)
                .await
                .expect("failed to bind TCP listener for TLS");
            let listener = tls::TlsListener::new(tcp, acceptor, tls_cfg.handshake_timeout);
            tracing::info!(
                listen = %cfg.listen_addr,
                store = %cfg.store_root.display(),
                tls = true,
                mtls = tls_cfg.client_ca_path.is_some(),
                "kappa-registry starting with TLS"
            );
            topcoat::serve(listener, router)
                .await
                .expect("TLS server error");
        }
        None => {
            tracing::info!(
                listen = %cfg.listen_addr,
                store = %cfg.store_root.display(),
                "kappa-registry starting"
            );
            topcoat::start(router).await.expect("server error");
        }
    }
}
