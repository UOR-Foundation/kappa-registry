//! kappa-registry HTTP server.

pub mod auth;
pub mod broadcast;
pub mod config;
pub mod layers;
pub mod openapi;
pub mod ratelimit;
pub mod resolvers;
pub mod tls;

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use topcoat::context::{app_context, request_context, try_app_context, Cx};
use topcoat::router::response::IntoResponse;
use topcoat::router::{
    Body, Compression, LayerFn, Method, Path, RouteFn, RouteFuture, Router,
    StatusCode, raw_path_params,
};

use kappa_core::clock::ntp_lamport::NtpLamportClock;
use kappa_core::crypto::keystore::KeyStore;
use kappa_core::events::InMemoryEventLog;
use kappa_core::store::KappaStore;
use kappa_core::transaction::TransactionManager;
use kappa_core::types::{CallerIdentity, MaxBlobSize, NamespaceRef, ResolvedNamespace};
use kappa_store_redb::PersistentStore;

use auth::TrustPolicy;
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
        let probe = raw_path_params(cx)
                .find(|(k, _)| *k == "probe")
                .map(|(_, v)| v.as_str().to_string())
                .unwrap_or_default();
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

// -- Namespace create endpoint ------------------------------------------------

fn namespace_create_route(cx: &Cx, _body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let resolved = request_context::<ResolvedNamespace>(cx);
        let caller = request_context::<CallerIdentity>(cx).0.clone();
        let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

        match resolved {
            ResolvedNamespace::Exists(_) => {
                (StatusCode::CONFLICT, r#"{"error":"namespace already exists"}"#).into_response(cx)
            }
            ResolvedNamespace::NotFound { name, protocol } => {
                let name = name.clone();
                let protocol = protocol.clone();
                let caller_for_closure = caller.clone();
                let protocol_for_closure = protocol.clone();
                let result = tokio::task::spawn_blocking(move || {
                    store.namespace_resolve_or_create(&name, &caller_for_closure, Some(&protocol_for_closure))
                })
                .await
                .map_err(|e| topcoat::router::error::bad_request(e.to_string()))?
                .map_err(|e| topcoat::router::error::bad_request(e.to_string()))?;

                let info = serde_json::json!({
                    "uuid": result.uuid_hex(),
                    "name": result.display_name().unwrap_or(""),
                    "protocol": protocol,
                    "owner": caller,
                });
                (
                    StatusCode::CREATED,
                    [("content-type", "application/json")],
                    serde_json::to_string(&info).unwrap_or_default(),
                )
                    .into_response(cx)
            }
            ResolvedNamespace::NoNamespace => {
                (StatusCode::BAD_REQUEST, r#"{"error":"no namespace in path"}"#).into_response(cx)
            }
        }
    })
}

// Warning header is applied by warning_layer, not a response hook.
// The layer checks the request path and only adds Warning: 299 to
// OCI/kappa-distribution responses (/v2/, /identity/, /_status, /docs).

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
    let store: Arc<dyn KappaStore> = {
        let mut store_config = kappa_store_redb::PersistentStoreConfig::new(blob_root, db_path);
        store_config.fsync = cfg.fsync;
        store_config.upload_timeout_secs = Some(cfg.upload_timeout_secs);
        Arc::new(
            PersistentStore::new(store_config, clock.clone())
                .expect("failed to initialize persistent store"),
        )
    };

    kappa_core::version::check_or_write_version(&cfg.store_root)
        .expect("store format version check failed");

    // -- System namespace bootstrap (before identity, _root must exist first) --
    // Create system namespaces with "anonymous" as temporary owner.
    // Node identity bootstrap will create capability edges on _root.
    // After identity bootstrap, the owner is updated to the node anchor.
    {
        let system_ns = [
            ("_root", None),
            ("_nix", Some("nix")),
            ("_system", None),
            ("_admin", None),
            ("_aliases", None),
            ("_handles", None),
            ("_akd/identity", None),
        ];
        for (name, protocol) in &system_ns {
            match store.namespace_resolve_or_create(name, "anonymous", *protocol) {
                Ok(ns) => {
                    tracing::debug!(
                        namespace = name,
                        uuid = %ns.uuid_hex(),
                        "system namespace ready"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        namespace = name,
                        error = %e,
                        "system namespace bootstrap failed"
                    );
                }
            }
        }
    }

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
    let event_log_for_ws: Arc<dyn kappa_core::events::EventLog> = event_log.clone();
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

    // -- Root token + Bearer auth --
    // KAPPA_ROOT_TOKEN=token=anchor creates a single _root delegation
    // from the node anchor to the specified anchor. This is the only
    // path from "configured token" to "root authority." All other
    // KAPPA_AUTH_TOKENS authenticate but have no automatic authority.
    // The root token holder delegates to others via Delegation edges.
    let mut all_tokens = cfg.auth_tokens.clone();
    if let Some(ref ni) = node_identity {
        if let Ok(root_token_str) = std::env::var("KAPPA_ROOT_TOKEN") {
            if let Some((token, anchor)) = root_token_str.split_once('=') {
                let node_anchor = ni.anchor().as_str().to_string();
                let root_ns = store.namespace_resolve("_root", None)
                    .expect("_root namespace must exist after bootstrap");
                let scope = serde_json::json!({
                    "namespaces": [],
                    "operations": ["read", "write", "admin"],
                    "delegation_depth": 1,
                });
                let scope_bytes = serde_json::to_vec(&scope).unwrap_or_default();
                let edge = kappa_core::types::Edge {
                    source: node_anchor.clone(),
                    target: anchor.to_string(),
                    relation: kappa_core::types::EdgeRelation::Delegation,
                    asserter: node_anchor.clone(),
                    value_kappa: None,
                    metadata: Some(scope_bytes),
                };
                if let Err(e) = store.edge_put(&root_ns, &edge) {
                    tracing::warn!(
                        anchor = anchor,
                        error = %e,
                        "failed to create root delegation"
                    );
                } else {
                    tracing::info!(
                        anchor = anchor,
                        "delegated _root authority to root token"
                    );
                }
                // Include root token in authentication tokens
                if !all_tokens.iter().any(|(t, _)| t == token) {
                    all_tokens.push((token.to_string(), anchor.to_string()));
                }
            }
        }
    }
    let bearer_auth = Arc::new(auth::BearerAuth::new(
        all_tokens,
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
        .compression(Compression::off());

    // Layer chain: topcoat runs the LAST registered layer OUTERMOST.
    // Registration order: innermost first, outermost last.
    //
    // Execution order (outermost → innermost):
    //   warning → request_log → proxy_trust → request_id →
    //   security_headers → cors → timeout → auth →
    //   rate_limit → body_limit → response_compliance → cache → handler
    //
    // Auth before rate_limit: unauthenticated requests get 401 before
    // consuming rate limit tokens.
    // Warning outermost: sees ALL responses including auth 403/404.
    // Namespace interceptor is pathless: runs on every request including 404/405.
    builder = builder.layer(LayerFn::new(None::<&Path>, namespace::namespace_layer));
    builder = builder.layer(LayerFn::new(Some("/"),cache_layer));
    builder = builder.layer(LayerFn::new(Some("/"),response_compliance_layer));
    builder = builder.layer(LayerFn::new(Some("/"),body_limit_layer));
    builder = builder.layer(LayerFn::new(Some("/"),rate_limit_layer));
    builder = builder.layer(LayerFn::new(Some("/"),auth_layer));
    builder = builder.layer(LayerFn::new(Some("/"),timeout_layer));
    builder = builder.layer(LayerFn::new(Some("/"),cors_layer));
    builder = builder.layer(LayerFn::new(Some("/"),security_headers_layer));
    builder = builder.layer(LayerFn::new(Some("/"),request_id_layer));
    builder = builder.layer(LayerFn::new(Some("/"),proxy_trust_layer));
    builder = builder.layer(LayerFn::new(Some("/"),request_log_layer));
    builder = builder.layer(LayerFn::new(Some("/"),warning_layer));

    // Routes
    builder = builder
        .route(RouteFn::new(Method::GET, p("/_status"), status_handler))
        .route(RouteFn::new(Method::GET, p("/v2/"), version_check))
        .route(RouteFn::new(
            Method::GET,
            p("/v2/_health/{probe}"),
            health_handler,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/openapi.json"),
            openapi::openapi_json_handler,
        ))
        .route(RouteFn::new(
            Method::GET,
            p("/docs"),
            openapi::docs_handler,
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

    // S3 virtual-hosted-style base domain for bucket routing
    let s3_base_domain = std::env::var("KAPPA_S3_BASE_DOMAIN").unwrap_or_default();
    if !s3_base_domain.is_empty() {
        tracing::info!(base_domain = %s3_base_domain, "S3 virtual-hosted-style enabled");
    }
    builder = builder.app_context(namespace::S3BaseDomain(s3_base_domain));

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

    // TrustPolicy -> AsserterFilter for identity resolution
    {
        let trust_policy = auth::AllowList::allow_all();
        let filter = Arc::new(kappa_module_identity::AsserterFilter(
            Box::new(move |asserter: &str| trust_policy.believes(asserter, "")),
        ));
        builder = builder.app_context(filter);
    }

    if let Some(ref rl) = rate_limiter {
        builder = builder.app_context(rl.clone());
    }

    // -- Identity resolver registry --
    // All protocol-specific identity resolvers registered in one registry.
    // Dispatch by accepts() -- first resolver that recognizes the identifier
    // format handles it. Registration order: most specific first.
    let resolver_registry = resolvers::build_registry();
    builder = builder.app_context(resolver_registry.clone());

    // -- Upload eviction + config --
    #[cfg(feature = "oci")]
    {
        builder = builder.app_context(disk_pressure.clone());
        let upload_timeout_secs = cfg.upload_timeout_secs;
        let eviction_store = store.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                eviction_store.upload_evict_expired(upload_timeout_secs);
            }
        });
        builder = builder.app_context(kappa_module_oci::upload::UploadTimeout(
            cfg.upload_timeout_secs,
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
        // EventLog for WebSocket event streaming
        builder = builder.app_context(event_log_for_ws);

        // CrdtManager for WebSocket CRDT collaboration
        let crdt_manager = Arc::new(kappa_module_distribution::CrdtManager::new(store.clone()));
        builder = builder.app_context(crdt_manager);

        builder = kappa_module_distribution::register(builder);
    }

    // -- AT Protocol XRPC routes --
    #[cfg(feature = "atproto")]
    {
        builder = kappa_module_atproto::register(builder);
        tracing::info!("AT Protocol XRPC endpoints enabled");
    }

    // -- Namespace management routes --
    {
        use topcoat::router::response::IntoResponse;
        use kappa_core::types::ResolvedNamespace;

        fn namespace_info_handler(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let ns = topcoat::context::request_context::<ResolvedNamespace>(cx)
                    .expect_exists()
                    .map_err(|_| topcoat::router::error::not_found())?;
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let ns_name = ns.as_str().to_string();
                let result = tokio::task::spawn_blocking(move || {
                    store.namespace_info(&ns_name, None)
                }).await;
                match result {
                    Ok(Ok(info)) => {
                        let body = serde_json::to_string(&info).unwrap_or_default();
                        (StatusCode::OK, [("content-type", "application/json")], body).into_response(cx)
                    }
                    _ => StatusCode::NOT_FOUND.into_response(cx),
                }
            })
        }

        fn namespace_rename_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let ns = topcoat::context::request_context::<ResolvedNamespace>(cx)
                    .expect_exists()
                    .map_err(|_| topcoat::router::error::not_found())?;
                let asserter = topcoat::context::try_request_context::<kappa_core::types::CallerIdentity>(cx)
                    .map(|ci| ci.0.clone()).unwrap_or_else(|| "anonymous".to_string());
                let bytes = topcoat::router::to_bytes(body, 64 * 1024).await
                    .map(|b| b.to_vec()).unwrap_or_default();
                let v: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;
                let new_name = v["new_name"].as_str()
                    .ok_or_else(|| topcoat::router::error::bad_request("missing new_name"))?
                    .to_string();
                let old_name = ns.as_str().to_string();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let result = tokio::task::spawn_blocking(move || {
                    store.namespace_rename(&old_name, &new_name, &asserter, None)
                }).await;
                match result {
                    Ok(Ok(())) => StatusCode::OK.into_response(cx),
                    Ok(Err(e)) => (StatusCode::FORBIDDEN, e.to_string()).into_response(cx),
                    Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(cx),
                }
            })
        }

        fn namespace_transfer_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let ns = topcoat::context::request_context::<ResolvedNamespace>(cx)
                    .expect_exists()
                    .map_err(|_| topcoat::router::error::not_found())?;
                let asserter = topcoat::context::try_request_context::<kappa_core::types::CallerIdentity>(cx)
                    .map(|ci| ci.0.clone()).unwrap_or_else(|| "anonymous".to_string());
                let bytes = topcoat::router::to_bytes(body, 64 * 1024).await
                    .map(|b| b.to_vec()).unwrap_or_default();
                let v: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;
                let new_owner = v["new_owner"].as_str()
                    .ok_or_else(|| topcoat::router::error::bad_request("missing new_owner"))?
                    .to_string();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let ns_uuid = *ns.uuid();
                let result = tokio::task::spawn_blocking(move || {
                    store.namespace_transfer(&ns_uuid, &new_owner, &asserter)
                }).await;
                match result {
                    Ok(Ok(())) => StatusCode::OK.into_response(cx),
                    Ok(Err(e)) => (StatusCode::FORBIDDEN, e.to_string()).into_response(cx),
                    Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(cx),
                }
            })
        }

        fn namespace_delete_handler(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let ns = topcoat::context::request_context::<ResolvedNamespace>(cx)
                    .expect_exists()
                    .map_err(|_| topcoat::router::error::not_found())?;
                let asserter = topcoat::context::try_request_context::<kappa_core::types::CallerIdentity>(cx)
                    .map(|ci| ci.0.clone()).unwrap_or_else(|| "anonymous".to_string());
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let ns_name = ns.as_str().to_string();
                let result = tokio::task::spawn_blocking(move || {
                    store.namespace_delete(&ns_name, &asserter, None)
                }).await;
                match result {
                    Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(cx),
                    Ok(Err(e)) => (StatusCode::FORBIDDEN, e.to_string()).into_response(cx),
                    Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(cx),
                }
            })
        }

        fn namespace_add_alias_handler(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let ns = topcoat::context::request_context::<ResolvedNamespace>(cx)
                    .expect_exists()
                    .map_err(|_| topcoat::router::error::not_found())?;
                let asserter = topcoat::context::try_request_context::<kappa_core::types::CallerIdentity>(cx)
                    .map(|ci| ci.0.clone()).unwrap_or_else(|| "anonymous".to_string());
                let bytes = topcoat::router::to_bytes(body, 64 * 1024).await
                    .map(|b| b.to_vec()).unwrap_or_default();
                let v: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| topcoat::router::error::bad_request(format!("invalid JSON: {e}")))?;
                let alias = v["alias"].as_str()
                    .ok_or_else(|| topcoat::router::error::bad_request("missing alias"))?
                    .to_string();
                let protocol = v["protocol"].as_str().map(|s| s.to_string());
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let ns_uuid = *ns.uuid();
                let result = tokio::task::spawn_blocking(move || {
                    store.namespace_add_alias(&ns_uuid, &alias, &asserter, protocol.as_deref())
                }).await;
                match result {
                    Ok(Ok(())) => StatusCode::CREATED.into_response(cx),
                    Ok(Err(e)) => (StatusCode::CONFLICT, e.to_string()).into_response(cx),
                    Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(cx),
                }
            })
        }

        fn namespace_list_handler(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let query_protocol = {
                    let uri = topcoat::router::request::uri(cx);
                    uri.query().and_then(|q| {
                        q.split('&').find_map(|pair| {
                            let (k, v) = pair.split_once('=')?;
                            if k == "protocol" { Some(v.to_string()) } else { None }
                        })
                    })
                };
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let result = tokio::task::spawn_blocking(move || {
                    store.namespace_list(query_protocol.as_deref())
                }).await;
                match result {
                    Ok(Ok(records)) => {
                        let body = serde_json::to_string(&records).unwrap_or_default();
                        (StatusCode::OK, [("content-type", "application/json")], body).into_response(cx)
                    }
                    _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(cx),
                }
            })
        }

        builder = builder
            .route(RouteFn::new(Method::POST, p("/v2/{*ns}/_namespace/create"), namespace_create_route))
            .route(RouteFn::new(Method::GET, p("/v2/{*ns}/_namespace/info"), namespace_info_handler))
            .route(RouteFn::new(Method::POST, p("/v2/{*ns}/_namespace/rename"), namespace_rename_handler))
            .route(RouteFn::new(Method::POST, p("/v2/{*ns}/_namespace/transfer"), namespace_transfer_handler))
            .route(RouteFn::new(Method::DELETE, p("/v2/{*ns}/_namespace"), namespace_delete_handler))
            .route(RouteFn::new(Method::POST, p("/v2/{*ns}/_namespace/alias"), namespace_add_alias_handler))
            .route(RouteFn::new(Method::GET, p("/v2/_namespaces"), namespace_list_handler));
    }

    // -- Veilid transport (optional) --
    #[cfg(feature = "veilid")]
    {
        if let Some(ref storage_dir) = cfg.veilid_storage_dir {
            let namespace = cfg.veilid_namespace.clone().unwrap_or_else(|| "kappa-registry".to_string());
            tracing::info!(
                storage_dir = %storage_dir,
                namespace = %namespace,
                "starting Veilid transport"
            );

            let transport_config = kappa_transport_veilid::TransportConfig {
                namespace,
                storage_dir: storage_dir.clone(),
                allow_insecure_protected_store: cfg.veilid_insecure,
                ..Default::default()
            };

            match kappa_transport_veilid::TransportNode::start(transport_config).await {
                Ok((node, _inbound_rx)) => {
                    let node = Arc::new(node);
                    let peer_transport = Arc::new(
                        kappa_transport_veilid::VeilidPeerTransport::new(node.clone()),
                    );
                    let self_id = node_identity
                        .as_ref()
                        .map(|ni| ni.anchor().as_str().to_string())
                        .unwrap_or_default();
                    let membership = Arc::new(
                        kappa_transport_veilid::VeilidMembershipView::new(node.clone(), self_id),
                    );
                    builder = builder.app_context(peer_transport);
                    builder = builder.app_context(membership);
                    tracing::info!("Veilid transport started");
                }
                Err(e) => {
                    tracing::warn!("Veilid transport start failed: {e}");
                }
            }
        }
    }

    // -- Git smart HTTP routes --
    #[cfg(feature = "git")]
    {
        /// Determine the object hash format for a repository.
        /// Reads _config/object_format tag. Defaults to SHA-1.
        fn repo_object_hash(store: &dyn KappaStore, repo: &NamespaceRef) -> gix_hash::Kind {
            match store.tag_get(repo, "_config/object_format") {
                Ok(entry) => match entry.kappa.as_str() {
                    "sha256" => gix_hash::Kind::Sha256,
                    _ => gix_hash::Kind::Sha1,
                },
                Err(_) => gix_hash::Kind::Sha1,
            }
        }

        fn git_info_refs(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                // repo_name extracted by namespace interceptor layer
                // service comes from ?service= query param, not path param
                let service = {
                    let parts: &http::request::Parts = request_context(cx);
                    parts.uri.query().unwrap_or("").split('&')
                        .find_map(|p| p.strip_prefix("service="))
                        .unwrap_or("").to_string()
                };
                let is_upload = service.contains("upload-pack");
                // Check Git-Protocol header for v2
                let is_v2 = {
                    let parts: &http::request::Parts = request_context(cx);
                    parts.headers.get("git-protocol")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.contains("version=2"))
                        .unwrap_or(false)
                };
                let repo = {
                    use kappa_core::types::ResolvedNamespace;
                    match request_context::<ResolvedNamespace>(cx) {
                        ResolvedNamespace::Exists(ns) => ns.clone(),
                        ResolvedNamespace::NotFound { name, protocol } if !is_upload => {
                            // receive-pack (push) creates namespace on first push
                            let s = app_context::<Arc<dyn KappaStore>>(cx).clone();
                            let name = name.clone();
                            let protocol = protocol.clone();
                            tokio::task::spawn_blocking(move || {
                                s.namespace_resolve_or_create(&name, "_git", Some(&protocol))
                            }).await
                                .map_err(|e| std::io::Error::other(e.to_string()))?
                                .map_err(|e| std::io::Error::other(e.to_string()))?
                        }
                        _ => return StatusCode::NOT_FOUND.into_response(cx),
                    }
                };
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let svc = service.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let object_hash = repo_object_hash(&*store, &repo);
                    let mut out = Vec::new();
                    if is_v2 {
                        kappa_module_git::write_v2_capability_advertisement(&mut out, object_hash)
                            .map(|_| out)
                    } else {
                        kappa_module_git::write_ref_advertisement(
                            &*store, &repo, &svc, &mut out, object_hash,
                        ).map(|_| out)
                    }
                }).await;
                match result {
                    Ok(Ok(data)) => {
                        let ct = if is_upload {
                            "application/x-git-upload-pack-advertisement"
                        } else {
                            "application/x-git-receive-pack-advertisement"
                        };
                        let mut resp = (StatusCode::OK, [
                            ("content-type", ct.to_string()),
                            ("cache-control", "no-cache".to_string()),
                        ], data).into_response(cx)?;
                        if is_v2 {
                            resp.headers_mut().insert("git-protocol", "version=2".parse().unwrap());
                        }
                        Ok(resp)
                    }
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "git info/refs failed");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response(cx)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "git info/refs spawn failed");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response(cx)
                    }
                }
            })
        }

        fn git_upload_pack(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                // repo_name extracted by namespace interceptor layer
                let is_v2 = {
                    let parts: &http::request::Parts = request_context(cx);
                    parts.headers.get("git-protocol")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.contains("version=2"))
                        .unwrap_or(false)
                };
                let repo = {
                    use kappa_core::types::ResolvedNamespace;
                    request_context::<ResolvedNamespace>(cx).expect_exists()
                        .map_err(|_| topcoat::router::error::not_found())?
                };
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let request_bytes = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 256 * 1024 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
                };
                let result = tokio::task::spawn_blocking(move || {
                    let object_hash = repo_object_hash(&*store, &repo);
                    let mut response = Vec::new();
                    if is_v2 {
                        kappa_module_git::handle_v2_upload_pack(
                            &*store, &repo,
                            std::io::Cursor::new(request_bytes),
                            &mut response,
                            object_hash,
                        ).map(|_| response)
                    } else {
                        kappa_module_git::handle_upload_pack(
                            &*store, &repo,
                            std::io::Cursor::new(request_bytes),
                            &mut response,
                            object_hash,
                        ).map(|_| response)
                    }
                }).await;
                match result {
                    Ok(Ok(data)) => (StatusCode::OK, [
                        ("content-type", "application/x-git-upload-pack-result".to_string()),
                    ], data).into_response(cx),
                    _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(cx),
                }
            })
        }

        fn git_receive_pack(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let repo = {
                    use kappa_core::types::ResolvedNamespace;
                    match request_context::<ResolvedNamespace>(cx) {
                        ResolvedNamespace::Exists(ns) => ns.clone(),
                        ResolvedNamespace::NotFound { name, protocol } => {
                            let s = app_context::<Arc<dyn KappaStore>>(cx).clone();
                            let name = name.clone();
                            let protocol = protocol.clone();
                            tokio::task::spawn_blocking(move || {
                                s.namespace_resolve_or_create(&name, "_git", Some(&protocol))
                            }).await
                                .map_err(|e| std::io::Error::other(e.to_string()))?
                                .map_err(|e| std::io::Error::other(e.to_string()))?
                        }
                        ResolvedNamespace::NoNamespace => return StatusCode::NOT_FOUND.into_response(cx),
                    }
                };
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let request_bytes = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 256 * 1024 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
                };
                let result = tokio::task::spawn_blocking(move || {
                    let object_hash = repo_object_hash(&*store, &repo);
                    let mut response = Vec::new();
                    kappa_module_git::handle_receive_pack(
                        &*store, &repo,
                        std::io::BufReader::new(std::io::Cursor::new(request_bytes)),
                        &mut response,
                        object_hash,
                    ).map(|_| response)
                }).await;
                match result {
                    Ok(Ok(data)) => (StatusCode::OK, [
                        ("content-type", "application/x-git-receive-pack-result".to_string()),
                    ], data).into_response(cx),
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "git receive-pack failed");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response(cx)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "git receive-pack spawn failed");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response(cx)
                    }
                }
            })
        }

        fn git_lfs_batch(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let repo = {
                    use kappa_core::types::ResolvedNamespace;
                    match request_context::<ResolvedNamespace>(cx) {
                        ResolvedNamespace::Exists(ns) => ns.clone(),
                        ResolvedNamespace::NotFound { name, protocol } => {
                            let s = app_context::<Arc<dyn KappaStore>>(cx).clone();
                            let name = name.clone();
                            let protocol = protocol.clone();
                            tokio::task::spawn_blocking(move || {
                                s.namespace_resolve_or_create(&name, "_git", Some(&protocol))
                            }).await
                                .map_err(|e| std::io::Error::other(e.to_string()))?
                                .map_err(|e| std::io::Error::other(e.to_string()))?
                        }
                        ResolvedNamespace::NoNamespace => return StatusCode::NOT_FOUND.into_response(cx),
                    }
                };
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let request_bytes = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 10 * 1024 * 1024).await
                        .map(|b| b.to_vec()).unwrap_or_default()
                };
                let base_url = {
                    let parts: &http::request::Parts = request_context(cx);
                    let host = parts.headers.get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("localhost:5000");
                    format!("http://{}", host)
                };
                let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
                    let batch_req: kappa_module_git::BatchRequest =
                        serde_json::from_slice(&request_bytes)
                            .map_err(|e| format!("invalid LFS batch request: {e}"))?;
                    let batch_resp = kappa_module_git::process_batch(
                        &*store, &base_url, repo.as_str(), &batch_req,
                    );
                    serde_json::to_vec(&batch_resp)
                        .map_err(|e| format!("LFS response serialize: {e}"))
                }).await;
                match result {
                    Ok(Ok(json)) => (StatusCode::OK, [
                        ("content-type", "application/vnd.git-lfs+json".to_string()),
                    ], json).into_response(cx),
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, [
                        ("content-type", "application/vnd.git-lfs+json".to_string()),
                    ], br#"{"message":"internal error"}"#.to_vec()).into_response(cx),
                }
            })
        }

        // Git routes: /_git/ internal prefix. The .git/ -> /_git/ rewrite
        // happens in serve_with_vhost BEFORE routing, not in a layer,
        // because topcoat resolves routes before layers run.
        builder = builder
            .route(RouteFn::new(Method::GET, p("/_git/{*repo}/info/refs"), git_info_refs))
            .route(RouteFn::new(Method::POST, p("/_git/{*repo}/git_upload_pack"), git_upload_pack))
            .route(RouteFn::new(Method::POST, p("/_git/{*repo}/git_receive_pack"), git_receive_pack))
            .route(RouteFn::new(Method::POST, p("/_git/{*repo}/info/lfs/objects/batch"), git_lfs_batch));

        tracing::info!("Git smart HTTP protocol enabled (v1+v2, LFS)");
    }

    // -- Nix binary cache routes --
    #[cfg(feature = "nix")]
    {
        // NixKeyResolver is now in resolvers.rs -- registered via ResolverRegistry below

        fn nix_cache_info(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let priority = std::env::var("KAPPA_NIX_PRIORITY")
                    .unwrap_or_else(|_| "30".to_string());
                let body = format!(
                    "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: {}\n",
                    priority
                );
                (StatusCode::OK, [
                    ("content-type", "text/x-nix-cache-info"),
                ], body).into_response(cx)
            })
        }

        fn nix_narinfo_get(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let nix_ns = {
                    use kappa_core::types::ResolvedNamespace;
                    request_context::<ResolvedNamespace>(cx).expect_exists()
                        .map_err(|_| topcoat::router::error::not_found())?
                };
                let hash = raw_path_params(cx).find(|(k, _)| *k == "hash")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let tag_name = format!("narinfo:{}", hash);
                let result = tokio::task::spawn_blocking(move || {
                    let entry = store.tag_get(&nix_ns, &tag_name)?;
                    store.blob_get(&entry.kappa)
                }).await;
                match result {
                    Ok(Ok(content)) => (StatusCode::OK, [
                        ("content-type", "text/x-nix-narinfo"),
                        ("cache-control", "max-age=600"),
                    ], content).into_response(cx),
                    _ => StatusCode::NOT_FOUND.into_response(cx),
                }
            })
        }

        fn nix_narinfo_head(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let nix_ns = {
                    use kappa_core::types::ResolvedNamespace;
                    request_context::<ResolvedNamespace>(cx).expect_exists()
                        .map_err(|_| topcoat::router::error::not_found())?
                };
                let hash = raw_path_params(cx).find(|(k, _)| *k == "hash")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let tag_name = format!("narinfo:{}", hash);
                let result = tokio::task::spawn_blocking(move || {
                    let entry = store.tag_get(&nix_ns, &tag_name)?;
                    store.blob_size(&entry.kappa)
                }).await;
                match result {
                    Ok(Ok(size)) => (StatusCode::OK, [
                        ("content-type", "text/x-nix-narinfo"),
                        ("content-length", &size.to_string()),
                    ]).into_response(cx),
                    _ => StatusCode::NOT_FOUND.into_response(cx),
                }
            })
        }

        fn nix_narinfo_put(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let url_hash = raw_path_params(cx).find(|(k, _)| *k == "hash")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let nix_ns = {
                    use topcoat::context::request_context;
                    use kappa_core::types::ResolvedNamespace;
                    request_context::<ResolvedNamespace>(cx).expect_exists()
                        .map_err(|_| topcoat::router::error::not_found())?
                };
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let nix_resolver = try_app_context::<Arc<kappa_core::identity::resolver::ResolverRegistry>>(cx).cloned();
                let narinfo_bytes = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 64 * 1024).await
                        .map(|b| b.to_vec()).unwrap_or_default()
                };
                let result = tokio::task::spawn_blocking(move || {
                    let narinfo_text = String::from_utf8(narinfo_bytes.clone())
                        .map_err(|e| kappa_core::types::StoreError::Rejected(
                            format!("narinfo is not valid UTF-8: {e}")
                        ))?;
                    let narinfo = kappa_module_nix::narinfo::NarInfo::parse(&narinfo_text)
                        .map_err(|e| kappa_core::types::StoreError::Rejected(
                            format!("narinfo parse error: {e}")
                        ))?;

                    // Verify URL hash matches store path hash
                    let store_hash = narinfo.store_path_hash();
                    if url_hash != store_hash {
                        return Err(kappa_core::types::StoreError::Rejected(format!(
                            "URL hash {} does not match store path hash {}",
                            url_hash, store_hash
                        )));
                    }

                    // Verify NarHash and references if the referenced NAR is already stored.
                    // The Nix client uploads narinfo BEFORE the NAR, so the NAR may not
                    // exist yet. When it does exist, verify immediately. When it doesn't,
                    // store the narinfo and defer verification to NAR PUT time.
                    let nar_path = narinfo.url.strip_prefix("nar/").unwrap_or(&narinfo.url);
                    let nar_tag_name = format!("nar:{}", nar_path);
                    if let Ok(nar_entry) = store.tag_get(&nix_ns, &nar_tag_name) {
                        let nar_bytes = store.blob_get(&nar_entry.kappa)?;
                        kappa_module_nix::refs::decompress_and_verify(
                            &nar_bytes,
                            &narinfo.compression,
                            &narinfo.nar_hash,
                            &narinfo.references,
                        ).map_err(|e| kappa_core::types::StoreError::Rejected(
                            format!("NAR verification failed: {e}")
                        ))?;
                        // Create compression record and retag NAR by NarHash
                        let _ = store.ingest_compressed(
                            &narinfo.nar_hash,
                            &nar_bytes,
                            &narinfo.compression,
                            narinfo.nar_size,
                        );
                        let nar_path = narinfo.url.strip_prefix("nar/").unwrap_or(&narinfo.url);
                        let nar_tag = format!("nar:{}", nar_path);
                        store.tag_set(&nix_ns, &nar_tag, &narinfo.nar_hash)?;
                    }

                    // Store narinfo text as blob
                    let narinfo_result = store.ingest_compute(
                        kappa_core::kappa::Axis::Sha256, &narinfo_bytes
                    )?;

                    // Set tag: narinfo:{hash} -> narinfo blob kappa
                    let tag_name = format!("narinfo:{}", store_hash);
                    store.tag_set(&nix_ns, &tag_name, &narinfo_result.kappa)?;

                    // Create RefersTo edges via edge_put_batch
                    let edges: Vec<kappa_core::types::Edge> = narinfo.references.iter()
                        .filter_map(|basename| {
                            if basename.len() > 32 && basename.as_bytes().get(32) == Some(&b'-') {
                                Some(kappa_core::types::Edge {
                                    source: narinfo_result.kappa.clone(),
                                    target: format!("storepath:{}", &basename[..32]),
                                    relation: kappa_core::types::EdgeRelation::RefersTo,
                                    asserter: "_nix".to_string(),
                                    value_kappa: None,
                                    metadata: None,
                                })
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !edges.is_empty() {
                        store.edge_put_batch(&nix_ns, &edges)?;
                    }

                    // Create DerivedFrom edge if deriver is present
                    if let Some(ref deriver) = narinfo.deriver {
                        let deriver_edge = kappa_core::types::Edge {
                            source: narinfo_result.kappa.clone(),
                            target: format!("deriver:{}", deriver),
                            relation: kappa_core::types::EdgeRelation::DerivedFrom,
                            asserter: "_nix".to_string(),
                            value_kappa: None,
                            metadata: None,
                        };
                        store.edge_put(&nix_ns, &deriver_edge)?;
                    }

                    // Store signatures as blob metadata
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let mut sig_key_names: Vec<String> = Vec::new();
                    for (i, sig) in narinfo.signatures.iter().enumerate() {
                        let meta_key = format!("_nix_sig_{}", i);
                        store.blob_put_meta(
                            &narinfo_result.kappa, &meta_key, sig.as_bytes()
                        )?;
                        if let Some((key_name, _)) = sig.split_once(':') {
                            sig_key_names.push(key_name.to_string());
                        }
                    }

                    Ok::<(kappa_core::types::NamespaceRef, String, Vec<String>, u64), kappa_core::types::StoreError>(
                        (nix_ns, narinfo_result.kappa, sig_key_names, now_ms)
                    )
                }).await;
                // Phase 2: resolve signing keys to anchors (async, outside spawn_blocking)
                match &result {
                    Ok(Ok((nix_ns, narinfo_kappa, sig_key_names, now_ms))) => {
                        if let Some(ref registry) = nix_resolver {
                            let store2 = app_context::<Arc<dyn KappaStore>>(cx).clone();
                            for key_name in sig_key_names {
                                if let Ok(Some(identity)) = registry.resolve(key_name).await {
                                    // Create identity binding: key name -> anchor
                                    let binding = kappa_core::identity::binding::IdentityBinding {
                                        source: key_name.to_string(),
                                        target: identity.anchor.clone(),
                                        method: "nix-key".to_string(),
                                        trust_level: 3,
                                        verified_at_ms: *now_ms,
                                    };
                                    // Create Assertion edge: anchor signed this narinfo
                                    let assertion_edge = kappa_core::types::Edge {
                                        source: identity.anchor.clone(),
                                        target: narinfo_kappa.clone(),
                                        relation: kappa_core::types::EdgeRelation::Assertion,
                                        asserter: identity.anchor.clone(),
                                        value_kappa: None,
                                        metadata: Some(format!("nix-sig:{}", key_name).into_bytes()),
                                    };
                                    let ns = nix_ns.clone();
                                    let s = store2.clone();
                                    let _ = tokio::task::spawn_blocking(move || {
                                        s.identity_binding_put(&ns, &binding)?;
                                        s.edge_put(&ns, &assertion_edge)?;
                                        Ok::<(), kappa_core::types::StoreError>(())
                                    }).await;
                                }
                            }
                        }
                    }
                    _ => {}
                }
                match &result {
                    Ok(Ok(_)) => StatusCode::CREATED.into_response(cx),
                    Ok(Err(kappa_core::types::StoreError::Rejected(msg))) => {
                        (StatusCode::BAD_REQUEST, msg.clone()).into_response(cx)
                    }
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "nix narinfo put failed");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response(cx)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "nix narinfo put spawn failed");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response(cx)
                    }
                }
            })
        }

        fn nix_nar_get(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let nix_ns = {
                    use kappa_core::types::ResolvedNamespace;
                    request_context::<ResolvedNamespace>(cx).expect_exists()
                        .map_err(|_| topcoat::router::error::not_found())?
                };
                let path = raw_path_params(cx).find(|(k, _)| *k == "path")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let tag_name = format!("nar:{}", path);
                let result = tokio::task::spawn_blocking(move || {
                    let entry = store.tag_get(&nix_ns, &tag_name)?;
                    let mut reader = store.blob_open_compressed(&entry.kappa)?;
                    let mut content = Vec::new();
                    std::io::Read::read_to_end(&mut *reader, &mut content)?;
                    Ok::<Vec<u8>, kappa_core::types::StoreError>(content)
                }).await;
                match result {
                    Ok(Ok(content)) => (StatusCode::OK, [
                        ("content-type", "application/x-nix-nar"),
                    ], content).into_response(cx),
                    _ => StatusCode::NOT_FOUND.into_response(cx),
                }
            })
        }

        fn nix_nar_put(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let path = raw_path_params(cx).find(|(k, _)| *k == "path")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let nix_ns = {
                    use topcoat::context::request_context;
                    use kappa_core::types::ResolvedNamespace;
                    request_context::<ResolvedNamespace>(cx).expect_exists()
                        .map_err(|_| topcoat::router::error::not_found())?
                };
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let content = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 10 * 1024 * 1024 * 1024).await
                        .map(|b| b.to_vec()).unwrap_or_default()
                };
                let result = tokio::task::spawn_blocking(move || {
                    let nar_kappa = kappa_core::kappa::kappa_from_bytes(&content);
                    store.ingest_verified(&nar_kappa, &content)?;
                    let tag_name = format!("nar:{}", path);
                    store.tag_set(&nix_ns, &tag_name, &nar_kappa)?;

                    // Deferred verification: check if any narinfo already references
                    // this NAR and verify NarHash + references now that the NAR is stored.
                    // Scan narinfo tags for entries whose URL field matches this NAR path.
                    // The narinfo stores the URL as "nar/{path}", the NAR tag is "nar:{path}".
                    if let Ok(tags) = store.tag_list(&nix_ns) {
                        for tag in &tags {
                            if !tag.name.starts_with("narinfo:") {
                                continue;
                            }
                            if let Ok(narinfo_bytes) = store.blob_get(&tag.kappa) {
                                if let Ok(narinfo_text) = String::from_utf8(narinfo_bytes) {
                                    if let Ok(narinfo) = kappa_module_nix::narinfo::NarInfo::parse(&narinfo_text) {
                                        let narinfo_nar_path = narinfo.url.strip_prefix("nar/").unwrap_or(&narinfo.url);
                                        if narinfo_nar_path == path {
                                            match kappa_module_nix::refs::decompress_and_verify(
                                                &content,
                                                &narinfo.compression,
                                                &narinfo.nar_hash,
                                                &narinfo.references,
                                            ) {
                                                Ok(()) => {
                                                    let _ = store.ingest_compressed(
                                                        &narinfo.nar_hash,
                                                        &content,
                                                        &narinfo.compression,
                                                        narinfo.nar_size,
                                                    );
                                                    let nar_tag = format!("nar:{}", path);
                                                    let _ = store.tag_set(&nix_ns, &nar_tag, &narinfo.nar_hash);
                                                }
                                                Err(e) => {
                                                    tracing::warn!(
                                                        narinfo = %tag.name,
                                                        error = %e,
                                                        "deferred NAR verification failed, removing narinfo"
                                                    );
                                                    let _ = store.tag_delete(&nix_ns, &tag.name);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Ok::<(), kappa_core::types::StoreError>(())
                }).await;
                match result {
                    Ok(Ok(())) => StatusCode::CREATED.into_response(cx),
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "nix nar put failed");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response(cx)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "nix nar put spawn failed");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response(cx)
                    }
                }
            })
        }

        // Routes use INTERNAL paths from nix_rewrite.rs mapping table.
        // External /{hash}.narinfo is rewritten to /narinfo/{hash} by the
        // rewrite layer before routing. See nix_rewrite.rs doc comment.
        builder = builder
            .route(RouteFn::new(Method::GET, p("/_nix/nix-cache-info"), nix_cache_info))
            .route(RouteFn::new(Method::GET, p("/_nix/narinfo/{hash}"), nix_narinfo_get))
            .route(RouteFn::new(Method::HEAD, p("/_nix/narinfo/{hash}"), nix_narinfo_head))
            .route(RouteFn::new(Method::PUT, p("/_nix/narinfo/{hash}"), nix_narinfo_put))
            .route(RouteFn::new(Method::GET, p("/_nix/nar/{*path}"), nix_nar_get))
            .route(RouteFn::new(Method::PUT, p("/_nix/nar/{*path}"), nix_nar_put));

        tracing::info!("Nix binary cache protocol enabled");
    }

    // -- S3-compatible routes --
    #[cfg(feature = "s3")]
    {
        /// Check SigV4 auth and bucket policy on an S3 request.
        /// Returns None if auth + policy pass. Some(Response) on failure.
        fn s3_auth_check(cx: &Cx) -> Option<topcoat::router::response::Response> {
            // Step 1: SigV4 credential verification
            match layers::sigv4::verify_request(cx, None) {
                Ok(_) => {}
                Err(response) => return Some(response),
            }
            // Step 2: Bucket policy evaluation
            let bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                .map(|(_, v)| v.as_str().to_string());
            if let Some(ref b) = bucket {
                let query = parse_s3_query(cx);
                let parts: &http::request::Parts = request_context(cx);
                let action = derive_s3_action(&parts.method, &query);
                if let Some(resp) = evaluate_bucket_policy(cx, b, action) {
                    return Some(resp);
                }
            }
            None
        }

        /// Derive S3 action from HTTP method and query params.
        fn derive_s3_action(method: &Method, query: &std::collections::HashMap<String, String>) -> &'static str {
            if method == Method::GET {
                if query.contains_key("tagging") { return "s3:GetObjectTagging"; }
                if query.contains_key("acl") { return "s3:GetObjectAcl"; }
                if query.contains_key("versioning") { return "s3:GetBucketVersioning"; }
                if query.contains_key("lifecycle") { return "s3:GetLifecycleConfiguration"; }
                if query.contains_key("cors") { return "s3:GetBucketCors"; }
                if query.contains_key("policy") { return "s3:GetBucketPolicy"; }
                if query.contains_key("attributes") { return "s3:GetObjectAttributes"; }
                return "s3:GetObject";
            }
            if method == Method::PUT {
                if query.contains_key("tagging") { return "s3:PutObjectTagging"; }
                if query.contains_key("versioning") { return "s3:PutBucketVersioning"; }
                if query.contains_key("lifecycle") { return "s3:PutLifecycleConfiguration"; }
                if query.contains_key("cors") { return "s3:PutBucketCors"; }
                if query.contains_key("policy") { return "s3:PutBucketPolicy"; }
                return "s3:PutObject";
            }
            if method == Method::DELETE {
                if query.contains_key("tagging") { return "s3:DeleteObjectTagging"; }
                if query.contains_key("lifecycle") { return "s3:DeleteLifecycleConfiguration"; }
                if query.contains_key("cors") { return "s3:DeleteBucketCors"; }
                if query.contains_key("policy") { return "s3:DeleteBucketPolicy"; }
                return "s3:DeleteObject";
            }
            if method == Method::HEAD { return "s3:GetObject"; }
            if method == Method::POST {
                if query.contains_key("uploads") { return "s3:PutObject"; }
                if query.contains_key("delete") { return "s3:DeleteObject"; }
                return "s3:PutObject";
            }
            "s3:*"
        }

        /// Evaluate bucket policy against the current request.
        /// Returns None if allowed, Some(Response) if denied.
        fn evaluate_bucket_policy(
            cx: &Cx,
            bucket: &str,
            action: &str,
        ) -> Option<topcoat::router::response::Response> {
            let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
            let b = match store.namespace_resolve(bucket, Some("s3")) { Ok(r) => r, Err(_) => return None };
            // Synchronous policy check -- policy blobs are small
            let policy_json = {
                match store.tag_get(&b, "_config/policy") {
                    Ok(entry) => match store.blob_get(&entry.kappa) {
                        Ok(bytes) => Some(bytes),
                        Err(_) => None,
                    },
                    Err(_) => None,
                }
            };
            let policy_bytes = policy_json?;
            let policy: serde_json::Value = serde_json::from_slice(&policy_bytes).ok()?;
            let statements = policy.get("Statement")?.as_array()?;

            let mut any_allow = false;
            for stmt in statements {
                let effect = stmt.get("Effect").and_then(|e| e.as_str()).unwrap_or("");
                let actions: Vec<&str> = match stmt.get("Action") {
                    Some(serde_json::Value::String(s)) => vec![s.as_str()],
                    Some(serde_json::Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str()).collect(),
                    _ => continue,
                };
                let action_matches = actions.iter().any(|a| {
                    *a == "*" || *a == action
                        || (a.ends_with('*') && action.starts_with(&a[..a.len() - 1]))
                });
                if !action_matches { continue; }
                if effect == "Deny" {
                    let err = kappa_module_s3::encode_s3_error_xml(
                        "AccessDenied", "Access Denied by bucket policy",
                    );
                    if let Ok(resp) = (StatusCode::FORBIDDEN, [("content-type", "application/xml")], err).into_response(cx) {
                        return Some(resp);
                    }
                }
                if effect == "Allow" { any_allow = true; }
            }
            if !statements.is_empty() && !any_allow {
                let err = kappa_module_s3::encode_s3_error_xml(
                    "AccessDenied", "Access Denied by bucket policy (implicit deny)",
                );
                if let Ok(resp) = (StatusCode::FORBIDDEN, [("content-type", "application/xml")], err).into_response(cx) {
                    return Some(resp);
                }
            }
            None
        }

        /// Resolve S3 bucket namespace from interceptor context. Read path.
        fn s3_bucket_read(cx: &Cx) -> topcoat::Result<kappa_core::types::NamespaceRef> {
            use kappa_core::types::ResolvedNamespace;
            request_context::<ResolvedNamespace>(cx)
                .expect_exists()
                .map_err(|_| topcoat::router::error::not_found().into())
        }

        /// Resolve S3 bucket namespace from interceptor context. Write path: creates on first write.
        async fn s3_bucket_write(cx: &Cx) -> topcoat::Result<kappa_core::types::NamespaceRef> {
            use kappa_core::types::ResolvedNamespace;
            match request_context::<ResolvedNamespace>(cx) {
                ResolvedNamespace::Exists(ns) => Ok(ns.clone()),
                ResolvedNamespace::NotFound { name, protocol } => {
                    let s = app_context::<Arc<dyn KappaStore>>(cx).clone();
                    let name = name.clone();
                    let protocol = protocol.clone();
                    tokio::task::spawn_blocking(move || {
                        s.namespace_resolve_or_create(&name, "_s3", Some(&protocol))
                    })
                    .await
                    .map_err(|e| topcoat::router::error::bad_request(e.to_string()))?
                    .map_err(|e| topcoat::router::error::bad_request(e.to_string()).into())
                }
                ResolvedNamespace::NoNamespace => {
                    Err(topcoat::router::error::not_found().into())
                }
            }
        }

        /// Parse query parameters from a URI string.
        fn parse_s3_query(cx: &Cx) -> std::collections::HashMap<String, String> {
            use topcoat::context::request_context;
            let parts: &http::request::Parts = request_context(cx);
            let mut map = std::collections::HashMap::new();
            if let Some(query) = parts.uri.query() {
                for pair in query.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        map.insert(
                            percent_decode(k),
                            percent_decode(v),
                        );
                    } else {
                        map.insert(percent_decode(pair), String::new());
                    }
                }
            }
            map
        }

        /// Percent-decode a URL-encoded string (e.g. dir%2F -> dir/).
        fn percent_decode(s: &str) -> String {
            let mut result = Vec::with_capacity(s.len());
            let bytes = s.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' && i + 2 < bytes.len() {
                    if let (Some(hi), Some(lo)) = (
                        hex_val(bytes[i + 1]),
                        hex_val(bytes[i + 2]),
                    ) {
                        result.push(hi << 4 | lo);
                        i += 3;
                        continue;
                    }
                }
                // '+' decodes to space in query strings
                if bytes[i] == b'+' {
                    result.push(b' ');
                } else {
                    result.push(bytes[i]);
                }
                i += 1;
            }
            String::from_utf8(result).unwrap_or_else(|_| s.to_string())
        }

        fn hex_val(b: u8) -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        }

        fn s3_list_objects(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let bucket_ns = s3_bucket_read(cx)?;
                let bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                // Parse query params from URI query string, not path params
                let query = parse_s3_query(cx);
                let prefix = query.get("prefix").cloned();
                let delimiter = query.get("delimiter").cloned();
                let max_keys: u32 = query.get("max-keys")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1000);
                let continuation_token = query.get("continuation-token").cloned();
                let start_after = query.get("start-after").cloned();
                let encoding_type = query.get("encoding-type").cloned();

                let req = kappa_module_s3::ListObjectsV2Request {
                    bucket: bucket.clone(),
                    prefix,
                    delimiter,
                    max_keys,
                    continuation_token,
                    start_after,
                    encoding_type,
                    fetch_owner: false,
                };

                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    let resp = kappa_module_s3::list_objects_v2(&*store, &bucket, &req)?;
                    Ok::<Vec<u8>, kappa_core::types::StoreError>(
                        kappa_module_s3::encode_list_objects_v2_xml(&resp),
                    )
                }).await;

                match result {
                    Ok(Ok(xml)) => (StatusCode::OK, [
                        ("content-type", "application/xml".to_string()),
                    ], xml).into_response(cx),
                    _ => {
                        let err_xml = kappa_module_s3::encode_s3_error_xml(
                            "InternalError", "list failed",
                        );
                        (StatusCode::INTERNAL_SERVER_ERROR, [
                            ("content-type", "application/xml".to_string()),
                        ], err_xml).into_response(cx)
                    }
                }
            })
        }

        fn s3_put_object(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let bucket_ns = s3_bucket_write(cx).await?;
                let bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let key = raw_path_params(cx).find(|(k, _)| *k == "key")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();

                // Item 46: SSE-C rejection
                {
                    let parts: &http::request::Parts = request_context(cx);
                    if parts.headers.contains_key("x-amz-server-side-encryption-customer-algorithm") {
                        let err = kappa_module_s3::encode_s3_error_xml(
                            "InvalidArgument", "SSE-C is not supported. Use SSE-S3 (AES256).",
                        );
                        return (StatusCode::BAD_REQUEST, [("content-type", "application/xml")], err).into_response(cx);
                    }
                }

                let sse_algo = {
                    let parts: &http::request::Parts = request_context(cx);
                    parts.headers.get("x-amz-server-side-encryption")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                };

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                // Item 42: Check bucket exists BEFORE reading body.
                // If Expect: 100-continue is set and bucket does not exist,
                // hyper never sends 100 Continue -- client sees 404 without uploading.
                {
                    let bucket_name = bucket.clone();
                    let s = store.clone();
                    let exists = tokio::task::spawn_blocking(move || s.namespace_exists(&bucket_name, Some("s3")))
                        .await.unwrap_or(Ok(false)).unwrap_or(false);
                    if !exists {
                        let err = kappa_module_s3::encode_s3_error_xml(
                            "NoSuchBucket", "The specified bucket does not exist.",
                        );
                        return (StatusCode::NOT_FOUND, [("content-type", "application/xml")], err).into_response(cx);
                    }
                }

                // Extract Content-MD5 and Content-Type and x-amz-content-sha256 before reading body
                let (content_md5_header, content_type_header, content_sha256_header) = {
                    let parts: &http::request::Parts = request_context(cx);
                    let cmd5 = parts.headers.get("content-md5")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let ct = parts.headers.get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let csha = parts.headers.get("x-amz-content-sha256")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    (cmd5, ct, csha)
                };

                let content = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 256 * 1024 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
                };

                // Fix 4: Validate Content-MD5 header against body
                if let Some(ref expected_md5_b64) = content_md5_header {
                    use md5::Digest;
                    let computed = md5::Md5::digest(&content);
                    let computed_b64 = base64_simd::STANDARD.encode_to_string(&computed);
                    if computed_b64 != *expected_md5_b64 {
                        let err = kappa_module_s3::encode_s3_error_xml(
                            "BadDigest", "The Content-MD5 you specified did not match what we received.",
                        );
                        return (StatusCode::BAD_REQUEST, [("content-type", "application/xml")], err).into_response(cx);
                    }
                }

                // Fix 5: Validate x-amz-content-sha256 against body
                if let Some(ref expected_sha) = content_sha256_header {
                    if expected_sha != "UNSIGNED-PAYLOAD"
                        && !expected_sha.starts_with("STREAMING-")
                        && !expected_sha.is_empty()
                    {
                        let computed = kappa_core::crypto::sigv4::sha256_hex(&content);
                        if computed != *expected_sha {
                            let err = kappa_module_s3::encode_s3_error_xml(
                                "XAmzContentSHA256Mismatch",
                                "The provided x-amz-content-sha256 header does not match the body.",
                            );
                            return (StatusCode::BAD_REQUEST, [("content-type", "application/xml")], err).into_response(cx);
                        }
                    }
                }

                let sse = sse_algo.clone();
                let ct_for_store = content_type_header.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    let digest = kappa_core::kappa::kappa_from_bytes(&content);
                    let ingest = store.ingest_verified(&digest, &content)?;

                    // Fix 2: S3 ETag for single PUT is md5(content), not kappa
                    use md5::Digest;
                    let md5_hash = md5::Md5::digest(&content);
                    let etag = format!("\"{}\"", hex::encode(md5_hash));

                    // Store creation timestamp for lifecycle expiration
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let _ = store.blob_put_meta(&ingest.kappa, "_s3_created_ms", now_ms.to_string().as_bytes());

                    // Store MD5 for ETag retrieval on GET
                    let _ = store.blob_put_meta(&ingest.kappa, "_s3_etag", etag.as_bytes());

                    // Fix 6: Store Content-Type from PUT request
                    if let Some(ref ct) = ct_for_store {
                        let _ = store.blob_put_meta(&ingest.kappa, "content-type", ct.as_bytes());
                    }

                    // Item 46: Store SSE metadata
                    if let Some(ref algo) = sse {
                        let _ = store.blob_put_meta(&ingest.kappa, "_s3_sse", algo.as_bytes());
                    }
                    let vid = match store.version_put(&bucket, &key, &ingest.kappa, Some(&etag)) {
                        Ok(v) => v,
                        Err(kappa_core::types::StoreError::Rejected(_)) => {
                            store.tag_set(&bucket, &key, &ingest.kappa)?;
                            "null".to_string()
                        }
                        Err(e) => return Err(e),
                    };
                    Ok::<(String, String, String), kappa_core::types::StoreError>((etag, vid, ingest.kappa))
                }).await;

                match result {
                    Ok(Ok((etag, vid, _kappa))) => {
                        let mut hm = http::HeaderMap::new();
                        hm.insert("etag", etag.parse().unwrap());
                        if vid != "null" {
                            hm.insert("x-amz-version-id", vid.parse().unwrap());
                        }
                        if let Some(ref algo) = sse_algo {
                            hm.insert("x-amz-server-side-encryption", algo.parse().unwrap());
                        }
                        (StatusCode::OK, hm).into_response(cx)
                    }
                    _ => {
                        let err_xml = kappa_module_s3::encode_s3_error_xml(
                            "InternalError", "put failed",
                        );
                        (StatusCode::INTERNAL_SERVER_ERROR, [
                            ("content-type", "application/xml"),
                        ], err_xml).into_response(cx)
                    }
                }
            })
        }

        fn s3_get_object(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let bucket_ns = s3_bucket_read(cx)?;
                let bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let key = raw_path_params(cx).find(|(k, _)| *k == "key")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let query = parse_s3_query(cx);
                let version_id = query.get("versionId").cloned();

                // Item 39: ListParts dispatch
                if let Some(upload_id) = query.get("uploadId") {
                    let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                    let uid = upload_id.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        let received = store.upload_bytes_received(&uid);
                        if received.is_none() {
                            return Err(kappa_core::types::StoreError::NotFound(format!("upload {}", uid)));
                        }
                        Ok(Vec::<kappa_module_s3::xml::PartInfo>::new())
                    }).await;
                    match result {
                        Ok(Ok(parts)) => {
                            let xml = kappa_module_s3::encode_list_parts_xml(&parts);
                            return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response(cx);
                        }
                        _ => {
                            let err = kappa_module_s3::encode_s3_error_xml("NoSuchUpload", "upload not found");
                            return (StatusCode::NOT_FOUND, [("content-type", "application/xml")], err).into_response(cx);
                        }
                    }
                }

                // Item 43: Object tagging GET
                if query.contains_key("tagging") {
                    let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                    let _bucket_name = bucket.clone();
                    let k = key.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        let b = bucket_ns.clone();
                        let entry = store.tag_get(&b, &k)?;
                        match store.blob_get_meta(&entry.kappa, "_s3_tags") {
                            Ok(raw) => Ok(raw),
                            Err(kappa_core::types::StoreError::NotFound(_)) => Ok(b"[]".to_vec()),
                            Err(e) => Err(e),
                        }
                    }).await;
                    match result {
                        Ok(Ok(raw)) => {
                            // Convert JSON tag array to XML
                            let tags: Vec<(String, String)> = serde_json::from_slice(&raw).unwrap_or_default();
                            let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Tagging><TagSet>");
                            for (k, v) in &tags {
                                xml.push_str(&format!("<Tag><Key>{}</Key><Value>{}</Value></Tag>", k, v));
                            }
                            xml.push_str("</TagSet></Tagging>");
                            return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response(cx);
                        }
                        _ => {
                            let err = kappa_module_s3::encode_s3_error_xml("NoSuchKey", "key not found");
                            return (StatusCode::NOT_FOUND, [("content-type", "application/xml")], err).into_response(cx);
                        }
                    }
                }

                // Item 48: GetObjectAttributes
                if query.contains_key("attributes") {
                    let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                    let _bucket_name = bucket.clone();
                    let k = key.clone();
                    // x-amz-object-attributes header specifies which attributes to return
                    let requested_attrs = {
                        use topcoat::context::request_context;
                        let parts: &http::request::Parts = request_context(cx);
                        parts.headers.get("x-amz-object-attributes")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("ETag,ObjectSize,StorageClass")
                            .to_string()
                    };
                    let result = tokio::task::spawn_blocking(move || {
                        let b = bucket_ns.clone();
                        let entry = store.tag_get(&b, &k)?;
                        let size = store.blob_size(&entry.kappa)?;
                        Ok::<(String, u64), kappa_core::types::StoreError>((entry.kappa, size))
                    }).await;
                    match result {
                        Ok(Ok((kappa, size))) => {
                            let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><GetObjectAttributesResponse>");
                            if requested_attrs.contains("ETag") {
                                xml.push_str(&format!("<ETag>\"{}\"</ETag>", kappa));
                            }
                            if requested_attrs.contains("ObjectSize") {
                                xml.push_str(&format!("<ObjectSize>{}</ObjectSize>", size));
                            }
                            if requested_attrs.contains("StorageClass") {
                                xml.push_str("<StorageClass>STANDARD</StorageClass>");
                            }
                            xml.push_str("</GetObjectAttributesResponse>");
                            return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response(cx);
                        }
                        _ => {
                            let err = kappa_module_s3::encode_s3_error_xml("NoSuchKey", "key not found");
                            return (StatusCode::NOT_FOUND, [("content-type", "application/xml")], err).into_response(cx);
                        }
                    }
                }

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    let (kappa, content, vid) = match store.version_get(&bucket, &key, version_id.as_deref()) {
                        Ok(ve) => {
                            let kappa = ve.kappa.ok_or_else(|| {
                                kappa_core::types::StoreError::NotFound(
                                    format!("{}/{} (delete marker: {})", bucket, key, ve.version_id)
                                )
                            })?;
                            let content = store.blob_get(&kappa)?;
                            (kappa, content, ve.version_id)
                        }
                        Err(kappa_core::types::StoreError::Rejected(_)) => {
                            let entry = store.tag_get(&bucket, &key)?;
                            let content = store.blob_get(&entry.kappa)?;
                            (entry.kappa, content, "null".to_string())
                        }
                        Err(e) => return Err(e),
                    };
                    // Read stored metadata for response headers
                    let sse = store.blob_get_meta(&kappa, "_s3_sse").ok()
                        .and_then(|b| String::from_utf8(b).ok());
                    let ct = store.blob_get_meta(&kappa, "content-type").ok()
                        .and_then(|b| String::from_utf8(b).ok());
                    let etag = store.blob_get_meta(&kappa, "_s3_etag").ok()
                        .and_then(|b| String::from_utf8(b).ok());
                    let created = store.blob_get_meta(&kappa, "_s3_created_ms").ok()
                        .and_then(|b| String::from_utf8(b).ok());
                    Ok((kappa, content, vid, sse, ct, etag, created))
                }).await;

                match result {
                    Ok(Ok((kappa, content, vid, sse, ct, stored_etag, created))) => {
                        let mut hm = http::HeaderMap::new();
                        // Fix 6: Return Content-Type from PUT, default octet-stream
                        hm.insert("content-type", ct.unwrap_or_else(|| "application/octet-stream".to_string()).parse().unwrap());
                        // Fix 2: Return stored MD5 ETag, fall back to kappa
                        let etag_val = stored_etag.unwrap_or_else(|| format!("\"{}\"", kappa));
                        hm.insert("etag", etag_val.parse().unwrap());
                        hm.insert("content-length", content.len().to_string().parse().unwrap());
                        // Fix 7: Last-Modified from _s3_created_ms
                        if let Some(ref ms_str) = created {
                            if let Ok(ms) = ms_str.parse::<u64>() {
                                let http_date = kappa_core::clock::epoch_ms_to_http_date(ms);
                                hm.insert("last-modified", http_date.parse().unwrap());
                            }
                        }
                        if vid != "null" {
                            hm.insert("x-amz-version-id", vid.parse().unwrap());
                        }
                        if let Some(algo) = sse {
                            hm.insert("x-amz-server-side-encryption", algo.parse().unwrap());
                        }
                        (StatusCode::OK, hm, content).into_response(cx)
                    }
                    Ok(Err(kappa_core::types::StoreError::NotFound(msg))) => {
                        let mut hm = http::HeaderMap::new();
                        hm.insert("content-type", "application/xml".parse().unwrap());
                        if msg.contains("delete marker:") {
                            hm.insert("x-amz-delete-marker", "true".parse().unwrap());
                            if let Some(vid) = msg.split("delete marker: ").nth(1).and_then(|s| s.strip_suffix(')')) {
                                hm.insert("x-amz-version-id", vid.parse().unwrap());
                            }
                        }
                        let err_xml = kappa_module_s3::encode_s3_error_xml(
                            "NoSuchKey", "The specified key does not exist.",
                        );
                        (StatusCode::NOT_FOUND, hm, err_xml).into_response(cx)
                    }
                    _ => {
                        let err_xml = kappa_module_s3::encode_s3_error_xml(
                            "InternalError", "get failed",
                        );
                        (StatusCode::INTERNAL_SERVER_ERROR, [
                            ("content-type", "application/xml".to_string()),
                        ], err_xml).into_response(cx)
                    }
                }
            })
        }

        fn s3_head_object(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let bucket_ns = s3_bucket_read(cx)?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let key = raw_path_params(cx).find(|(k, _)| *k == "key")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let query = parse_s3_query(cx);
                let version_id = query.get("versionId").cloned();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    match store.version_get(&bucket, &key, version_id.as_deref()) {
                        Ok(ve) => {
                            let kappa = ve.kappa.ok_or_else(|| {
                                kappa_core::types::StoreError::NotFound(
                                    format!("{}/{} (delete marker: {})", bucket, key, ve.version_id)
                                )
                            })?;
                            let size = store.blob_size(&kappa)?;
                            let ct = store.blob_get_meta(&kappa, "content-type").ok()
                                .and_then(|b| String::from_utf8(b).ok());
                            let etag = store.blob_get_meta(&kappa, "_s3_etag").ok()
                                .and_then(|b| String::from_utf8(b).ok());
                            let created = store.blob_get_meta(&kappa, "_s3_created_ms").ok()
                                .and_then(|b| String::from_utf8(b).ok());
                            Ok((kappa, size, ve.version_id, ct, etag, created))
                        }
                        Err(kappa_core::types::StoreError::Rejected(_)) => {
                            let entry = store.tag_get(&bucket, &key)?;
                            let size = store.blob_size(&entry.kappa)?;
                            let ct = store.blob_get_meta(&entry.kappa, "content-type").ok()
                                .and_then(|b| String::from_utf8(b).ok());
                            let etag = store.blob_get_meta(&entry.kappa, "_s3_etag").ok()
                                .and_then(|b| String::from_utf8(b).ok());
                            let created = store.blob_get_meta(&entry.kappa, "_s3_created_ms").ok()
                                .and_then(|b| String::from_utf8(b).ok());
                            Ok((entry.kappa, size, "null".to_string(), ct, etag, created))
                        }
                        Err(e) => Err(e),
                    }
                }).await;

                match result {
                    Ok(Ok((kappa, size, vid, ct, stored_etag, created))) => {
                        let mut hm = http::HeaderMap::new();
                        hm.insert("content-type", ct.unwrap_or_else(|| "application/octet-stream".to_string()).parse().unwrap());
                        let etag_val = stored_etag.unwrap_or_else(|| format!("\"{}\"", kappa));
                        hm.insert("etag", etag_val.parse().unwrap());
                        hm.insert("content-length", size.to_string().parse().unwrap());
                        if let Some(ref ms_str) = created {
                            if let Ok(ms) = ms_str.parse::<u64>() {
                                let dt = kappa_core::clock::epoch_ms_to_datetime(ms);
                                if let Ok(epoch_secs) = kappa_core::clock::parse_datetime_to_epoch_secs(&dt) {
                                    if let Some(dt_utc) = chrono::DateTime::from_timestamp(epoch_secs as i64, 0) {
                                        let http_date = dt_utc.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
                                        hm.insert("last-modified", http_date.parse().unwrap());
                                    }
                                }
                            }
                        }
                        if vid != "null" {
                            hm.insert("x-amz-version-id", vid.parse().unwrap());
                        }
                        (StatusCode::OK, hm).into_response(cx)
                    }
                    Ok(Err(kappa_core::types::StoreError::NotFound(msg))) => {
                        if msg.contains("delete marker:") {
                            (StatusCode::NOT_FOUND, [
                                ("x-amz-delete-marker", "true"),
                            ]).into_response(cx)
                        } else {
                            StatusCode::NOT_FOUND.into_response(cx)
                        }
                    }
                    _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(cx),
                }
            })
        }

        fn s3_delete_object(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let key = raw_path_params(cx).find(|(k, _)| *k == "key")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let query = parse_s3_query(cx);
                let version_id = query.get("versionId").cloned();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    match store.version_delete(&bucket, &key, version_id.as_deref()) {
                        Ok(dr) => Ok(dr),
                        Err(kappa_core::types::StoreError::Rejected(_)) => {
                            // Versioning not implemented -- fallback to tag_delete
                            store.tag_delete(&bucket, &key)?;
                            Ok(kappa_core::types::DeleteResult {
                                version_id: "null".to_string(),
                                is_delete_marker: false,
                            })
                        }
                        Err(e) => Err(e),
                    }
                }).await;

                match result {
                    Ok(Ok(dr)) => {
                        let mut hm = http::HeaderMap::new();
                        if dr.is_delete_marker {
                            hm.insert("x-amz-delete-marker", "true".parse().unwrap());
                        }
                        if dr.version_id != "null" {
                            hm.insert("x-amz-version-id", dr.version_id.parse().unwrap());
                        }
                        (StatusCode::NO_CONTENT, hm).into_response(cx)
                    }
                    _ => StatusCode::NO_CONTENT.into_response(cx),
                }
            })
        }

        fn s3_create_bucket(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                // "Create" a bucket by touching a marker tag
                let _ = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    store.tag_set(&bucket, "_bucket_marker", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
                }).await;

                StatusCode::OK.into_response(cx)
            })
        }

        fn s3_head_bucket(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let _bucket_ns = s3_bucket_read(cx)?;
                let bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                let exists = tokio::task::spawn_blocking(move || {
                    store.namespace_exists(&bucket, Some("s3")).unwrap_or(false)
                }).await.unwrap_or(false);

                if exists {
                    StatusCode::OK.into_response(cx)
                } else {
                    let err_xml = kappa_module_s3::encode_s3_error_xml(
                        "NoSuchBucket", "The specified bucket does not exist.",
                    );
                    (StatusCode::NOT_FOUND, [
                        ("content-type", "application/xml".to_string()),
                    ], err_xml).into_response(cx)
                }
            })
        }

        fn s3_delete_bucket(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    // S3 DeleteBucket requires the bucket to be empty.
                    // Check tag_list: if any non-marker tags exist, reject.
                    let tags = store.tag_list(&bucket)?;
                    let non_marker: Vec<_> = tags.iter()
                        .filter(|t| t.name != "_bucket_marker")
                        .collect();
                    if !non_marker.is_empty() {
                        return Err(kappa_core::types::StoreError::Conflict(
                            "BucketNotEmpty".to_string(),
                        ));
                    }
                    // Delete the bucket marker tag
                    let _ = store.tag_delete(&bucket, "_bucket_marker");
                    Ok(())
                }).await;

                match result {
                    Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(cx),
                    Ok(Err(kappa_core::types::StoreError::Conflict(_))) => {
                        let err_xml = kappa_module_s3::encode_s3_error_xml(
                            "BucketNotEmpty",
                            "The bucket you tried to delete is not empty.",
                        );
                        (StatusCode::CONFLICT, [
                            ("content-type", "application/xml".to_string()),
                        ], err_xml).into_response(cx)
                    }
                    Ok(Err(kappa_core::types::StoreError::NotFound(_))) => {
                        let err_xml = kappa_module_s3::encode_s3_error_xml(
                            "NoSuchBucket",
                            "The specified bucket does not exist.",
                        );
                        (StatusCode::NOT_FOUND, [
                            ("content-type", "application/xml".to_string()),
                        ], err_xml).into_response(cx)
                    }
                    _ => {
                        let err_xml = kappa_module_s3::encode_s3_error_xml(
                            "InternalError", "delete bucket failed",
                        );
                        (StatusCode::INTERNAL_SERVER_ERROR, [
                            ("content-type", "application/xml".to_string()),
                        ], err_xml).into_response(cx)
                    }
                }
            })
        }

        fn s3_list_buckets(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                let result = tokio::task::spawn_blocking(move || {
                    store.namespace_list(Some("s3"))
                }).await;

                match result {
                    Ok(Ok(namespaces)) => {
                        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                        xml.push_str("<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
                        xml.push_str("<Buckets>");
                        for rec in &namespaces {
                            for alias in &rec.aliases {
                                xml.push_str("<Bucket><Name>");
                                xml.push_str(alias);
                                xml.push_str("</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate></Bucket>");
                            }
                        }
                        xml.push_str("</Buckets></ListAllMyBucketsResult>");
                        (StatusCode::OK, [
                            ("content-type", "application/xml".to_string()),
                        ], xml).into_response(cx)
                    }
                    _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(cx),
                }
            })
        }

        // -- S3 Multipart Upload --

        fn s3_initiate_multipart(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let key = raw_path_params(cx).find(|(k, _)| *k == "key")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let max_size = app_context::<MaxBlobSize>(cx).0 as u64;

                let bucket_for_xml = bucket.clone();
                let key_for_xml = key.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    store.upload_begin(&bucket, max_size)
                }).await;

                match result {
                    Ok(Ok(upload_id)) => {
                        let xml = kappa_module_s3::encode_initiate_multipart_xml(&bucket_for_xml, &key_for_xml, &upload_id);
                        (StatusCode::OK, [
                            ("content-type", "application/xml".to_string()),
                        ], xml).into_response(cx)
                    }
                    _ => {
                        let err = kappa_module_s3::encode_s3_error_xml("InternalError", "initiate failed");
                        (StatusCode::INTERNAL_SERVER_ERROR, [("content-type", "application/xml".to_string())], err).into_response(cx)
                    }
                }
            })
        }

        fn s3_upload_part(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let query = parse_s3_query(cx);
                let upload_id = query.get("uploadId").cloned().unwrap_or_default();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                // Fix 1: Stream body to upload_put_part in chunks.
                // Read body frames via http-body, write each to store.
                // One frame in memory at a time. No 5 GiB allocation.
                use http_body_util::BodyExt;
                let mut offset = store.upload_bytes_received(&upload_id).unwrap_or(0);
                let mut body = body;
                let mut total: u64 = offset;
                let mut part_error: Option<kappa_core::types::StoreError> = None;

                while let Some(frame_result) = body.frame().await {
                    match frame_result {
                        Ok(frame) => {
                            if let Some(data) = frame.data_ref() {
                                let chunk = data.to_vec();
                                let uid = upload_id.clone();
                                let s = store.clone();
                                let off = offset;
                                match tokio::task::spawn_blocking(move || {
                                    s.upload_put_part(&uid, off, &chunk)
                                }).await {
                                    Ok(Ok(new_total)) => {
                                        offset = new_total;
                                        total = new_total;
                                    }
                                    Ok(Err(e)) => { part_error = Some(e); break; }
                                    Err(e) => {
                                        part_error = Some(kappa_core::types::StoreError::Io(
                                            std::io::Error::other(e.to_string())
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }

                if let Some(e) = part_error {
                    let err = kappa_module_s3::encode_s3_error_xml("InternalError", &e.to_string());
                    return (StatusCode::INTERNAL_SERVER_ERROR, [("content-type", "application/xml".to_string())], err).into_response(cx);
                }

                // Per-part ETag: MD5 of the part data (already computed by upload_put_part)
                let _ = total;
                (StatusCode::OK, [
                    ("etag", "\"part\"".to_string()),
                ]).into_response(cx)
            })
        }

        fn s3_complete_multipart(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let key = raw_path_params(cx).find(|(k, _)| *k == "key")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let query = parse_s3_query(cx);
                let upload_id = query.get("uploadId").cloned().unwrap_or_default();

                // Fix 8: Parse CompleteMultipartUpload XML body
                // Format: <CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"..."</ETag></Part>...</CompleteMultipartUpload>
                let body_bytes = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 10 * 1024 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
                };
                let body_str = String::from_utf8_lossy(&body_bytes);
                let mut client_parts: Vec<(u32, String)> = Vec::new();
                let mut remaining = body_str.as_ref();
                while let Some(part_start) = remaining.find("<Part>") {
                    let after = &remaining[part_start..];
                    if let Some(part_end) = after.find("</Part>") {
                        let block = &after[6..part_end];
                        let pn = block.find("<PartNumber>").and_then(|s| {
                            block[s+12..].find("</PartNumber>").and_then(|e| block[s+12..s+12+e].parse::<u32>().ok())
                        });
                        let etag = block.find("<ETag>").and_then(|s| {
                            block[s+6..].find("</ETag>").map(|e| block[s+6..s+6+e].to_string())
                        });
                        if let (Some(pn), Some(etag)) = (pn, etag) {
                            client_parts.push((pn, etag));
                        }
                        remaining = &after[part_end + 7..];
                    } else { break; }
                }
                // Sort by part number (S3 requires ascending order)
                client_parts.sort_by_key(|(pn, _)| *pn);

                // Content-Type from the initiate request (stored as upload metadata if available)
                let content_type_header = {
                    let parts: &http::request::Parts = request_context(cx);
                    parts.headers.get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                };

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let bucket_for_xml = bucket.clone();

                // Fix 8: Validate client part list against uploaded parts BEFORE completing
                if !client_parts.is_empty() {
                    let uid_for_check = upload_id.clone();
                    let s_for_check = store.clone();
                    let validation = tokio::task::spawn_blocking(move || {
                        let stored = s_for_check.upload_part_info(&uid_for_check);
                        if stored.is_empty() {
                            return Err("NoSuchUpload".to_string());
                        }
                        // Check ascending order
                        for i in 1..client_parts.len() {
                            if client_parts[i].0 <= client_parts[i - 1].0 {
                                return Err(format!(
                                    "InvalidPartOrder: part {} listed before or equal to part {}",
                                    client_parts[i].0, client_parts[i - 1].0
                                ));
                            }
                        }
                        // Check each listed part exists and ETag matches
                        for (pn, client_etag) in &client_parts {
                            let found = stored.iter().find(|(spn, _, _)| spn == pn);
                            match found {
                                None => return Err(format!(
                                    "InvalidPart: part {} was not uploaded", pn
                                )),
                                Some((_, stored_etag, _)) => {
                                    // Normalize: strip surrounding quotes for comparison
                                    let ce = client_etag.trim_matches('"');
                                    let se = stored_etag.trim_matches('"');
                                    if ce != se {
                                        return Err(format!(
                                            "InvalidPart: ETag mismatch for part {}: client={}, stored={}",
                                            pn, ce, se
                                        ));
                                    }
                                }
                            }
                        }
                        Ok(())
                    }).await;
                    match validation {
                        Ok(Err(msg)) => {
                            let code = if msg.starts_with("InvalidPartOrder") { "InvalidPartOrder" } else { "InvalidPart" };
                            let err = kappa_module_s3::encode_s3_error_xml(code, &msg);
                            return (StatusCode::BAD_REQUEST, [("content-type", "application/xml")], err).into_response(cx);
                        }
                        Err(e) => {
                            let err = kappa_module_s3::encode_s3_error_xml("InternalError", &e.to_string());
                            return (StatusCode::INTERNAL_SERVER_ERROR, [("content-type", "application/xml")], err).into_response(cx);
                        }
                        Ok(Ok(())) => {} // validation passed
                    }
                }

                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    let ingest_result = store.upload_complete(&upload_id, None)?;
                    store.tag_set(&bucket, &key, &ingest_result.kappa)?;
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let _ = store.blob_put_meta(&ingest_result.kappa, "_s3_created_ms", now_ms.to_string().as_bytes());

                    // Fix 3: composite ETag from IngestResult.etag (md5-of-md5s-N)
                    let etag = ingest_result.etag.unwrap_or_else(|| {
                        // Fallback: compute MD5 of content for single-chunk uploads
                        format!("\"{}\"", ingest_result.kappa)
                    });
                    let _ = store.blob_put_meta(&ingest_result.kappa, "_s3_etag", etag.as_bytes());

                    // Store content-type if provided
                    if let Some(ref ct) = content_type_header {
                        let _ = store.blob_put_meta(&ingest_result.kappa, "content-type", ct.as_bytes());
                    }

                    Ok::<(String, String), kappa_core::types::StoreError>((key.clone(), etag))
                }).await;

                match result {
                    Ok(Ok((completed_key, etag))) => {
                        let xml = kappa_module_s3::encode_complete_multipart_xml(&bucket_for_xml, &completed_key, &etag);
                        (StatusCode::OK, [
                            ("content-type", "application/xml".to_string()),
                        ], xml).into_response(cx)
                    }
                    _ => {
                        let err = kappa_module_s3::encode_s3_error_xml("InternalError", "complete failed");
                        (StatusCode::INTERNAL_SERVER_ERROR, [("content-type", "application/xml".to_string())], err).into_response(cx)
                    }
                }
            })
        }

        fn s3_abort_multipart(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let query = parse_s3_query(cx);
                let upload_id = query.get("uploadId").cloned().unwrap_or_default();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let _ = tokio::task::spawn_blocking(move || {
                    store.upload_abort(&upload_id)
                }).await;

                StatusCode::NO_CONTENT.into_response(cx)
            })
        }

        fn s3_delete_objects(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let bucket_ns = s3_bucket_write(cx).await?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let body_bytes = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 10 * 1024 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
                };

                // Parse the XML body to extract keys to delete
                // Format: <Delete><Object><Key>...</Key></Object>...</Delete>
                let body_str = String::from_utf8_lossy(&body_bytes);
                let mut keys_to_delete: Vec<String> = Vec::new();
                // Simple XML extraction -- find all <Key>...</Key> values
                let mut remaining = body_str.as_ref();
                while let Some(start) = remaining.find("<Key>") {
                    let after_tag = &remaining[start + 5..];
                    if let Some(end) = after_tag.find("</Key>") {
                        keys_to_delete.push(after_tag[..end].to_string());
                        remaining = &after_tag[end + 6..];
                    } else {
                        break;
                    }
                }

                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    let mut deleted = Vec::new();
                    let mut errors: Vec<(String, String, String)> = Vec::new();
                    for key in &keys_to_delete {
                        match store.tag_delete(&bucket, key) {
                            Ok(()) => deleted.push(key.clone()),
                            Err(e) => errors.push((key.clone(), "InternalError".into(), e.to_string())),
                        }
                    }
                    Ok::<_, kappa_core::types::StoreError>((deleted, errors))
                }).await;

                match result {
                    Ok(Ok((deleted, errors))) => {
                        let xml = kappa_module_s3::encode_delete_result_xml(&deleted, &errors);
                        (StatusCode::OK, [
                            ("content-type", "application/xml".to_string()),
                        ], xml).into_response(cx)
                    }
                    _ => {
                        let err = kappa_module_s3::encode_s3_error_xml("InternalError", "batch delete failed");
                        (StatusCode::INTERNAL_SERVER_ERROR, [("content-type", "application/xml".to_string())], err).into_response(cx)
                    }
                }
            })
        }

        fn s3_copy_object(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let key = raw_path_params(cx).find(|(k, _)| *k == "key")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();

                // x-amz-copy-source header: /source-bucket/source-key
                let copy_source = {
                    use topcoat::context::request_context;
                    let parts: &http::request::Parts = request_context(cx);
                    parts.headers.get("x-amz-copy-source")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string()
                };

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    // Parse copy source: /bucket/key or bucket/key
                    let source = copy_source.strip_prefix('/').unwrap_or(&copy_source);
                    let (src_bucket, src_key) = source.split_once('/')
                        .ok_or_else(|| kappa_core::types::StoreError::Rejected("invalid copy source".into()))?;

                    let src_ns = store.namespace_resolve(src_bucket, Some("s3"))?;
                    let src_entry = store.tag_get(&src_ns, src_key)?;
                    store.tag_set(&bucket, &key, &src_entry.kappa)?;
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let _ = store.blob_put_meta(&src_entry.kappa, "_s3_created_ms", now_ms.to_string().as_bytes());
                    Ok::<String, kappa_core::types::StoreError>(src_entry.kappa)
                }).await;

                match result {
                    Ok(Ok(kappa)) => {
                        let etag = format!("\"{}\"", kappa);
                        let xml = kappa_module_s3::encode_copy_result_xml(&etag, "");
                        (StatusCode::OK, [
                            ("content-type", "application/xml".to_string()),
                        ], xml).into_response(cx)
                    }
                    Ok(Err(kappa_core::types::StoreError::NotFound(_))) => {
                        let err = kappa_module_s3::encode_s3_error_xml("NoSuchKey", "source key not found");
                        (StatusCode::NOT_FOUND, [("content-type", "application/xml".to_string())], err).into_response(cx)
                    }
                    _ => {
                        let err = kappa_module_s3::encode_s3_error_xml("InternalError", "copy failed");
                        (StatusCode::INTERNAL_SERVER_ERROR, [("content-type", "application/xml".to_string())], err).into_response(cx)
                    }
                }
            })
        }

        // PUT/GET /{bucket}?versioning -- versioning configuration
        fn s3_put_versioning(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let body_bytes = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 64 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
                };

                // Parse <VersioningConfiguration><Status>Enabled|Suspended</Status></VersioningConfiguration>
                let body_str = String::from_utf8_lossy(&body_bytes);
                let status_value = if body_str.contains("<Status>Enabled</Status>") {
                    "enabled"
                } else if body_str.contains("<Status>Suspended</Status>") {
                    "suspended"
                } else {
                    "unversioned"
                };

                let _ = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    store.tag_set(&bucket, "_config/versioning", status_value)
                }).await;

                StatusCode::OK.into_response(cx)
            })
        }

        fn s3_get_versioning(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_read(cx)?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();

                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();

                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    match store.tag_get(&bucket, "_config/versioning") {
                        Ok(entry) => Ok(entry.kappa),
                        Err(kappa_core::types::StoreError::NotFound(_)) => Ok(String::new()),
                        Err(e) => Err(e),
                    }
                }).await;

                let status_str = match result {
                    Ok(Ok(s)) => s,
                    _ => String::new(),
                };

                let xml_status = match status_str.as_str() {
                    "enabled" => "<Status>Enabled</Status>",
                    "suspended" => "<Status>Suspended</Status>",
                    _ => "",
                };
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     {}\
                     </VersioningConfiguration>",
                    xml_status
                );
                (StatusCode::OK, [("content-type", "application/xml")], xml).into_response(cx)
            })
        }

        // Unified POST /{bucket}/{key} handler -- dispatches by query params:
        // ?uploads -> InitiateMultipartUpload
        // ?uploadId=X -> CompleteMultipartUpload
        // else -> unsupported
        fn s3_post_object(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let uri = {
                    use topcoat::context::request_context;
                    let parts: &http::request::Parts = request_context(cx);
                    parts.uri.clone()
                };
                let query = uri.query().unwrap_or("");
                if query.contains("uploads") {
                    s3_initiate_multipart(cx, body).await
                } else if query.contains("uploadId") {
                    s3_complete_multipart(cx, body).await
                } else {
                    StatusCode::BAD_REQUEST.into_response(cx)
                }
            })
        }

        // Item 43: PUT /{bucket}/{key}?tagging
        fn s3_put_tagging(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let key = raw_path_params(cx).find(|(k, _)| *k == "key")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let body_bytes = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 128 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
                };
                // Parse XML: extract <Key>...</Key> and <Value>...</Value> pairs
                let body_str = String::from_utf8_lossy(&body_bytes);
                let mut tags: Vec<(String, String)> = Vec::new();
                let mut remaining = body_str.as_ref();
                while let Some(tag_start) = remaining.find("<Tag>") {
                    let after = &remaining[tag_start..];
                    if let Some(tag_end) = after.find("</Tag>") {
                        let tag_block = &after[5..tag_end];
                        let k = tag_block.find("<Key>").and_then(|s| {
                            tag_block[s+5..].find("</Key>").map(|e| tag_block[s+5..s+5+e].to_string())
                        });
                        let v = tag_block.find("<Value>").and_then(|s| {
                            tag_block[s+7..].find("</Value>").map(|e| tag_block[s+7..s+7+e].to_string())
                        });
                        if let (Some(k), Some(v)) = (k, v) {
                            if tags.len() < 10 { tags.push((k, v)); }
                        }
                        remaining = &after[tag_end+6..];
                    } else { break; }
                }
                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    let entry = store.tag_get(&bucket, &key)?;
                    let json = serde_json::to_vec(&tags)
                        .map_err(|e| kappa_core::types::StoreError::Io(std::io::Error::other(e.to_string())))?;
                    store.blob_put_meta(&entry.kappa, "_s3_tags", &json)
                }).await;
                match result {
                    Ok(Ok(())) => StatusCode::OK.into_response(cx),
                    _ => {
                        let err = kappa_module_s3::encode_s3_error_xml("InternalError", "put tagging failed");
                        (StatusCode::INTERNAL_SERVER_ERROR, [("content-type", "application/xml")], err).into_response(cx)
                    }
                }
            })
        }

        // Item 43: DELETE /{bucket}/{key}?tagging
        fn s3_delete_tagging(cx: &Cx, _body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let key = raw_path_params(cx).find(|(k, _)| *k == "key")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let _ = tokio::task::spawn_blocking(move || -> Result<(), kappa_core::types::StoreError> {
                    let bucket = bucket_ns.clone();
                    if let Ok(entry) = store.tag_get(&bucket, &key) {
                        let _ = store.blob_delete_meta(&entry.kappa, "_s3_tags");
                    }
                    Ok(())
                }).await;
                StatusCode::NO_CONTENT.into_response(cx)
            })
        }

        // Unified PUT /{bucket}/{key} handler -- dispatches by query/header:
        // ?tagging -> PutObjectTagging
        // x-amz-copy-source header -> CopyObject
        // ?partNumber=&uploadId= -> UploadPart
        // else -> PutObject
        fn s3_put_or_copy_or_part(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let (has_copy_source, has_part_number, has_tagging) = {
                    use topcoat::context::request_context;
                    let parts: &http::request::Parts = request_context(cx);
                    let copy = parts.headers.contains_key("x-amz-copy-source");
                    let q = parts.uri.query().unwrap_or("");
                    let part = q.contains("partNumber");
                    let tagging = q.contains("tagging");
                    (copy, part, tagging)
                };
                if has_tagging {
                    s3_put_tagging(cx, body).await
                } else if has_copy_source {
                    s3_copy_object(cx, body).await
                } else if has_part_number {
                    s3_upload_part(cx, body).await
                } else {
                    s3_put_object(cx, body).await
                }
            })
        }

        // Unified DELETE /{bucket}/{key} handler -- dispatches by query:
        // ?tagging -> DeleteObjectTagging
        // ?uploadId= -> AbortMultipartUpload
        // else -> DeleteObject
        fn s3_delete_or_abort(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let (has_upload_id, has_tagging) = {
                    use topcoat::context::request_context;
                    let parts: &http::request::Parts = request_context(cx);
                    let q = parts.uri.query().unwrap_or("");
                    (q.contains("uploadId"), q.contains("tagging"))
                };
                if has_tagging {
                    s3_delete_tagging(cx, body).await
                } else if has_upload_id {
                    s3_abort_multipart(cx, body).await
                } else {
                    s3_delete_object(cx, body).await
                }
            })
        }

        // Item 44/45: Generic bucket config PUT/GET/DELETE for lifecycle, cors, policy
        fn s3_put_bucket_config<'a>(cx: &'a Cx, body: Body, config_key: &'static str) -> RouteFuture<'a> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let body_bytes = {
                    use topcoat::router::to_bytes;
                    to_bytes(body, 256 * 1024).await.map(|b| b.to_vec()).unwrap_or_default()
                };
                let tag_name = format!("_config/{}", config_key);
                let _ = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    let kappa = kappa_core::kappa::kappa_from_bytes(&body_bytes);
                    let _ = store.ingest_verified(&kappa, &body_bytes);
                    store.tag_set(&bucket, &tag_name, &kappa)
                }).await;
                StatusCode::OK.into_response(cx)
            })
        }

        fn s3_get_bucket_config<'a>(cx: &'a Cx, _body: Body, config_key: &'static str) -> RouteFuture<'a> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_read(cx)?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let tag_name = format!("_config/{}", config_key);
                let result = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    let entry = store.tag_get(&bucket, &tag_name)?;
                    store.blob_get(&entry.kappa)
                }).await;
                match result {
                    Ok(Ok(content)) => (StatusCode::OK, [
                        ("content-type", "application/xml"),
                    ], content).into_response(cx),
                    _ => {
                        let err = kappa_module_s3::encode_s3_error_xml(
                            "NoSuchConfiguration",
                            &format!("{} configuration not found", config_key),
                        );
                        (StatusCode::NOT_FOUND, [("content-type", "application/xml")], err).into_response(cx)
                    }
                }
            })
        }

        fn s3_delete_bucket_config<'a>(cx: &'a Cx, _body: Body, config_key: &'static str) -> RouteFuture<'a> {
            Box::pin(async move {
                let bucket_ns = s3_bucket_write(cx).await?;
                let _bucket = raw_path_params(cx).find(|(k, _)| *k == "bucket")
                    .map(|(_, v)| v.as_str().to_string()).unwrap_or_default();
                let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
                let tag_name = format!("_config/{}", config_key);
                let _ = tokio::task::spawn_blocking(move || {
                    let bucket = bucket_ns.clone();
                    store.tag_delete(&bucket, &tag_name)
                }).await;
                StatusCode::NO_CONTENT.into_response(cx)
            })
        }

        // Unified bucket-level PUT: dispatches by query param
        fn s3_put_bucket_dispatch(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let query = parse_s3_query(cx);
                if query.contains_key("versioning") {
                    s3_put_versioning(cx, body).await
                } else if query.contains_key("lifecycle") {
                    s3_put_bucket_config(cx, body, "lifecycle").await
                } else if query.contains_key("cors") {
                    s3_put_bucket_config(cx, body, "cors").await
                } else if query.contains_key("policy") {
                    s3_put_bucket_config(cx, body, "policy").await
                } else if query.contains_key("acl") {
                    s3_put_bucket_config(cx, body, "acl").await
                } else {
                    s3_create_bucket(cx, body).await
                }
            })
        }

        // Unified bucket-level GET: dispatches by query param
        fn s3_get_bucket_dispatch(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let query = parse_s3_query(cx);
                if query.contains_key("versioning") {
                    s3_get_versioning(cx, body).await
                } else if query.contains_key("lifecycle") {
                    s3_get_bucket_config(cx, body, "lifecycle").await
                } else if query.contains_key("cors") {
                    s3_get_bucket_config(cx, body, "cors").await
                } else if query.contains_key("policy") {
                    s3_get_bucket_config(cx, body, "policy").await
                } else if query.contains_key("acl") {
                    s3_get_bucket_config(cx, body, "acl").await
                } else {
                    s3_list_objects(cx, body).await
                }
            })
        }

        // Unified bucket-level DELETE: dispatches by query param
        fn s3_delete_bucket_dispatch(cx: &Cx, body: Body) -> RouteFuture<'_> {
            Box::pin(async move {
                if let Some(r) = s3_auth_check(cx) { return Ok(r); }
                let query = parse_s3_query(cx);
                if query.contains_key("lifecycle") {
                    s3_delete_bucket_config(cx, body, "lifecycle").await
                } else if query.contains_key("cors") {
                    s3_delete_bucket_config(cx, body, "cors").await
                } else if query.contains_key("policy") {
                    s3_delete_bucket_config(cx, body, "policy").await
                } else {
                    s3_delete_bucket(cx, body).await
                }
            })
        }

        // S3 routes -- path-style. One handler per method+path, with
        // query-parameter dispatch inside the unified handlers above.
        builder = builder
            .route(RouteFn::new(Method::PUT, p("/{bucket}/{*key}"), s3_put_or_copy_or_part))
            .route(RouteFn::new(Method::GET, p("/{bucket}/{*key}"), s3_get_object))
            .route(RouteFn::new(Method::HEAD, p("/{bucket}/{*key}"), s3_head_object))
            .route(RouteFn::new(Method::DELETE, p("/{bucket}/{*key}"), s3_delete_or_abort))
            .route(RouteFn::new(Method::POST, p("/{bucket}/{*key}"), s3_post_object))
            .route(RouteFn::new(Method::GET, p("/{bucket}"), s3_get_bucket_dispatch))
            .route(RouteFn::new(Method::PUT, p("/{bucket}"), s3_put_bucket_dispatch))
            .route(RouteFn::new(Method::HEAD, p("/{bucket}"), s3_head_bucket))
            .route(RouteFn::new(Method::DELETE, p("/{bucket}"), s3_delete_bucket_dispatch))
            .route(RouteFn::new(Method::POST, p("/{bucket}"), s3_delete_objects))
            .route(RouteFn::new(Method::GET, p("/"), s3_list_buckets));

        tracing::info!("S3-compatible API enabled (path-style)");
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

    // -- S3 lifecycle background task (item 44) --
    // Checks every 24 hours (configurable via KAPPA_LIFECYCLE_INTERVAL_SECS).
    // For each namespace with a _config/lifecycle tag, evaluates expiration rules.
    let lifecycle_store = store.clone();
    let lifecycle_interval_secs: u64 = std::env::var("KAPPA_LIFECYCLE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(86400);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(lifecycle_interval_secs));
        loop {
            interval.tick().await;
            let s = lifecycle_store.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let namespaces = match s.namespace_list(None) {
                    Ok(ns) => ns,
                    Err(_) => return,
                };
                for rec in &namespaces {
                    let ns_name = rec.aliases.first().map(|s| s.as_str()).unwrap_or(&rec.uuid_hex);
                    let uuid_bytes = hex::decode(&rec.uuid_hex).unwrap_or_default(); if uuid_bytes.len() != 16 { continue; } let mut uuid_arr = [0u8; 16]; uuid_arr.copy_from_slice(&uuid_bytes); let ns = NamespaceRef::with_name(uuid_arr, ns_name.to_string());
                    // Check if this namespace has a lifecycle config
                    let lifecycle_tag = match s.tag_get(&ns, "_config/lifecycle") {
                        Ok(entry) => entry,
                        Err(_) => continue,
                    };
                    let config_bytes = match s.blob_get(&lifecycle_tag.kappa) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    let config_str = String::from_utf8_lossy(&config_bytes);
                    if let Some(days_start) = config_str.find("<Days>") {
                        let after = &config_str[days_start + 6..];
                        if let Some(days_end) = after.find("</Days>") {
                            if let Ok(days) = after[..days_end].parse::<u64>() {
                                let threshold_ms = days * 86400 * 1000;
                                let now_ms = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64;
                                if let Ok(tags) = s.tag_list(&ns) {
                                    for tag in &tags {
                                        if tag.name.starts_with('_') { continue; }
                                        let created_ms = s.blob_get_meta(&tag.kappa, "_s3_created_ms")
                                            .ok()
                                            .and_then(|b| String::from_utf8(b).ok())
                                            .and_then(|s| s.parse::<u64>().ok())
                                            .unwrap_or(0);
                                        if created_ms > 0 && now_ms.saturating_sub(created_ms) >= threshold_ms {
                                            tracing::info!(
                                                ns = ns.as_str(), key = %tag.name,
                                                age_days = (now_ms - created_ms) / 86400000,
                                                "lifecycle: expiring object"
                                            );
                                            let _ = s.tag_delete(&ns, &tag.name);
                                        } else if threshold_ms == 0 {
                                            let _ = s.tag_delete(&ns, &tag.name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // AbortIncompleteMultipartUpload
                    if config_str.contains("<AbortIncompleteMultipartUpload>") {
                        if let Some(d_start) = config_str.find("<DaysAfterInitiation>") {
                            let after = &config_str[d_start + 21..];
                            if let Some(d_end) = after.find("</DaysAfterInitiation>") {
                                if let Ok(days) = after[..d_end].parse::<u64>() {
                                    s.upload_evict_expired(days * 86400);
                                }
                            }
                        }
                    }
                }
            }).await;
        }
    });

    // -- Federation probe background task --
    if !cfg.federation_peers.is_empty() {
        let probe_store = store.clone();
        let probe_identity = node_identity.clone();
        let peers = cfg.federation_peers.clone();
        let probe_interval = cfg.probe_interval_secs;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(probe_interval));
            loop {
                ticker.tick().await;
                let mut results = Vec::new();
                for peer_url in &peers {
                    let result = match reqwest::get(format!("{peer_url}/_status")).await {
                        Ok(resp) if resp.status().is_success() => {
                            kappa_core::identity::probe::ProbeResult::Verified(
                                kappa_core::identity::trust::PeerRecord {
                                    endpoint: peer_url.to_string(),
                                    asserter_anchor: peer_url.to_string(),
                                    last_epoch: 0,
                                    state_root: String::new(),
                                }
                            )
                        }
                        _ => kappa_core::identity::probe::ProbeResult::Unreachable(
                            format!("failed to reach {peer_url}")
                        ),
                    };
                    results.push(result);
                }
                if let Some(ref ni) = probe_identity {
                    ni.update_from_probes(&results);
                    // Store trust position as tag in _system namespace
                    let system_ns = kappa_core::types::NamespaceRef::deterministic("_system");
                    let position = ni.position();
                    let key = format!("trust/position/{}", ni.anchor().as_str());
                    let _ = probe_store.tag_set(&system_ns, &key, position.as_str());
                }
            }
        });
        tracing::info!(
            peers = cfg.federation_peers.len(),
            interval_secs = cfg.probe_interval_secs,
            "federation probe task started"
        );
    }

    // -- Start --
    // Git, Nix, and S3 vhost rewrites are handled by the namespace
    // interceptor layer via topcoat rewrite(). Protocol detection uses
    // request signals (path suffixes, headers, query params), not URL
    // conventions.
    use topcoat::router::{RouterService, internal_serve};

    let service = RouterService::new(router).shutdown_timeout(Duration::from_secs(30));

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
            internal_serve(listener, service, shutdown_signal())
                .await
                .expect("TLS server error");
        }
        None => {
            tracing::info!(
                listen = %cfg.listen_addr,
                store = %cfg.store_root.display(),
                "kappa-registry starting"
            );
            let tcp = tokio::net::TcpListener::bind(&cfg.listen_addr)
                .await
                .expect("failed to bind TCP listener");
            internal_serve(tcp, service, shutdown_signal())
                .await
                .expect("server error");
        }
    }
}

/// Shutdown signal: Ctrl+C or SIGTERM on Unix.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
