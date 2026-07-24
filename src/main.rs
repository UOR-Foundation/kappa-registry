use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use kappa_registry::config::Config;
use kappa_registry::handlers::upload::SessionStore;
use kappa_registry::store::fs::FsStore;
use kappa_registry::transaction::TransactionManager;
use kappa_registry::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kappa_registry=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = Config::from_env();

    let store = match FsStore::new(cfg.store_root.clone()) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("failed to initialize store at {:?}: {e}", cfg.store_root);
            std::process::exit(2);
        }
    };

    let transactions = Arc::new(TransactionManager::new(
        cfg.store_root.clone(),
        cfg.max_transactions,
        cfg.max_blob_size,
        cfg.max_staging_bytes,
        cfg.upload_timeout_secs,
    ));

    let rate_limiter = if cfg.rate_limit.is_enabled() {
        tracing::info!(
            "rate limiting enabled: read={}/{}ms write={}/{}ms admin={}/{}ms",
            cfg.rate_limit.read.burst,
            cfg.rate_limit.read.period_ms,
            cfg.rate_limit.write.burst,
            cfg.rate_limit.write.period_ms,
            cfg.rate_limit.admin.burst,
            cfg.rate_limit.admin.period_ms,
        );
        Some(kappa_registry::ratelimit::TieredRateLimiter::new(
            &cfg.rate_limit,
        ))
    } else {
        None
    };

    let signer: Option<Arc<dyn kappa_registry::crypto::RegistrySigner>> = {
        let keystore = kappa_registry::crypto::keystore::KeyStore::new(store.root());
        match keystore {
            Ok(ks) => match ks.load_or_generate(&cfg.signing_algorithm) {
                Ok(s) => {
                    tracing::info!(
                        algorithm = s.algorithm(),
                        key_id = s.key_id(),
                        "signing key loaded"
                    );
                    Some(Arc::from(s))
                }
                Err(e) => {
                    tracing::warn!("signing key unavailable: {e}");
                    None
                }
            },
            Err(e) => {
                tracing::warn!("keystore initialization failed: {e}");
                None
            }
        }
    };

    let state = AppState {
        store,
        sessions: Arc::new(SessionStore::new()),
        transactions,
        rate_limiter,
        signer,
        max_blob_size: cfg.max_blob_size,
        upload_timeout_secs: cfg.upload_timeout_secs,
    };

    let listener = match TcpListener::bind(cfg.listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind {}: {e}", cfg.listen_addr);
            std::process::exit(3);
        }
    };

    tracing::info!("kappa-registry listening on {}", cfg.listen_addr);

    let cleanup_sessions = state.sessions.clone();
    let cleanup_transactions = state.transactions.clone();
    let cleanup_timeout = cfg.upload_timeout_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let evicted = cleanup_sessions.evict_expired(cleanup_timeout);
            if evicted > 0 {
                tracing::info!("upload cleanup: evicted {evicted} expired sessions");
            }
            let txn_evicted = cleanup_transactions.evict_expired();
            if txn_evicted > 0 {
                tracing::info!("transaction cleanup: evicted {txn_evicted} expired transactions");
            }
        }
    });

    let router = kappa_registry::app(state);

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
