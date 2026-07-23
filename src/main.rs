use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use kappa_registry::config::Config;
use kappa_registry::handlers::upload::SessionStore;
use kappa_registry::store::fs::FsStore;
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

    let state = AppState {
        store,
        sessions: Arc::new(SessionStore::new()),
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
    let cleanup_timeout = cfg.upload_timeout_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let evicted = cleanup_sessions.evict_expired(cleanup_timeout);
            if evicted > 0 {
                tracing::info!("upload cleanup: evicted {evicted} expired sessions");
            }
        }
    });

    let router = if cfg.rate_limit_rps > 0 {
        tracing::info!(
            "rate limiting enabled: {} rps, burst {}",
            cfg.rate_limit_rps,
            cfg.rate_limit_burst
        );
        kappa_registry::app_with_rate_limit(state, cfg.rate_limit_rps, cfg.rate_limit_burst)
    } else {
        kappa_registry::app(state)
    };

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
