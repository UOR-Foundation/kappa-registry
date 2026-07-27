use std::sync::Arc;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use kappa_registry::config::Config;
use kappa_registry::handlers::upload::SessionStore;
use kappa_registry::store::fs::FsStore;
use kappa_registry::transaction::TransactionManager;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kappa_registry=info".into()),
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

    let sessions = Arc::new(SessionStore::new());
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

    // Periodic cleanup task
    let cleanup_sessions = sessions.clone();
    let cleanup_transactions = transactions.clone();
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

    // Bootstrap node identity (I-1: never touches the network)
    let node_identity: Option<Arc<kappa_registry::identity::NodeIdentity>> = {
        let keystore = kappa_registry::crypto::keystore::KeyStore::new(store.root());
        match keystore {
            Ok(ks) => {
                match kappa_registry::identity::NodeIdentity::bootstrap(
                    &ks,
                    &*store,
                    &cfg.signing_algorithm,
                ) {
                    Ok(ni) => Some(Arc::new(ni)),
                    Err(e) => {
                        tracing::warn!("node identity bootstrap failed: {e}");
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!("keystore unavailable for identity bootstrap: {e}");
                None
            }
        }
    };

    let router = kappa_registry::router(
        store,
        sessions,
        transactions,
        rate_limiter,
        signer,
        node_identity,
        cfg.max_blob_size,
        cfg.upload_timeout_secs,
    );

    let listener = match tokio::net::TcpListener::bind(cfg.listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind {}: {e}", cfg.listen_addr);
            std::process::exit(3);
        }
    };

    tracing::info!("kappa-registry listening on {}", cfg.listen_addr);

    topcoat::serve(listener, router).await.unwrap();
}
