//! The authenticated identity directory serving identity proofs.
//!
//! One directory over the `_identity/directory` system namespace,
//! published through the store's execution contract and signed by the
//! node's epoch authority like every other namespace; it holds no key of
//! its own. The namespace must already exist: system namespace bootstrap
//! creates it.

use std::sync::Arc;

use kappa_store::time::Clock;
use kappa_store::traits::KappaStore;
use kappa_transparency::Directory;

/// System namespace holding the directory's committed records.
pub const DIRECTORY_NAMESPACE: &str = kappa_transparency::DIRECTORY_NAMESPACE;

/// Open (or recover) the directory on a blocking worker.
pub async fn open(
    store: Arc<dyn KappaStore>,
    clock: Arc<dyn Clock>,
) -> Result<Arc<Directory>, String> {
    tokio::task::spawn_blocking(move || Directory::open(store, clock))
        .await
        .map_err(|error| format!("identity directory worker: {error}"))?
        .map(Arc::new)
        .map_err(|error| format!("identity directory: {error}"))
}
