//! Content preparation for handlers: the request body becomes prepared
//! content on a blocking worker, outside any store writer, before the
//! execution that names it is opened.
//!
//! The prepared value is handed to the execution closure through a
//! `Mutex<Option<_>>` because the closure is `FnMut + 'static` and the
//! value is consumed by `content_install`. `execute` runs its work at most
//! once: a namespace created concurrently is resolved before the work
//! runs, never after, so the holder is emptied exactly by the installation
//! that moves the value into the execution. A later take is a programming
//! error, reported as such.
//!
//! The preparation deadline is taken when the handler calls `prepare_body`,
//! so the time the job waits for a worker counts against it, and it never
//! exceeds the request's own deadline.

use std::sync::{Arc, Mutex};

use topcoat::context::Cx;

use kappa_store::{ContentIdentity, PreparationBounds, PreparedContent};

use crate::error::HandlerError;

/// Bound on preparing one body, matching the write deadline.
pub const PREPARATION_DEADLINE: std::time::Duration = crate::execute::WRITE_DEADLINE;

/// Prepared content shared with an execution closure.
pub type Prepared = Arc<Mutex<Option<Box<dyn PreparedContent>>>>;

/// Prepare `body` under `identity` on a blocking worker.
pub async fn prepare_body(
    cx: &Cx,
    identity: ContentIdentity,
    body: Vec<u8>,
) -> Result<Prepared, HandlerError> {
    let store = crate::store::store(cx);
    let maximum =
        crate::store::try_service::<crate::MaxBlobSize>(cx).map_or(u64::MAX, |m| m.0 as u64);
    let deadline = crate::execute::request_deadline(cx, PREPARATION_DEADLINE);
    let prepared = crate::blocking::blocking(move || {
        store.prepare_content(
            identity,
            &mut body.as_slice(),
            PreparationBounds { maximum, deadline },
        )
    })
    .await?;
    Ok(Arc::new(Mutex::new(Some(prepared))))
}

/// Take the prepared content out of its holder for installation.
pub fn take_prepared(prepared: &Prepared) -> Result<Box<dyn PreparedContent>, HandlerError> {
    prepared
        .lock()
        .map_err(|_| HandlerError::internal("prepared content lock poisoned"))?
        .take()
        .ok_or_else(|| HandlerError::internal("prepared content was already installed"))
}
