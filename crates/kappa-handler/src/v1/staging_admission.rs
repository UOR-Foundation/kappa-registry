//! Reservations against the staging budget, the server's budget handle,
//! and the committed-head scans the budget and the maintenance tasks
//! share.

use std::ops::ControlFlow;
use std::sync::Arc;

use topcoat::context::Cx;

use kappa_store::resource;
use kappa_store::traits::KappaStore;
use kappa_store::{
    Execution, NamespaceFilter, NamespaceRef, PageRequest, ResourceHead, StoreError,
};

use super::{StagingBudget, Work};
use crate::error::HandlerError;
use crate::execute::Outcome;

/// `work` with `reservation` held until the work is dropped. `execute`
/// drops its work on the blocking worker only after the publication was
/// observed, so the reservation outlives a dropped request future.
#[allow(
    clippy::no_effect_underscore_binding,
    reason = "the binding moves the reservation into the work; its drop is the only effect needed"
)]
fn held<R, T>(reservation: R, mut work: Box<Work<T>>) -> Box<Work<T>>
where
    R: Send + 'static,
    T: 'static,
{
    Box::new(move |execution: &mut dyn Execution| {
        let _held = &reservation;
        work(execution)
    })
}

/// A reserved slot for one resource open, returned when dropped.
pub struct OpenAdmission {
    pub(super) budget: Arc<StagingBudget>,
}

impl OpenAdmission {
    /// `work` with this reservation held until the work is dropped.
    pub fn held_by<T: 'static>(
        self,
        work: impl FnMut(&mut dyn Execution) -> Result<Outcome<T>, HandlerError> + Send + 'static,
    ) -> Box<Work<T>> {
        held(self, Box::new(work))
    }
}

impl Drop for OpenAdmission {
    fn drop(&mut self) {
        self.budget.release_pending_open();
    }
}

/// Reserved bytes for one stage, returned when dropped.
pub struct ByteAdmission {
    pub(super) budget: Arc<StagingBudget>,
    pub(super) len: u64,
}

impl ByteAdmission {
    /// `work` with this reservation held until the work is dropped.
    pub fn held_by<T: 'static>(
        self,
        work: impl FnMut(&mut dyn Execution) -> Result<Outcome<T>, HandlerError> + Send + 'static,
    ) -> Box<Work<T>> {
        held(self, Box::new(work))
    }
}

impl Drop for ByteAdmission {
    fn drop(&mut self) {
        self.budget.release_pending_bytes(self.len);
    }
}

/// The server's staging budget.
///
/// # Errors
///
/// `Internal` when the server registered none: staging is never admitted
/// without a budget.
pub fn staging_budget(cx: &Cx) -> Result<&Arc<StagingBudget>, HandlerError> {
    crate::store::try_service::<Arc<StagingBudget>>(cx)
        .ok_or_else(|| HandlerError::internal("staging budget not configured"))
}

/// Visit the resource heads committed in `ns` in tag order until `visit`
/// breaks. Heads live under the `_resource/` tag prefix; member and
/// ownership keys below a head carry a slash and are not heads.
pub fn scan_namespace_resources<S: KappaStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    mut visit: impl FnMut(&str, &ResourceHead) -> Result<ControlFlow<()>, StoreError>,
) -> Result<(), StoreError> {
    let mut cursor = store.tag_cursor(ns, Some("_resource/"))?;
    while cursor.key() != kappa_cursor::TERMINATED {
        let name = std::str::from_utf8(cursor.key())
            .map_err(|error| StoreError::Internal(format!("tag cursor key: {error}")))?;
        if let Some(id) = name.strip_prefix("_resource/")
            && !id.contains('/')
            && let Some(resource) = resource::resolve(store, ns, id)?
            && visit(id, &resource.head)?.is_break()
        {
            return Ok(());
        }
        cursor.advance();
    }
    Ok(())
}

/// Visit every resource head committed in `store`, across all namespaces.
pub fn scan_resources<S: KappaStore + ?Sized>(
    store: &S,
    mut visit: impl FnMut(&NamespaceRef, &str, &ResourceHead) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut request = PageRequest::first(256);
    loop {
        let page = store.namespace_list(&NamespaceFilter::default(), &request)?;
        for info in &page.items {
            scan_namespace_resources(store, &info.ns, |id, head| {
                visit(&info.ns, id, head)?;
                Ok(ControlFlow::Continue(()))
            })?;
        }
        match page.next_after {
            Some(next) if request.after.as_ref() != Some(&next) => request.after = Some(next),
            Some(_) => {
                return Err(StoreError::Internal(
                    "namespace traversal did not advance".into(),
                ));
            }
            None => return Ok(()),
        }
    }
}
