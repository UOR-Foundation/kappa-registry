use crate::error::HandlerError;
use std::time::Duration;

/// Run a blocking closure on the tokio blocking threadpool with a
/// deadline.
///
/// The closure returns `Result<T, E>` where `E: Into<HandlerError>`.
/// Store errors convert automatically — the caller does not wrap in
/// `Ok(...)` or call `.map_err`. The closure IS the store call:
///
/// ```ignore
/// let kappa = blocking(move || s.tag_get(&ns, "name")).await?;
/// ```
///
/// Timeout and panic errors are added by this wrapper.
pub async fn with_deadline<T, E, F>(deadline: Duration, f: F) -> Result<T, HandlerError>
where
    T: Send + 'static,
    E: Into<HandlerError> + Send + 'static,
    F: FnOnce() -> Result<T, E> + Send + 'static,
{
    let handle = tokio::task::spawn_blocking(move || f().map_err(Into::into));
    match tokio::time::timeout(deadline, handle).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_err)) => Err(HandlerError::Internal {
            reason: format!("blocking task failed: {join_err}"),
        }),
        Err(_elapsed) => Err(HandlerError::Timeout {
            deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
        }),
    }
}

/// Run a bounded point read inline on the runtime worker.
///
/// For store reads that touch a bounded number of index entries and no
/// content: namespace resolution, authorization's grant and delegation
/// lookups, tag and metadata lookups, existence checks. Such a read costs
/// less than handing it to the blocking pool, whose round trip (thread
/// wake, two channel handoffs) is microseconds on its own, so on a hot
/// read path the handoff would be most of the request. Content transfer,
/// scans, executions and long operations stay on [`blocking`]. Errors
/// convert as [`blocking`]'s do; a panic unwinds into the request, which the
/// router answers with an internal error.
pub fn point_read<T, E, F>(f: F) -> Result<T, HandlerError>
where
    E: Into<HandlerError>,
    F: FnOnce() -> Result<T, E>,
{
    f().map_err(Into::into)
}

/// Run a blocking closure with a default 30-second deadline.
///
/// For operations that should complete in seconds: `tag_get`, `blob_get`,
/// `namespace_resolve`, and one execution from `begin_execution` through
/// its writes to `publish` or `abort`. The execution holds the store's
/// single writer for that whole span, so it runs inside one closure and
/// never across an await. Handler writes use `execute`, which bounds
/// publication by its own deadline. Long operations (CAR export, GC sweep)
/// use `with_deadline` directly or `tokio::task::spawn_blocking`
/// without a deadline.
pub async fn blocking<T, E, F>(f: F) -> Result<T, HandlerError>
where
    T: Send + 'static,
    E: Into<HandlerError> + Send + 'static,
    F: FnOnce() -> Result<T, E> + Send + 'static,
{
    with_deadline(Duration::from_secs(30), f).await
}
