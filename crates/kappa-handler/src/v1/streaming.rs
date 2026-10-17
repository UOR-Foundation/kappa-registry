//! Streaming response infrastructure.
//!
//! Streaming handlers (CAR export, blob GET, firehose) send the HTTP
//! status before the body is complete. Errors during the body have no
//! path to the operator via status code. This module provides that path.
//!
//! Architecture:
//! 1. The `request_log` layer creates a `StreamingErrorSlot` and stores it
//!    in the request context via cx.with(slot.clone()).
//! 2. The handler calls `streaming_response()` which reads the slot from
//!    request context and returns a `StreamingWriter` that carries the slot.
//! 3. The `spawn_blocking` task writes body chunks via `writer.send()`.
//!    On error, the task calls `writer.report_error(e)`.
//! 4. A request-scoped observer reports producer failures when they occur,
//!    including after headers return. Body termination checks producer success.
//!
//! The writer carries its error slot. Producer panic or abandonment reports
//! failure on Drop and is exposed as a body error rather than a clean EOF.

use std::sync::{Arc, Mutex};

use http::StatusCode;

use crate::HandlerError;

/// Error slot shared between the handler's streaming writer and the
/// `request_log` layer. `Arc<Mutex<Option<HandlerError>>>` because it
/// crosses the `spawn_blocking` boundary (Send + Sync required).
#[derive(Clone)]
pub struct StreamingErrorSlot {
    inner: Arc<Mutex<Option<HandlerError>>>,
    completed: Arc<Mutex<bool>>,
    failed: Arc<std::sync::atomic::AtomicBool>,
    observer: Option<ErrorObserver>,
}

type ErrorObserver = Arc<dyn Fn(&HandlerError) + Send + Sync>;

impl StreamingErrorSlot {
    /// Create a new empty error slot.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
            completed: Arc::new(Mutex::new(false)),
            failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            observer: None,
        }
    }

    /// Attach request-scoped diagnostics that run when the producer fails,
    /// including failures occurring after response headers have been returned.
    pub fn with_observer(observer: impl Fn(&HandlerError) + Send + Sync + 'static) -> Self {
        Self {
            observer: Some(Arc::new(observer)),
            ..Self::new()
        }
    }

    /// Report an error from the streaming writer task.
    pub fn report_error(&self, error: HandlerError) {
        if self.failed.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        if let Some(observer) = &self.observer {
            observer(&error);
        }
        if let Ok(mut slot) = self.inner.lock() {
            *slot = Some(error);
        }
    }

    /// Mark the streaming writer as completed successfully.
    pub fn mark_completed(&self) {
        if let Ok(mut flag) = self.completed.lock() {
            *flag = true;
        }
    }

    /// Read the error after the stream completes. Called by `request_log` layer.
    /// Returns:
    /// - Some(error) if the writer reported an error
    /// - None if the writer completed successfully
    pub fn take_error(&self) -> Option<HandlerError> {
        self.inner.lock().ok().and_then(|mut slot| slot.take())
    }

    /// Check if the writer completed. If false and no error, the writer
    /// was dropped without completing (panic or abort).
    pub fn is_completed(&self) -> bool {
        self.completed.lock().is_ok_and(|flag| *flag)
    }
}

impl Drop for StreamingWriter {
    fn drop(&mut self) {
        if !self.error_slot.is_completed()
            && !self
                .error_slot
                .failed
                .load(std::sync::atomic::Ordering::Acquire)
        {
            self.error_slot.report_error(HandlerError::internal(
                "streaming producer dropped without completion",
            ));
        }
    }
}

impl Default for StreamingErrorSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// The writer half of a streaming response. Passed to `spawn_blocking`.
pub struct StreamingWriter {
    /// Channel for body chunks.
    body_tx: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    /// Error slot shared with the `request_log` layer.
    error_slot: StreamingErrorSlot,
}

impl StreamingWriter {
    /// Send a body chunk. Returns Err if the client disconnected.
    pub fn send(&self, data: bytes::Bytes) -> Result<(), HandlerError> {
        self.body_tx
            .blocking_send(Ok(data))
            .map_err(|_| HandlerError::internal("client disconnected"))
    }

    /// Report a fatal error and stop writing.
    pub fn report_error(self, error: HandlerError) {
        let message = error.to_string();
        self.error_slot.report_error(error);
        // An error frame prevents a truncated body from appearing as a clean
        // end-of-stream when no Content-Length was supplied.
        let _ = self
            .body_tx
            .blocking_send(Err(std::io::Error::other(message)));
    }

    /// Mark the writer as completed successfully. Call at the end of
    /// a successful write loop. If not called and no error reported,
    /// the `request_log` layer logs "writer dropped without completion."
    pub fn mark_completed(&self) {
        self.error_slot.mark_completed();
    }
}

/// Construct a streaming response.
///
/// Reads `StreamingErrorSlot` from request context. If not present
/// (`request_log` layer not installed), creates one that is not
/// monitored — errors are still captured but nobody reads them.
/// This allows streaming handlers to work in test contexts without
/// the full middleware stack.
pub fn streaming_response(
    cx: &topcoat::context::Cx,
    content_type: &str,
    content_length: Option<u64>,
    channel_size: usize,
) -> Result<(topcoat::router::response::Response, StreamingWriter), HandlerError> {
    let error_slot = topcoat::context::try_request_context::<StreamingErrorSlot>(cx)
        .cloned()
        .unwrap_or_default();

    if channel_size == 0 {
        return Err(HandlerError::internal(
            "streaming channel capacity must be positive",
        ));
    }
    let (body_tx, body_rx) =
        tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(channel_size);

    let body = streaming_body(body_rx, error_slot.clone());

    let mut builder = topcoat::router::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", content_type);

    if let Some(len) = content_length {
        builder = builder.header("content-length", len.to_string());
    }

    let response = builder
        .body(body)
        .map_err(|e| HandlerError::internal(format!("streaming response builder: {e}")))?;

    Ok((
        response,
        StreamingWriter {
            body_tx,
            error_slot,
        },
    ))
}

fn streaming_body(
    body_rx: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>,
    error_slot: StreamingErrorSlot,
) -> topcoat::router::Body {
    let stream = tokio_stream::wrappers::ReceiverStream::new(body_rx);
    let terminal_slot = error_slot;
    let terminal = futures_util::stream::once(async move {
        if terminal_slot.is_completed() {
            None
        } else {
            Some(Err(std::io::Error::other(
                "streaming producer did not complete",
            )))
        }
    });
    let terminal = futures_util::StreamExt::filter_map(terminal, std::future::ready);
    let stream = futures_util::StreamExt::chain(stream, terminal);
    let body_stream =
        http_body_util::StreamBody::new(futures_util::StreamExt::map(stream, |result| {
            result.map(http_body::Frame::data)
        }));

    topcoat::router::Body::new(body_stream)
}

/// Stream a blob the namespace `ns` admitted as a response.
///
/// Single blocking phase: `blob_open_in` + `blob_size_in`, then chunked
/// reads through the `StreamingWriter`. Error reporting through the slot.
pub async fn stream_blob(
    cx: &topcoat::context::Cx,
    store: std::sync::Arc<dyn kappa_store::KappaStore>,
    ns: &kappa_store::NamespaceRef,
    kappa: &kappa_store::Kappa,
    content_type: &str,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let kappa = kappa.clone();
    let ns = ns.clone();
    let (size, reader) = crate::blocking::blocking(move || {
        let reader = store.blob_open_in(&ns, &kappa)?;
        let size = store.blob_size_in(&ns, &kappa)?;
        Ok::<_, kappa_store::StoreError>((size, reader))
    })
    .await?;

    let (response, writer) = streaming_response(cx, content_type, Some(size), 16)?;

    tokio::task::spawn_blocking(move || {
        let mut reader = reader;
        let mut buf = vec![0u8; 64 * 1024];
        let mut remaining = size;
        loop {
            match std::io::Read::read(&mut *reader, &mut buf) {
                Ok(0) => {
                    if remaining != 0 {
                        writer.report_error(HandlerError::internal(
                            "blob ended before its declared length",
                        ));
                        return;
                    }
                    writer.mark_completed();
                    break;
                }
                Ok(n) => {
                    if n as u64 > remaining {
                        writer.report_error(HandlerError::internal(
                            "blob exceeded its declared length",
                        ));
                        return;
                    }
                    remaining -= n as u64;
                    if let Err(e) = writer.send(bytes::Bytes::copy_from_slice(&buf[..n])) {
                        writer.report_error(e);
                        return;
                    }
                }
                Err(io_err) if io_err.kind() == std::io::ErrorKind::Interrupted => {}
                Err(io_err) => {
                    writer
                        .report_error(HandlerError::internal(format!("blob read error: {io_err}")));
                    return;
                }
            }
        }
    });

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[tokio::test]
    async fn producer_failure_is_a_body_error_after_delivered_chunks() -> TestResult {
        let slot = StreamingErrorSlot::new();
        let (body_tx, body_rx) = tokio::sync::mpsc::channel(1);
        let writer = StreamingWriter {
            body_tx,
            error_slot: slot.clone(),
        };
        let mut body = streaming_body(body_rx, slot.clone());
        let producer = tokio::task::spawn_blocking(move || {
            writer.send(bytes::Bytes::from_static(b"partial"))?;
            writer.report_error(HandlerError::internal("storage read failed"));
            Ok::<(), HandlerError>(())
        });
        let first = body.frame().await.ok_or("missing first frame")??;
        let data = first.into_data().map_err(|_| "first frame is not data")?;
        assert_eq!(data, b"partial"[..]);
        assert!(body.frame().await.ok_or("missing failure frame")?.is_err());
        producer.await??;
        assert!(slot.take_error().is_some());
        assert!(!slot.is_completed());
        Ok(())
    }

    #[tokio::test]
    async fn abandoned_producer_is_not_clean_eof() -> TestResult {
        let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = observed.clone();
        let slot = StreamingErrorSlot::with_observer(move |_| {
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
        let (body_tx, body_rx) = tokio::sync::mpsc::channel(1);
        let writer = StreamingWriter {
            body_tx,
            error_slot: slot.clone(),
        };
        let mut body = streaming_body(body_rx, slot.clone());
        drop(writer);
        assert!(body.frame().await.ok_or("missing terminal frame")?.is_err());
        assert!(body.frame().await.is_none());
        assert!(slot.take_error().is_some());
        assert_eq!(observed.load(std::sync::atomic::Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn completed_producer_delivers_clean_eof() {
        let slot = StreamingErrorSlot::new();
        let (body_tx, body_rx) = tokio::sync::mpsc::channel(1);
        let writer = StreamingWriter {
            body_tx,
            error_slot: slot.clone(),
        };
        let mut body = streaming_body(body_rx, slot.clone());
        writer.mark_completed();
        drop(writer);
        assert!(body.frame().await.is_none());
        assert!(slot.take_error().is_none());
    }

    #[tokio::test]
    async fn disconnected_consumer_releases_the_blocking_producer() -> TestResult {
        let (body_tx, body_rx) = tokio::sync::mpsc::channel(1);
        drop(body_rx);
        let writer = StreamingWriter {
            body_tx,
            error_slot: StreamingErrorSlot::new(),
        };
        let sent =
            tokio::task::spawn_blocking(move || writer.send(bytes::Bytes::from_static(b"data")))
                .await?;
        assert!(sent.is_err());
        Ok(())
    }
}
