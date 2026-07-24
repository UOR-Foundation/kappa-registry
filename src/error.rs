use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::store::StoreError;

#[derive(Debug)]
pub enum AppError {
    DigestInvalid { expected: String, got: String },
    SchemaViolation(String),
    FilterRejected(String),
    AxisMismatch,
    BlobUnknown,
    TagUnknown,
    EdgeUnknown,
    TagContentAbsent,
    EdgeSourceAbsent,
    RangeNotSatisfiable,
    UploadNotFound,
    FinalizerOutstanding(String),
    NameInvalid(String),
    Internal(String),
    Store(StoreError),
}

impl AppError {
    pub fn digest_invalid(expected: &str, got: &str) -> Self {
        Self::DigestInvalid {
            expected: expected.to_string(),
            got: got.to_string(),
        }
    }

    pub fn filter_rejected(reason: &str) -> Self {
        Self::FilterRejected(reason.to_string())
    }

    pub fn schema_violation(reason: &str) -> Self {
        Self::SchemaViolation(reason.to_string())
    }

    pub fn internal(msg: &str) -> Self {
        Self::Internal(msg.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::DigestInvalid { expected, got } => (
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                format!("expected {expected}, got {got}"),
            ),
            Self::SchemaViolation(reason) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "SCHEMA_VIOLATION", reason)
            }
            Self::FilterRejected(reason) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "FILTER_REJECTED", reason)
            }
            Self::AxisMismatch => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "AXIS_MISMATCH",
                "operands have different axes".to_string(),
            ),
            Self::BlobUnknown => (
                StatusCode::NOT_FOUND,
                "BLOB_UNKNOWN",
                "blob not found".to_string(),
            ),
            Self::TagUnknown => (
                StatusCode::NOT_FOUND,
                "TAG_UNKNOWN",
                "tag not found".to_string(),
            ),
            Self::EdgeUnknown => (
                StatusCode::NOT_FOUND,
                "EDGE_UNKNOWN",
                "edge not found".to_string(),
            ),
            Self::TagContentAbsent => (
                StatusCode::NOT_FOUND,
                "TAG_CONTENT_ABSENT",
                "kappa not in store".to_string(),
            ),
            Self::EdgeSourceAbsent => (
                StatusCode::CONFLICT,
                "EDGE_SOURCE_ABSENT",
                "source kappa absent".to_string(),
            ),
            Self::RangeNotSatisfiable => (
                StatusCode::RANGE_NOT_SATISFIABLE,
                "BLOB_UPLOAD_INVALID",
                "out-of-order chunk".to_string(),
            ),
            Self::UploadNotFound => (
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "upload session not found".to_string(),
            ),
            Self::FinalizerOutstanding(ctrl) => (
                StatusCode::CONFLICT,
                "FINALIZER_OUTSTANDING",
                format!("finalizer {ctrl} blocks unpin"),
            ),
            Self::NameInvalid(msg) => (StatusCode::BAD_REQUEST, "NAME_INVALID", msg),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", msg),
            Self::Store(e) => match e {
                StoreError::NotFound => (
                    StatusCode::NOT_FOUND,
                    "BLOB_UNKNOWN",
                    "not found".to_string(),
                ),
                StoreError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg),
                StoreError::Io(e) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", e.to_string()),
                StoreError::BundleTrailerMismatch
                | StoreError::BundleDecodeLimitExceeded
                | StoreError::BundleDeltaInNoDeltaBundle => {
                    (StatusCode::BAD_REQUEST, "BUNDLE_INVALID", e.to_string())
                }
                StoreError::BundleTruncated(_) => {
                    (StatusCode::BAD_REQUEST, "BUNDLE_TRUNCATED", e.to_string())
                }
                StoreError::BundleKappaMismatch(_) => {
                    (StatusCode::BAD_REQUEST, "DIGEST_INVALID", e.to_string())
                }
                StoreError::BundleUnsupportedEntryType(_) => {
                    (StatusCode::BAD_REQUEST, "BUNDLE_INVALID", e.to_string())
                }
                StoreError::DeltaTruncated(_)
                | StoreError::DeltaReservedOpcode
                | StoreError::DeltaBaseSizeMismatch { .. }
                | StoreError::DeltaResultSizeMismatch { .. }
                | StoreError::DeltaCopyOutOfBounds { .. }
                | StoreError::DeltaVarintOverflow => {
                    (StatusCode::BAD_REQUEST, "DELTA_INVALID", e.to_string())
                }
                StoreError::DeltaUnresolvableBase(_) => {
                    (StatusCode::BAD_REQUEST, "DELTA_BASE_UNKNOWN", e.to_string())
                }
            },
        };

        let body = serde_json::json!({
            "errors": [{
                "code": code,
                "message": message,
            }]
        });

        (status, Json(body)).into_response()
    }
}

impl From<StoreError> for AppError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        Self::internal(&e.to_string())
    }
}

impl From<crate::kappa::LabelError> for AppError {
    fn from(e: crate::kappa::LabelError) -> Self {
        Self::NameInvalid(e.to_string())
    }
}

impl From<tokio::task::JoinError> for AppError {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::internal(&e.to_string())
    }
}
