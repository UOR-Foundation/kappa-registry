//! Namespace content admission: `_filter/` rules and `_schema/` validators
//! evaluated against content before anything is stored or published.
//!
//! Rejections are `HandlerError::Protocol` values carrying the OCI error
//! code and status, so a rejection raised inside an execution aborts it and
//! renders through the module's error envelope.

use topcoat::router::StatusCode;

use kappa_handler::HandlerError;
use kappa_store::NamespaceRef;
use kappa_store::traits::KappaStore;

use crate::tags::list_all_tags;

/// Evaluate every filter and schema of `ns` against `content`.
///
/// # Errors
///
/// `FILTER_REJECTED` or `SCHEMA_VIOLATION` (422) when the content is not
/// admitted; store failures; malformed filter or schema documents.
pub fn admit(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    content: &[u8],
) -> Result<(), HandlerError> {
    check_filters(store, ns, content)?;
    check_schemas(store, ns, content)
}

fn rejected(code: &str, message: String) -> HandlerError {
    HandlerError::protocol(StatusCode::UNPROCESSABLE_ENTITY, code, message)
}

fn check_filters(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    content: &[u8],
) -> Result<(), HandlerError> {
    for filter_tag in list_all_tags(store, ns, Some("_filter/"))? {
        let filter_bytes = store.blob_get_in(ns, &filter_tag.kappa)?;
        let rule = String::from_utf8_lossy(&filter_bytes);
        if let Some(needle) = rule.strip_prefix("deny:")
            && !needle.is_empty()
            && content
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
        {
            return Err(rejected(
                "FILTER_REJECTED",
                format!("filter {} rejected content", filter_tag.kappa),
            ));
        }
        if rule.contains("json-match") || rule.contains("accept_if") {
            let filter_json: serde_json::Value =
                serde_json::from_str(&rule).map_err(|e| HandlerError::Internal {
                    reason: format!("filter {} has invalid JSON: {e}", filter_tag.kappa),
                })?;
            if let Some(needle) = filter_json
                .get("accept_if")
                .and_then(|accept| accept.get("contains"))
                .and_then(serde_json::Value::as_str)
                && !String::from_utf8_lossy(content).contains(needle)
            {
                let reason = filter_json
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("filter rejected");
                return Err(rejected(
                    "FILTER_REJECTED",
                    format!("filter {}: {reason}", filter_tag.kappa),
                ));
            }
        }
    }
    Ok(())
}

fn check_schemas(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    content: &[u8],
) -> Result<(), HandlerError> {
    for schema_tag in list_all_tags(store, ns, Some("_schema/"))? {
        let schema_bytes = store.blob_get_in(ns, &schema_tag.kappa)?;
        let wrapper: serde_json::Value =
            serde_json::from_slice(&schema_bytes).map_err(|e| HandlerError::Internal {
                reason: format!("schema {} has invalid JSON: {e}", schema_tag.kappa),
            })?;
        let Some(format) = wrapper.get("format").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if format == "json-schema"
            && let Some(validation) = wrapper.get("validation")
        {
            let instance: serde_json::Value =
                serde_json::from_slice(content).map_err(|e| HandlerError::BadRequest {
                    reason: format!("content is not valid JSON for schema validation: {e}"),
                })?;
            if !jsonschema::is_valid(validation, &instance) {
                return Err(rejected(
                    "SCHEMA_VIOLATION",
                    "content does not match schema".into(),
                ));
            }
        }
    }
    Ok(())
}
