//! ListObjectsV2 implementation over store tags.
//!
//! Delimiter rollup: keys sharing a common prefix up to and including
//! the delimiter produce CommonPrefixes entries. Rolled-up keys do NOT
//! appear in Contents.
//!
//! MaxKeys counts BOTH Contents AND CommonPrefixes toward the limit.
//!
//! continuation-token takes precedence over start-after. When both are
//! present, start-after is silently ignored (S3 documented behavior).

use kappa_store::error::StoreError;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::blob::BlobStore;
use kappa_store::traits::namespace::NamespaceStore;
use kappa_store::traits::tag::TagStore;

/// Request parameters for ListObjectsV2.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ListObjectsV2Request {
    pub bucket: String,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: u32,
    pub continuation_token: Option<String>,
    pub start_after: Option<String>,
    pub encoding_type: Option<String>,
    pub fetch_owner: bool,
}

impl Default for ListObjectsV2Request {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            prefix: None,
            delimiter: None,
            max_keys: 1000,
            continuation_token: None,
            start_after: None,
            encoding_type: None,
            fetch_owner: false,
        }
    }
}

/// Response for ListObjectsV2.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ListObjectsV2Response {
    pub name: String,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: u32,
    pub is_truncated: bool,
    pub contents: Vec<ObjectEntry>,
    pub common_prefixes: Vec<String>,
    pub next_continuation_token: Option<String>,
    pub key_count: u32,
    pub encoding_type: Option<String>,
}

/// A single object entry in a list response.
#[derive(Debug, Clone)]
pub struct ObjectEntry {
    pub key: String,
    pub last_modified: String,
    pub etag: String,
    pub size: u64,
    pub storage_class: String,
}

/// Execute a ListObjectsV2 query against the store.
///
/// Tags in the namespace are treated as S3 object keys. Tag names are keys;
/// tag kappas are content addresses. ETag and modification time come from
/// the object metadata written with the object.
///
/// # Errors
///
/// Returns `StoreError` if the tag list query or a metadata read fails.
pub fn list_objects_v2<S: TagStore + BlobStore + NamespaceStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    request: &ListObjectsV2Request,
) -> Result<ListObjectsV2Response, StoreError> {
    let prefix = request.prefix.as_deref().unwrap_or("");

    let resume_after: Option<String> = if let Some(ref token) = request.continuation_token {
        Some(decode_continuation_token(token))
    } else {
        request.start_after.clone()
    };

    let delimiter = request.delimiter.as_deref();
    let max_keys = request.max_keys as usize;

    let mut contents: Vec<ObjectEntry> = Vec::new();
    let mut common_prefixes: Vec<String> = Vec::new();
    let mut seen_prefixes = std::collections::HashSet::new();
    let mut last_key: Option<String> = None;
    let mut total_count: usize = 0;

    let mut page_request = kappa_store::PageRequest {
        limit: 1024,
        after: resume_after,
    };
    let mut is_truncated = false;
    'pages: loop {
        let page = store.tag_list(namespace, Some(prefix), &page_request)?;
        for tag in &page.items {
            let key = &tag.name;

            if let Some(delim) = delimiter {
                let suffix = &key[prefix.len()..];
                if let Some(delim_pos) = suffix.find(delim) {
                    let common_prefix = format!("{}{}{}", prefix, &suffix[..delim_pos], delim);
                    if seen_prefixes.contains(&common_prefix) {
                        last_key = Some(key.clone());
                        continue;
                    }
                    if total_count >= max_keys {
                        is_truncated = max_keys != 0;
                        break 'pages;
                    }
                    if seen_prefixes.insert(common_prefix.clone()) {
                        common_prefixes.push(common_prefix);
                        total_count += 1;
                        last_key = Some(key.clone());
                    }
                    continue;
                }
            }

            if total_count >= max_keys {
                is_truncated = max_keys != 0;
                break 'pages;
            }
            contents.push(object_entry(store, namespace, key, &tag.kappa)?);
            total_count += 1;
            last_key = Some(key.clone());
        }
        match page.next_after {
            None => break,
            Some(after) => {
                if page_request
                    .after
                    .as_ref()
                    .is_some_and(|previous| after <= *previous)
                {
                    return Err(StoreError::Internal(
                        "object listing cursor did not advance".into(),
                    ));
                }
                page_request.after = Some(after);
            }
        }
    }

    let next_token = if is_truncated {
        last_key.map(|k| encode_continuation_token(&k))
    } else {
        None
    };

    Ok(ListObjectsV2Response {
        name: request.bucket.clone(),
        prefix: request.prefix.clone(),
        delimiter: request.delimiter.clone(),
        max_keys: request.max_keys,
        is_truncated,
        contents,
        common_prefixes,
        next_continuation_token: next_token,
        key_count: u32::try_from(total_count)
            .map_err(|_| StoreError::Internal("object listing count exceeds u32".into()))?,
        encoding_type: request.encoding_type.clone(),
    })
}

fn object_entry<S: BlobStore + NamespaceStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    key: &str,
    kappa: &kappa_store::kappa::Kappa,
) -> Result<ObjectEntry, StoreError> {
    let size = store.blob_size_in(namespace, kappa)?;
    let meta = crate::handlers::get_object_meta(store, namespace, key)?;
    let last_modified = match meta.created_ms {
        Some(ms) => {
            let ms = ms
                .parse::<u64>()
                .map_err(|error| StoreError::Internal(format!("stored object time: {error}")))?;
            kappa_handler::epoch_ms_to_iso8601(ms)
                .map_err(|error| StoreError::Internal(format!("stored object time: {error}")))?
        }
        None => "1970-01-01T00:00:00.000Z".to_string(),
    };
    Ok(ObjectEntry {
        key: key.to_string(),
        last_modified,
        etag: meta.etag.unwrap_or_else(|| format!("\"{kappa}\"")),
        size,
        storage_class: "STANDARD".to_string(),
    })
}

fn encode_continuation_token(last_key: &str) -> String {
    kappa_handler::base64_encode(last_key.as_bytes())
}

fn decode_continuation_token(token: &str) -> String {
    kappa_handler::base64_decode(token)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| token.to_string())
}

#[cfg(test)]
#[path = "list_tests.rs"]
mod tests;
