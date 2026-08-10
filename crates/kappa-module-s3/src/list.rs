//! ListObjectsV2 implementation over KappaStore tags.
//!
//! Delimiter rollup: keys sharing a common prefix up to and including
//! the delimiter produce CommonPrefixes entries. Rolled-up keys do NOT
//! appear in Contents.
//!
//! MaxKeys counts BOTH Contents AND CommonPrefixes toward the limit.
//!
//! continuation-token takes precedence over start-after. When both are
//! present, start-after is silently ignored (S3 documented behavior).

use kappa_core::store::KappaStore;
use kappa_core::types::StoreError;

/// Request parameters for ListObjectsV2.
#[derive(Debug, Clone)]
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
/// The store's tags in the given namespace (bucket) are treated as S3
/// object keys. Tag names are keys. Tag kappas are the content addresses.
pub fn list_objects_v2(
    store: &dyn KappaStore,
    namespace: &str,
    request: &ListObjectsV2Request,
) -> Result<ListObjectsV2Response, StoreError> {
    let all_tags = store.tag_list(namespace)?;

    let prefix = request.prefix.as_deref().unwrap_or("");

    // Determine the resume position.
    // continuation_token takes precedence over start_after.
    let resume_after: Option<String> = if let Some(ref token) = request.continuation_token {
        Some(decode_continuation_token(token))
    } else {
        request.start_after.clone()
    };

    // Filter tags by prefix and resume position
    let filtered: Vec<_> = all_tags
        .iter()
        .filter(|tag| tag.name.starts_with(prefix))
        .filter(|tag| {
            match &resume_after {
                Some(after) => tag.name.as_str() > after.as_str(),
                None => true,
            }
        })
        .collect();

    let delimiter = request.delimiter.as_deref();
    let max_keys = request.max_keys as usize;

    let mut contents: Vec<ObjectEntry> = Vec::new();
    let mut common_prefixes: Vec<String> = Vec::new();
    let mut seen_prefixes: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut last_key: Option<String> = None;
    let mut total_count: usize = 0;

    for tag in &filtered {
        if total_count >= max_keys {
            break;
        }

        let key = &tag.name;

        if let Some(delim) = delimiter {
            // Check for delimiter after the prefix
            let suffix = &key[prefix.len()..];
            if let Some(delim_pos) = suffix.find(delim) {
                // Roll up into CommonPrefixes
                let common_prefix = format!(
                    "{}{}{}",
                    prefix,
                    &suffix[..delim_pos],
                    delim
                );
                if seen_prefixes.insert(common_prefix.clone()) {
                    common_prefixes.push(common_prefix);
                    total_count += 1;
                    last_key = Some(key.clone());
                }
                continue;
            }
        }

        // Regular content entry
        let size = store.blob_size(&tag.kappa).unwrap_or(0);
        let last_modified = store.blob_get_meta(&tag.kappa, "_s3_created_ms")
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|ms_str| ms_str.parse::<u64>().ok())
            .map(|ms| kappa_core::clock::epoch_ms_to_iso8601(ms))
            .unwrap_or_else(|| "2026-01-01T00:00:00.000Z".to_string());
        let etag = store.blob_get_meta(&tag.kappa, "_s3_etag")
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| format!("\"{}\"", &tag.kappa));
        contents.push(ObjectEntry {
            key: key.clone(),
            last_modified,
            etag,
            size,
            storage_class: "STANDARD".to_string(),
        });
        total_count += 1;
        last_key = Some(key.clone());
    }

    let is_truncated = total_count >= max_keys && filtered.len() > total_count;
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
        key_count: total_count as u32,
        encoding_type: request.encoding_type.clone(),
    })
}

fn encode_continuation_token(last_key: &str) -> String {
    base64_simd::STANDARD.encode_to_string(last_key.as_bytes())
}

fn decode_continuation_token(token: &str) -> String {
    base64_simd::STANDARD
        .decode_to_vec(token.as_bytes())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_core::clock::ntp_lamport::NtpLamportClock;
    use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
    use std::sync::Arc;

    fn test_store() -> (Arc<InMemoryStore>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let clock = Arc::new(NtpLamportClock::new());
        let store = InMemoryStore::new(
            MemoryStoreConfig::new(tmp.path().join("blobs")),
            clock,
        ).unwrap();
        (Arc::new(store), tmp)
    }

    fn seed_tags(store: &dyn KappaStore, keys: &[&str]) {
        for key in keys {
            store.tag_set("bucket", key, "sha256:aaa").unwrap();
        }
    }

    #[test]
    fn list_all_objects() {
        let (store, _tmp) = test_store();
        seed_tags(&*store, &["a", "b", "c"]);
        let req = ListObjectsV2Request {
            bucket: "bucket".into(),
            ..Default::default()
        };
        let resp = list_objects_v2(&*store, "bucket", &req).unwrap();
        assert_eq!(resp.contents.len(), 3);
        assert_eq!(resp.key_count, 3);
        assert!(!resp.is_truncated);
    }

    #[test]
    fn list_with_prefix() {
        let (store, _tmp) = test_store();
        seed_tags(&*store, &["photos/a.jpg", "photos/b.jpg", "docs/c.txt"]);
        let req = ListObjectsV2Request {
            bucket: "bucket".into(),
            prefix: Some("photos/".into()),
            ..Default::default()
        };
        let resp = list_objects_v2(&*store, "bucket", &req).unwrap();
        assert_eq!(resp.contents.len(), 2);
    }

    #[test]
    fn delimiter_rollup() {
        let (store, _tmp) = test_store();
        seed_tags(&*store, &[
            "a/b/c/1", "a/b/c/2", "a/b/d/1", "a/e/1",
        ]);
        let req = ListObjectsV2Request {
            bucket: "bucket".into(),
            prefix: Some("a/".into()),
            delimiter: Some("/".into()),
            ..Default::default()
        };
        let resp = list_objects_v2(&*store, "bucket", &req).unwrap();
        assert_eq!(resp.contents.len(), 0);
        assert_eq!(resp.common_prefixes.len(), 2);
        assert!(resp.common_prefixes.contains(&"a/b/".to_string()));
        assert!(resp.common_prefixes.contains(&"a/e/".to_string()));
    }

    #[test]
    fn delimiter_rollup_deeper() {
        let (store, _tmp) = test_store();
        seed_tags(&*store, &[
            "a/b/c/1", "a/b/c/2", "a/b/d/1",
        ]);
        let req = ListObjectsV2Request {
            bucket: "bucket".into(),
            prefix: Some("a/b/".into()),
            delimiter: Some("/".into()),
            ..Default::default()
        };
        let resp = list_objects_v2(&*store, "bucket", &req).unwrap();
        assert_eq!(resp.contents.len(), 0);
        assert_eq!(resp.common_prefixes.len(), 2);
        assert!(resp.common_prefixes.contains(&"a/b/c/".to_string()));
        assert!(resp.common_prefixes.contains(&"a/b/d/".to_string()));
    }

    #[test]
    fn delimiter_leaf_entries() {
        let (store, _tmp) = test_store();
        seed_tags(&*store, &["a/b/c/1", "a/b/c/2"]);
        let req = ListObjectsV2Request {
            bucket: "bucket".into(),
            prefix: Some("a/b/c/".into()),
            delimiter: Some("/".into()),
            ..Default::default()
        };
        let resp = list_objects_v2(&*store, "bucket", &req).unwrap();
        assert_eq!(resp.contents.len(), 2);
        assert_eq!(resp.common_prefixes.len(), 0);
    }

    #[test]
    fn max_keys_truncates() {
        let (store, _tmp) = test_store();
        seed_tags(&*store, &["a", "b", "c", "d", "e"]);
        let req = ListObjectsV2Request {
            bucket: "bucket".into(),
            max_keys: 2,
            ..Default::default()
        };
        let resp = list_objects_v2(&*store, "bucket", &req).unwrap();
        assert_eq!(resp.key_count, 2);
        assert!(resp.is_truncated);
        assert!(resp.next_continuation_token.is_some());
    }

    #[test]
    fn max_keys_counts_common_prefixes() {
        let (store, _tmp) = test_store();
        seed_tags(&*store, &["a/1", "b/1", "c/1", "d/1"]);
        let req = ListObjectsV2Request {
            bucket: "bucket".into(),
            delimiter: Some("/".into()),
            max_keys: 2,
            ..Default::default()
        };
        let resp = list_objects_v2(&*store, "bucket", &req).unwrap();
        assert_eq!(resp.key_count, 2);
        assert!(resp.is_truncated);
        assert_eq!(resp.common_prefixes.len(), 2);
        assert_eq!(resp.contents.len(), 0);
    }

    #[test]
    fn continuation_token_resumes() {
        let (store, _tmp) = test_store();
        seed_tags(&*store, &["a", "b", "c", "d", "e"]);

        let req1 = ListObjectsV2Request {
            bucket: "bucket".into(),
            max_keys: 2,
            ..Default::default()
        };
        let resp1 = list_objects_v2(&*store, "bucket", &req1).unwrap();
        assert!(resp1.is_truncated);
        let token = resp1.next_continuation_token.unwrap();

        let req2 = ListObjectsV2Request {
            bucket: "bucket".into(),
            max_keys: 2,
            continuation_token: Some(token),
            ..Default::default()
        };
        let resp2 = list_objects_v2(&*store, "bucket", &req2).unwrap();
        assert_eq!(resp2.contents.len(), 2);
        assert_eq!(resp2.contents[0].key, "c");
        assert_eq!(resp2.contents[1].key, "d");
    }

    #[test]
    fn continuation_token_overrides_start_after() {
        let (store, _tmp) = test_store();
        seed_tags(&*store, &["a", "b", "c", "d", "e"]);

        let token = encode_continuation_token("c");
        let req = ListObjectsV2Request {
            bucket: "bucket".into(),
            continuation_token: Some(token),
            start_after: Some("a".into()),
            ..Default::default()
        };
        let resp = list_objects_v2(&*store, "bucket", &req).unwrap();
        // continuation_token resumes after "c", NOT after "a"
        assert_eq!(resp.contents[0].key, "d");
    }

    #[test]
    fn start_after_on_first_page() {
        let (store, _tmp) = test_store();
        seed_tags(&*store, &["a", "b", "c", "d", "e"]);

        let req = ListObjectsV2Request {
            bucket: "bucket".into(),
            start_after: Some("c".into()),
            ..Default::default()
        };
        let resp = list_objects_v2(&*store, "bucket", &req).unwrap();
        assert_eq!(resp.contents.len(), 2);
        assert_eq!(resp.contents[0].key, "d");
        assert_eq!(resp.contents[1].key, "e");
    }
}
