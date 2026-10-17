use super::*;

use kappa_handler::clock_at;
use kappa_store::clock::ClockMs;
use kappa_store::kappa::Kappa;
use kappa_store::tag::TagUpdate;
use kappa_store::{Axis, ExecutionStore, VerifiedContent};
use kappa_store_memory::{InMemoryStore, test_support};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn test_store() -> Result<InMemoryStore, Box<dyn std::error::Error>> {
    Ok(test_support::test_store()?.into_store())
}

fn bucket() -> NamespaceRef {
    NamespaceRef::deterministic("bucket")
}

fn request() -> ListObjectsV2Request {
    ListObjectsV2Request {
        bucket: "bucket".into(),
        ..Default::default()
    }
}

/// Publish one object per key, all naming the same content, installed in
/// the same execution.
fn seed_tags(store: &InMemoryStore, keys: &[&str]) -> Result<Kappa, StoreError> {
    let content = VerifiedContent::compute(Axis::Sha256, b"listing fixture")?;
    let kappa = content.kappa().clone();
    let mut execution = store.begin_execution(&bucket(), &clock_at(ClockMs::from_raw(1))?)?;
    execution.blob_put(&content)?;
    for key in keys {
        execution.tag_put(
            key,
            &TagUpdate::Set {
                kappa: kappa.clone(),
            },
        )?;
    }
    execution.publish()?;
    Ok(kappa)
}

#[test]
fn list_all_objects() -> TestResult {
    let store = test_store()?;
    seed_tags(&store, &["a", "b", "c"])?;
    let resp = list_objects_v2(&store, &bucket(), &request())?;
    assert_eq!(resp.contents.len(), 3);
    assert_eq!(resp.key_count, 3);
    assert!(!resp.is_truncated);
    Ok(())
}

#[test]
fn listing_reports_the_metadata_written_with_the_object() -> TestResult {
    let store = test_store()?;
    let kappa = seed_tags(&store, &["described", "bare"])?;
    let mut execution = store.begin_execution(&bucket(), &clock_at(ClockMs::from_raw(2))?)?;
    execution.namespace_put_meta(
        &crate::handlers::obj_meta_key("described", "etag"),
        b"\"0123abcd\"",
    )?;
    execution.namespace_put_meta(
        &crate::handlers::obj_meta_key("described", "created_ms"),
        b"86400000",
    )?;
    execution.publish()?;

    let resp = list_objects_v2(&store, &bucket(), &request())?;
    let [bare, described] = resp.contents.as_slice() else {
        return Err(format!("expected two objects, got {}", resp.contents.len()).into());
    };
    assert_eq!(described.key, "described");
    assert_eq!(described.etag, "\"0123abcd\"");
    assert_eq!(described.last_modified, "1970-01-02T00:00:00.000Z");
    assert_eq!(bare.key, "bare");
    assert_eq!(bare.etag, format!("\"{kappa}\""));
    assert_eq!(bare.last_modified, "1970-01-01T00:00:00.000Z");
    Ok(())
}

#[test]
fn list_with_prefix() -> TestResult {
    let store = test_store()?;
    seed_tags(&store, &["photos/a.jpg", "photos/b.jpg", "docs/c.txt"])?;
    let req = ListObjectsV2Request {
        prefix: Some("photos/".into()),
        ..request()
    };
    let resp = list_objects_v2(&store, &bucket(), &req)?;
    assert_eq!(resp.contents.len(), 2);
    Ok(())
}

#[test]
fn delimiter_rollup() -> TestResult {
    let store = test_store()?;
    seed_tags(&store, &["a/b/c/1", "a/b/c/2", "a/b/d/1", "a/e/1"])?;
    let req = ListObjectsV2Request {
        prefix: Some("a/".into()),
        delimiter: Some("/".into()),
        ..request()
    };
    let resp = list_objects_v2(&store, &bucket(), &req)?;
    assert_eq!(resp.contents.len(), 0);
    assert_eq!(resp.common_prefixes, ["a/b/", "a/e/"]);
    Ok(())
}

#[test]
fn delimiter_rollup_deeper() -> TestResult {
    let store = test_store()?;
    seed_tags(&store, &["a/b/c/1", "a/b/c/2", "a/b/d/1"])?;
    let req = ListObjectsV2Request {
        prefix: Some("a/b/".into()),
        delimiter: Some("/".into()),
        ..request()
    };
    let resp = list_objects_v2(&store, &bucket(), &req)?;
    assert_eq!(resp.contents.len(), 0);
    assert_eq!(resp.common_prefixes, ["a/b/c/", "a/b/d/"]);
    Ok(())
}

#[test]
fn delimiter_leaf_entries() -> TestResult {
    let store = test_store()?;
    seed_tags(&store, &["a/b/c/1", "a/b/c/2"])?;
    let req = ListObjectsV2Request {
        prefix: Some("a/b/c/".into()),
        delimiter: Some("/".into()),
        ..request()
    };
    let resp = list_objects_v2(&store, &bucket(), &req)?;
    assert_eq!(resp.contents.len(), 2);
    assert_eq!(resp.common_prefixes.len(), 0);
    Ok(())
}

#[test]
fn max_keys_truncates() -> TestResult {
    let store = test_store()?;
    seed_tags(&store, &["a", "b", "c", "d", "e"])?;
    let req = ListObjectsV2Request {
        max_keys: 2,
        ..request()
    };
    let resp = list_objects_v2(&store, &bucket(), &req)?;
    assert_eq!(resp.key_count, 2);
    assert!(resp.is_truncated);
    assert!(resp.next_continuation_token.is_some());
    Ok(())
}

#[test]
fn max_keys_counts_common_prefixes() -> TestResult {
    let store = test_store()?;
    seed_tags(&store, &["a/1", "b/1", "c/1", "d/1"])?;
    let req = ListObjectsV2Request {
        delimiter: Some("/".into()),
        max_keys: 2,
        ..request()
    };
    let resp = list_objects_v2(&store, &bucket(), &req)?;
    assert_eq!(resp.key_count, 2);
    assert!(resp.is_truncated);
    assert_eq!(resp.common_prefixes.len(), 2);
    assert_eq!(resp.contents.len(), 0);
    Ok(())
}

#[test]
fn continuation_token_resumes() -> TestResult {
    let store = test_store()?;
    seed_tags(&store, &["a", "b", "c", "d", "e"])?;
    let first = list_objects_v2(
        &store,
        &bucket(),
        &ListObjectsV2Request {
            max_keys: 2,
            ..request()
        },
    )?;
    assert!(first.is_truncated);
    let token = first
        .next_continuation_token
        .ok_or("truncated listing carries a continuation token")?;

    let second = list_objects_v2(
        &store,
        &bucket(),
        &ListObjectsV2Request {
            max_keys: 2,
            continuation_token: Some(token),
            ..request()
        },
    )?;
    let keys: Vec<&str> = second.contents.iter().map(|o| o.key.as_str()).collect();
    assert_eq!(keys, ["c", "d"]);
    Ok(())
}

#[test]
fn continuation_token_overrides_start_after() -> TestResult {
    let store = test_store()?;
    seed_tags(&store, &["a", "b", "c", "d", "e"])?;
    let req = ListObjectsV2Request {
        continuation_token: Some(encode_continuation_token("c")),
        start_after: Some("a".into()),
        ..request()
    };
    let resp = list_objects_v2(&store, &bucket(), &req)?;
    let first = resp.contents.first().ok_or("listing is empty")?;
    assert_eq!(first.key, "d");
    Ok(())
}

#[test]
fn start_after_on_first_page() -> TestResult {
    let store = test_store()?;
    seed_tags(&store, &["a", "b", "c", "d", "e"])?;
    let req = ListObjectsV2Request {
        start_after: Some("c".into()),
        ..request()
    };
    let resp = list_objects_v2(&store, &bucket(), &req)?;
    let keys: Vec<&str> = resp.contents.iter().map(|o| o.key.as_str()).collect();
    assert_eq!(keys, ["d", "e"]);
    Ok(())
}

#[test]
fn malformed_continuation_token_treated_as_literal() {
    let decoded = decode_continuation_token("not-valid-base64!!!");
    assert_eq!(decoded, "not-valid-base64!!!");
}
