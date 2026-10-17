//! Publication properties of OCI writes: what one request publishes, and
//! what a rejected or no-op request leaves unpublished.

mod support;

use kappa_store::{Kappa, MutationOp};
use support::{MANIFEST_TYPE, Registry, TestResult, manifest};

#[tokio::test]
async fn manifest_and_tag_publish_in_one_epoch() -> TestResult {
    let registry = Registry::new()?;
    let first = manifest("first");
    let created = registry
        .send("PUT", "/v2/app/manifests/v1", &[MANIFEST_TYPE], &first)
        .await?;
    assert_eq!(created.status, 201, "{}", created.text);
    // The first push creates the repository inside its own execution.
    let ns = registry
        .repository("app")?
        .ok_or("repository not created")?;
    let before = registry
        .epoch(&ns)?
        .ok_or("first push published no epoch")?;
    assert_eq!(
        created.header("x-kappa-epoch")?,
        Some(before.to_string().as_str())
    );

    let second = manifest("second");
    let digest = Kappa::sha256(&second);
    let pushed = registry
        .send("PUT", "/v2/app/manifests/v2", &[MANIFEST_TYPE], &second)
        .await?;
    assert_eq!(pushed.status, 201, "{}", pushed.text);
    let after = registry
        .epoch(&ns)?
        .ok_or("second push published no epoch")?;
    assert_eq!(after, before + 1);
    assert_eq!(
        pushed.header("x-kappa-epoch")?,
        Some(after.to_string().as_str())
    );
    assert_eq!(
        pushed.header("docker-content-digest")?,
        Some(digest.to_string().as_str())
    );
    assert_eq!(
        pushed.header("location")?,
        Some(format!("/v2/app/manifests/{digest}").as_str())
    );

    // One epoch carries the repository's reference to the manifest
    // (`_blob/{digest}`, which makes it retrievable by digest) and the tag.
    let ledger = registry.ledger(&ns, after)?;
    let tag_sets: Vec<_> = ledger
        .iter()
        .filter(|mutation| mutation.op == MutationOp::TagSet)
        .map(|mutation| (mutation.context.as_deref(), &mutation.kappa))
        .collect();
    let reference = format!("_blob/{digest}");
    assert_eq!(
        tag_sets,
        vec![(Some(reference.as_str()), &digest), (Some("v2"), &digest)]
    );
    assert_eq!(registry.store.blob_get(&digest)?, second);
    assert_eq!(registry.tag(&ns, "v2")?, Some(digest));
    Ok(())
}

#[tokio::test]
async fn filter_rejected_manifest_publishes_nothing() -> TestResult {
    let registry = Registry::new()?;
    let seeded = registry
        .send(
            "PUT",
            "/v2/app/manifests/base",
            &[MANIFEST_TYPE],
            &manifest("base"),
        )
        .await?;
    assert_eq!(seeded.status, 201, "{}", seeded.text);
    let ns = registry
        .repository("app")?
        .ok_or("repository not created")?;

    let rule = b"deny:forbidden";
    let rule_digest = Kappa::sha256(rule);
    let stored = registry
        .send("PUT", &format!("/v2/app/blobs/{rule_digest}"), &[], rule)
        .await?;
    assert_eq!(stored.status, 201, "{}", stored.text);
    let filter = format!(r#"{{"name":"_filter/deny","kappa":"{rule_digest}"}}"#);
    let installed = registry
        .send("POST", "/v2/app/tags/", &[], filter.as_bytes())
        .await?;
    assert_eq!(installed.status, 201, "{}", installed.text);
    let before = registry.epoch(&ns)?;

    let rejected_manifest = manifest("forbidden");
    let rejected = registry
        .send(
            "PUT",
            "/v2/app/manifests/bad",
            &[MANIFEST_TYPE],
            &rejected_manifest,
        )
        .await?;
    assert_eq!(rejected.status, 422, "{}", rejected.text);
    let envelope: serde_json::Value = serde_json::from_str(&rejected.text)?;
    assert_eq!(
        envelope["errors"][0]["code"], "FILTER_REJECTED",
        "{}",
        rejected.text
    );
    assert_eq!(registry.epoch(&ns)?, before);
    assert_eq!(registry.tag(&ns, "bad")?, None);
    assert!(
        !registry
            .store
            .blob_exists(&Kappa::sha256(&rejected_manifest))?
    );
    Ok(())
}

#[tokio::test]
async fn rejected_first_push_creates_no_repository() -> TestResult {
    let registry = Registry::new()?;
    let content = manifest("mismatch");
    let wrong = Kappa::sha256(b"other content");
    let rejected = registry
        .send(
            "PUT",
            &format!("/v2/fresh/manifests/{wrong}"),
            &[MANIFEST_TYPE],
            &content,
        )
        .await?;
    assert_eq!(rejected.status, 400, "{}", rejected.text);
    assert!(registry.repository("fresh")?.is_none());
    Ok(())
}

#[tokio::test]
async fn deleting_absent_or_untagged_publishes_no_epoch() -> TestResult {
    let registry = Registry::new()?;
    let content = manifest("untagged");
    let digest = Kappa::sha256(&content);
    let pushed = registry
        .send(
            "PUT",
            &format!("/v2/app/manifests/{digest}"),
            &[MANIFEST_TYPE],
            &content,
        )
        .await?;
    assert_eq!(pushed.status, 201, "{}", pushed.text);
    let ns = registry
        .repository("app")?
        .ok_or("repository not created")?;
    let before = registry.epoch(&ns)?;

    let missing_tag = registry
        .send("DELETE", "/v2/app/manifests/missing", &[], b"")
        .await?;
    assert_eq!(missing_tag.status, 404, "{}", missing_tag.text);
    let envelope: serde_json::Value = serde_json::from_str(&missing_tag.text)?;
    assert_eq!(
        envelope["errors"][0]["code"], "MANIFEST_UNKNOWN",
        "{}",
        missing_tag.text
    );

    let missing_query = registry
        .send("DELETE", "/v2/app/tags/?name=missing", &[], b"")
        .await?;
    assert_eq!(missing_query.status, 404, "{}", missing_query.text);

    let no_prefix = registry
        .send("DELETE", "/v2/app/tags/_prefix?prefix=none-", &[], b"")
        .await?;
    assert_eq!(no_prefix.status, 200, "{}", no_prefix.text);
    assert_eq!(no_prefix.text, r#"{"deleted":0}"#);
    assert_eq!(no_prefix.header("x-kappa-epoch")?, None);

    // Every refused or no-op deletion above published nothing.
    assert_eq!(registry.epoch(&ns)?, before);

    // The untagged manifest is the repository's by its reference: deleting
    // it by digest retires the reference in one epoch, after which the
    // repository no longer serves it.
    let untagged = registry
        .send("DELETE", &format!("/v2/app/manifests/{digest}"), &[], b"")
        .await?;
    assert_eq!(untagged.status, 202, "{}", untagged.text);
    let after = before.map(|epoch| epoch + 1);
    assert_eq!(
        untagged.header("x-kappa-epoch")?,
        after.map(|epoch| epoch.to_string()).as_deref()
    );
    assert_eq!(registry.epoch(&ns)?, after);
    let gone = registry
        .send("GET", &format!("/v2/app/manifests/{digest}"), &[], b"")
        .await?;
    assert_eq!(gone.status, 404, "{}", gone.text);
    Ok(())
}

#[tokio::test]
async fn idempotent_manifest_put_replays_once_and_conflicts_on_new_body() -> TestResult {
    let registry = Registry::new()?;
    let content = manifest("idempotent");
    let key = ("idempotency-key", "push-1");
    let first = registry
        .send(
            "PUT",
            "/v2/app/manifests/v1",
            &[MANIFEST_TYPE, key],
            &content,
        )
        .await?;
    assert_eq!(first.status, 201, "{}", first.text);
    assert_eq!(first.header("idempotent-replayed")?, None);
    let ns = registry
        .repository("app")?
        .ok_or("repository not created")?;
    let published = registry.epoch(&ns)?.ok_or("push published no epoch")?;

    let replay = registry
        .send(
            "PUT",
            "/v2/app/manifests/v1",
            &[MANIFEST_TYPE, key],
            &content,
        )
        .await?;
    assert_eq!(replay.status, 201, "{}", replay.text);
    assert_eq!(replay.header("idempotent-replayed")?, Some("true"));
    assert_eq!(
        replay.header("x-kappa-epoch")?,
        Some(published.to_string().as_str())
    );
    assert_eq!(
        replay.header("docker-content-digest")?,
        first.header("docker-content-digest")?
    );
    assert_eq!(registry.epoch(&ns)?, Some(published));

    let conflicting = registry
        .send(
            "PUT",
            "/v2/app/manifests/v1",
            &[MANIFEST_TYPE, key],
            &manifest("different"),
        )
        .await?;
    assert_eq!(conflicting.status, 409, "{}", conflicting.text);
    assert_eq!(registry.epoch(&ns)?, Some(published));
    assert_eq!(registry.tag(&ns, "v1")?, Some(Kappa::sha256(&content)));
    Ok(())
}

#[tokio::test]
async fn failed_tag_batch_member_publishes_nothing() -> TestResult {
    let registry = Registry::new()?;
    let content = manifest("batch");
    let pushed = registry
        .send("PUT", "/v2/app/manifests/v1", &[MANIFEST_TYPE], &content)
        .await?;
    assert_eq!(pushed.status, 201, "{}", pushed.text);
    let ns = registry
        .repository("app")?
        .ok_or("repository not created")?;
    let before = registry.epoch(&ns)?;
    let digest = Kappa::sha256(&content);

    let batch = format!(
        r#"{{"updates":[{{"name":"fresh","kappa":"{digest}"}},{{"name":"v1","kappa":"{digest}","expected_version":0}}]}}"#
    );
    let rejected = registry
        .send("POST", "/v2/app/tags/_batch", &[], batch.as_bytes())
        .await?;
    assert_eq!(rejected.status, 409, "{}", rejected.text);
    assert_eq!(registry.epoch(&ns)?, before);
    assert_eq!(registry.tag(&ns, "fresh")?, None);
    Ok(())
}
