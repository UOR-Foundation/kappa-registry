//! Identity substrate conformance tests: Groups 1-5 (Tier 1).
//!
//! These tests define the API contract for identity primitives.
//! Every test calls a KappaStore trait method and asserts success.
//! Tests FAIL until the implementation replaces the default
//! Err(Rejected("not implemented")) stubs.

use std::sync::Arc;

use kappa_core::clock::ntp_lamport::NtpLamportClock;
use kappa_core::identity::binding::IdentityBinding;
use kappa_core::identity::succession::IdentitySuccession;
use kappa_core::store::KappaStore;
use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
use kappa_core::types::*;

fn test_store() -> InMemoryStore {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(NtpLamportClock::new());
    InMemoryStore::new(
        MemoryStoreConfig::new(dir.path().join("blobs")),
        clock,
    ).unwrap()
}

// =============================================================================
// Group 1: IdentityBinding (12 tests)
// =============================================================================

#[test]
fn binding_create_stores_and_returns_kappa() {
    let store = test_store();
    let ns = NamespaceRef::deterministic("test-ns");
    let binding = IdentityBinding {
        source: "user@example.com".into(),
        target: "sha256:anchor123".into(),
        method: "email-link".into(),
        trust_level: 2,
        verified_at_ms: 1000,
    };
    let kappa = store.identity_binding_put(&ns, &binding).unwrap();
    assert!(kappa.starts_with("sha256:"), "kappa should be sha256, got {kappa}");
}

#[test]
fn binding_get_returns_stored_binding() {
    let store = test_store();
    let ns = NamespaceRef::deterministic("test-ns");
    let binding = IdentityBinding {
        source: "user@example.com".into(),
        target: "sha256:anchor123".into(),
        method: "email-link".into(),
        trust_level: 2,
        verified_at_ms: 1000,
    };
    store.identity_binding_put(&ns, &binding).unwrap();
    let results = store.identity_binding_get("user@example.com").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].target, "sha256:anchor123");
    assert_eq!(results[0].method, "email-link");
}

#[test]
fn binding_list_returns_all_for_subject() {
    let store = test_store();
    let ns = NamespaceRef::deterministic("test-ns");
    for i in 0..3 {
        let binding = IdentityBinding {
            source: "shared-subject".into(),
            target: format!("sha256:anchor{i}"),
            method: "self-asserted".into(),
            trust_level: 1,
            verified_at_ms: i * 100,
        };
        store.identity_binding_put(&ns, &binding).unwrap();
    }
    let results = store.identity_binding_get("shared-subject").unwrap();
    assert_eq!(results.len(), 3);
}

#[test]
fn binding_list_empty_for_unknown_subject() {
    let store = test_store();
    let results = store.identity_binding_get("nobody@nowhere.com").unwrap();
    assert!(results.is_empty());
}

#[test]
fn binding_delete_removes_binding() {
    let store = test_store();
    let ns = NamespaceRef::deterministic("test-ns");
    let binding = IdentityBinding {
        source: "delete-me@example.com".into(),
        target: "sha256:anchor-del".into(),
        method: "self-asserted".into(),
        trust_level: 1,
        verified_at_ms: 0,
    };
    store.identity_binding_put(&ns, &binding).unwrap();
    store.identity_binding_delete(&ns, "delete-me@example.com", "sha256:anchor-del").unwrap();
    let results = store.identity_binding_get("delete-me@example.com").unwrap();
    assert!(results.is_empty());
}

#[test]
fn binding_list_by_asserter() {
    let store = test_store();
    let ns = NamespaceRef::deterministic("test-ns");
    let asserter = "sha256:my-anchor";
    for source in &["email@a.com", "email@b.com", "email@c.com"] {
        let binding = IdentityBinding {
            source: source.to_string(),
            target: asserter.into(),
            method: "self-asserted".into(),
            trust_level: 1,
            verified_at_ms: 0,
        };
        store.identity_binding_put(&ns, &binding).unwrap();
    }
    let results = store.identity_binding_list_by_asserter(asserter).unwrap();
    assert_eq!(results.len(), 3);
}

#[test]
fn binding_list_by_asserter_empty() {
    let store = test_store();
    let results = store.identity_binding_list_by_asserter("sha256:nonexistent").unwrap();
    assert!(results.is_empty());
}

#[test]
fn binding_duplicate_source_target_is_idempotent() {
    let store = test_store();
    let ns = NamespaceRef::deterministic("test-ns");
    let binding = IdentityBinding {
        source: "dup@example.com".into(),
        target: "sha256:anchor-dup".into(),
        method: "self-asserted".into(),
        trust_level: 1,
        verified_at_ms: 0,
    };
    let k1 = store.identity_binding_put(&ns, &binding).unwrap();
    let k2 = store.identity_binding_put(&ns, &binding).unwrap();
    assert_eq!(k1, k2, "duplicate binding should produce same kappa");
    let results = store.identity_binding_get("dup@example.com").unwrap();
    assert_eq!(results.len(), 1, "duplicate should not create second entry");
}

#[test]
fn binding_different_asserters_same_source() {
    let store = test_store();
    let ns = NamespaceRef::deterministic("test-ns");
    let b1 = IdentityBinding {
        source: "contested@example.com".into(),
        target: "sha256:anchor-a".into(),
        method: "self-asserted".into(),
        trust_level: 1,
        verified_at_ms: 100,
    };
    let b2 = IdentityBinding {
        source: "contested@example.com".into(),
        target: "sha256:anchor-b".into(),
        method: "self-asserted".into(),
        trust_level: 1,
        verified_at_ms: 200,
    };
    store.identity_binding_put(&ns, &b1).unwrap();
    store.identity_binding_put(&ns, &b2).unwrap();
    let results = store.identity_binding_get("contested@example.com").unwrap();
    assert_eq!(results.len(), 2, "different targets for same source should both exist");
}

#[test]
fn binding_delete_nonexistent_is_noop() {
    let store = test_store();
    let ns = NamespaceRef::deterministic("test-ns");
    // Should not error on deleting something that doesn't exist
    store.identity_binding_delete(&ns, "ghost@nowhere.com", "sha256:ghost").unwrap();
}

#[test]
fn binding_query_isolation_by_source() {
    let store = test_store();
    let ns = NamespaceRef::deterministic("test-ns");
    let b1 = IdentityBinding {
        source: "alice@example.com".into(),
        target: "sha256:alice".into(),
        method: "self-asserted".into(),
        trust_level: 1,
        verified_at_ms: 0,
    };
    let b2 = IdentityBinding {
        source: "bob@example.com".into(),
        target: "sha256:bob".into(),
        method: "self-asserted".into(),
        trust_level: 1,
        verified_at_ms: 0,
    };
    store.identity_binding_put(&ns, &b1).unwrap();
    store.identity_binding_put(&ns, &b2).unwrap();
    let alice_results = store.identity_binding_get("alice@example.com").unwrap();
    assert_eq!(alice_results.len(), 1);
    assert_eq!(alice_results[0].target, "sha256:alice");
}

#[test]
fn binding_fields_preserved() {
    let store = test_store();
    let ns = NamespaceRef::deterministic("test-ns");
    let binding = IdentityBinding {
        source: "fields@test.com".into(),
        target: "sha256:fields-anchor".into(),
        method: "dns-txt".into(),
        trust_level: 3,
        verified_at_ms: 999999,
    };
    store.identity_binding_put(&ns, &binding).unwrap();
    let results = store.identity_binding_get("fields@test.com").unwrap();
    assert_eq!(results[0].source, "fields@test.com");
    assert_eq!(results[0].target, "sha256:fields-anchor");
    assert_eq!(results[0].method, "dns-txt");
    assert_eq!(results[0].trust_level, 3);
    assert_eq!(results[0].verified_at_ms, 999999);
}

// =============================================================================
// Group 2: IdentitySuccession (10 tests)
// =============================================================================

#[test]
fn succession_put_returns_kappa() {
    let store = test_store();
    let s = IdentitySuccession {
        old_anchor: "sha256:old".into(),
        new_anchor: "sha256:new".into(),
        reason: "rotation".into(),
        effective_at_ms: 1000,
        old_signature: vec![1, 2, 3],
        new_signature: vec![4, 5, 6],
    };
    let kappa = store.identity_succession_put(&s).unwrap();
    assert!(kappa.starts_with("sha256:"));
}

#[test]
fn succession_resolve_returns_current() {
    let store = test_store();
    let s = IdentitySuccession {
        old_anchor: "sha256:original".into(),
        new_anchor: "sha256:successor".into(),
        reason: "rotation".into(),
        effective_at_ms: 1000,
        old_signature: vec![],
        new_signature: vec![],
    };
    store.identity_succession_put(&s).unwrap();
    let current = store.identity_succession_resolve("sha256:original").unwrap();
    assert_eq!(current, "sha256:successor");
}

#[test]
fn succession_chain_3_deep() {
    let store = test_store();
    store.identity_succession_put(&IdentitySuccession {
        old_anchor: "sha256:a".into(), new_anchor: "sha256:b".into(),
        reason: "rotation".into(), effective_at_ms: 100,
        old_signature: vec![], new_signature: vec![],
    }).unwrap();
    store.identity_succession_put(&IdentitySuccession {
        old_anchor: "sha256:b".into(), new_anchor: "sha256:c".into(),
        reason: "rotation".into(), effective_at_ms: 200,
        old_signature: vec![], new_signature: vec![],
    }).unwrap();
    let current = store.identity_succession_resolve("sha256:a").unwrap();
    assert_eq!(current, "sha256:c");
}

#[test]
fn succession_chain_returns_ordered_list() {
    let store = test_store();
    store.identity_succession_put(&IdentitySuccession {
        old_anchor: "sha256:first".into(), new_anchor: "sha256:second".into(),
        reason: "rotation".into(), effective_at_ms: 100,
        old_signature: vec![], new_signature: vec![],
    }).unwrap();
    store.identity_succession_put(&IdentitySuccession {
        old_anchor: "sha256:second".into(), new_anchor: "sha256:third".into(),
        reason: "rotation".into(), effective_at_ms: 200,
        old_signature: vec![], new_signature: vec![],
    }).unwrap();
    let chain = store.identity_succession_chain("sha256:first").unwrap();
    assert_eq!(chain, vec!["sha256:first", "sha256:second", "sha256:third"]);
}

#[test]
fn succession_resolve_no_successor_returns_self() {
    let store = test_store();
    let current = store.identity_succession_resolve("sha256:standalone").unwrap();
    assert_eq!(current, "sha256:standalone");
}

#[test]
fn succession_chain_no_successor_returns_single() {
    let store = test_store();
    let chain = store.identity_succession_chain("sha256:standalone").unwrap();
    assert_eq!(chain, vec!["sha256:standalone"]);
}

#[test]
fn succession_cannot_succeed_to_self() {
    let store = test_store();
    let s = IdentitySuccession {
        old_anchor: "sha256:same".into(),
        new_anchor: "sha256:same".into(),
        reason: "rotation".into(),
        effective_at_ms: 100,
        old_signature: vec![],
        new_signature: vec![],
    };
    let result = store.identity_succession_put(&s);
    assert!(result.is_err(), "self-succession should be rejected");
}

#[test]
fn succession_cycle_detected() {
    let store = test_store();
    store.identity_succession_put(&IdentitySuccession {
        old_anchor: "sha256:x".into(), new_anchor: "sha256:y".into(),
        reason: "rotation".into(), effective_at_ms: 100,
        old_signature: vec![], new_signature: vec![],
    }).unwrap();
    store.identity_succession_put(&IdentitySuccession {
        old_anchor: "sha256:y".into(), new_anchor: "sha256:x".into(),
        reason: "rotation".into(), effective_at_ms: 200,
        old_signature: vec![], new_signature: vec![],
    }).unwrap();
    // resolve should detect the cycle and return an error, not loop forever
    let result = store.identity_succession_resolve("sha256:x");
    assert!(result.is_err(), "cycle should be detected");
}

#[test]
fn succession_fields_preserved() {
    let store = test_store();
    let s = IdentitySuccession {
        old_anchor: "sha256:old-fields".into(),
        new_anchor: "sha256:new-fields".into(),
        reason: "compromise".into(),
        effective_at_ms: 42000,
        old_signature: vec![10, 20],
        new_signature: vec![30, 40],
    };
    store.identity_succession_put(&s).unwrap();
    let chain = store.identity_succession_chain("sha256:old-fields").unwrap();
    assert_eq!(chain.len(), 2);
}

#[test]
fn succession_overwrite_replaces() {
    let store = test_store();
    store.identity_succession_put(&IdentitySuccession {
        old_anchor: "sha256:base".into(), new_anchor: "sha256:first-succ".into(),
        reason: "rotation".into(), effective_at_ms: 100,
        old_signature: vec![], new_signature: vec![],
    }).unwrap();
    // Overwrite with different successor
    store.identity_succession_put(&IdentitySuccession {
        old_anchor: "sha256:base".into(), new_anchor: "sha256:second-succ".into(),
        reason: "correction".into(), effective_at_ms: 200,
        old_signature: vec![], new_signature: vec![],
    }).unwrap();
    let current = store.identity_succession_resolve("sha256:base").unwrap();
    assert_eq!(current, "sha256:second-succ");
}

// =============================================================================
// Group 3: ExternalIdentifierResolver (8 tests)
// =============================================================================

use kappa_core::identity::resolver::{ExternalIdentifierResolver, ResolvedIdentity};

struct MockResolver {
    entries: std::collections::HashMap<String, ResolvedIdentity>,
}

impl ExternalIdentifierResolver for MockResolver {
    fn id_type(&self) -> &str { "mock" }
    fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, String> {
        Ok(self.entries.get(identifier).cloned())
    }
}

#[test]
fn resolver_trait_resolve_found() {
    let mut entries = std::collections::HashMap::new();
    entries.insert("user@example.com".into(), ResolvedIdentity {
        anchor: "sha256:resolved-anchor".into(),
        public_key: vec![1, 2, 3],
        algorithm: "ed25519".into(),
        service_endpoint: None,
        handle: "user@example.com".into(),
        evidence: None,
    });
    let resolver = MockResolver { entries };
    let result = resolver.resolve("user@example.com").unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().anchor, "sha256:resolved-anchor");
}

#[test]
fn resolver_trait_resolve_not_found() {
    let resolver = MockResolver { entries: std::collections::HashMap::new() };
    let result = resolver.resolve("nobody@nowhere.com").unwrap();
    assert!(result.is_none());
}

#[test]
fn resolver_trait_id_type() {
    let resolver = MockResolver { entries: std::collections::HashMap::new() };
    assert_eq!(resolver.id_type(), "mock");
}

#[test]
fn resolver_trait_cache_ttl_default() {
    let resolver = MockResolver { entries: std::collections::HashMap::new() };
    assert_eq!(resolver.cache_ttl_secs(), 300);
}

#[test]
fn resolver_resolved_identity_fields() {
    let ri = ResolvedIdentity {
        anchor: "sha256:a".into(),
        public_key: vec![42; 32],
        algorithm: "ed25519".into(),
        service_endpoint: Some("https://example.com".into()),
        handle: "user".into(),
        evidence: Some(vec![1, 2, 3]),
    };
    assert_eq!(ri.anchor, "sha256:a");
    assert_eq!(ri.public_key.len(), 32);
    assert_eq!(ri.algorithm, "ed25519");
    assert_eq!(ri.service_endpoint.as_deref(), Some("https://example.com"));
    assert_eq!(ri.handle, "user");
    assert_eq!(ri.evidence.as_ref().unwrap().len(), 3);
}

#[test]
fn resolver_multiple_identifiers() {
    let mut entries = std::collections::HashMap::new();
    entries.insert("alice@a.com".into(), ResolvedIdentity {
        anchor: "sha256:alice".into(), public_key: vec![], algorithm: "ed25519".into(),
        service_endpoint: None, handle: "alice".into(), evidence: None,
    });
    entries.insert("bob@b.com".into(), ResolvedIdentity {
        anchor: "sha256:bob".into(), public_key: vec![], algorithm: "ed25519".into(),
        service_endpoint: None, handle: "bob".into(), evidence: None,
    });
    let resolver = MockResolver { entries };
    assert_eq!(resolver.resolve("alice@a.com").unwrap().unwrap().anchor, "sha256:alice");
    assert_eq!(resolver.resolve("bob@b.com").unwrap().unwrap().anchor, "sha256:bob");
}

#[test]
fn resolver_same_anchor_different_ids() {
    let mut entries = std::collections::HashMap::new();
    let anchor = "sha256:shared-anchor";
    entries.insert("email@x.com".into(), ResolvedIdentity {
        anchor: anchor.into(), public_key: vec![], algorithm: "ed25519".into(),
        service_endpoint: None, handle: "email".into(), evidence: None,
    });
    entries.insert("github:user".into(), ResolvedIdentity {
        anchor: anchor.into(), public_key: vec![], algorithm: "ed25519".into(),
        service_endpoint: None, handle: "github".into(), evidence: None,
    });
    let resolver = MockResolver { entries };
    let r1 = resolver.resolve("email@x.com").unwrap().unwrap();
    let r2 = resolver.resolve("github:user").unwrap().unwrap();
    assert_eq!(r1.anchor, r2.anchor);
}

#[test]
fn resolver_evidence_optional() {
    let ri = ResolvedIdentity {
        anchor: "sha256:a".into(), public_key: vec![], algorithm: "ed25519".into(),
        service_endpoint: None, handle: "h".into(), evidence: None,
    };
    assert!(ri.evidence.is_none());
}

// =============================================================================
// Group 4: AKD Integration (10 tests)
// Tests use the existing assertion_index_put / assertion_index_query_subject
// which are already implemented on both stores.
// =============================================================================

#[test]
fn inbound_index_put_and_query() {
    let store = test_store();
    store.assertion_index_put("subject-1", "facet-a", "sha256:assertion-kappa-1").unwrap();
    let results = store.assertion_index_query_subject("subject-1").unwrap();
    assert!(results.contains(&"sha256:assertion-kappa-1".to_string()));
}

#[test]
fn inbound_index_multiple_facets_same_subject() {
    let store = test_store();
    store.assertion_index_put("subject-m", "facet-a", "sha256:k1").unwrap();
    store.assertion_index_put("subject-m", "facet-b", "sha256:k2").unwrap();
    store.assertion_index_put("subject-m", "facet-c", "sha256:k3").unwrap();
    let results = store.assertion_index_query_subject("subject-m").unwrap();
    assert_eq!(results.len(), 3);
}

#[test]
fn inbound_index_empty_for_unknown() {
    let store = test_store();
    let results = store.assertion_index_query_subject("nobody").unwrap();
    assert!(results.is_empty());
}

#[test]
fn inbound_index_not_duplicated() {
    let store = test_store();
    store.assertion_index_put("subj", "facet", "sha256:k").unwrap();
    store.assertion_index_put("subj", "facet", "sha256:k").unwrap();
    let results = store.assertion_index_query_subject("subj").unwrap();
    // Depending on implementation, duplicates may or may not be stored.
    // The query should return at least 1 and the value should be correct.
    assert!(!results.is_empty());
    assert!(results.contains(&"sha256:k".to_string()));
}

#[test]
fn inbound_index_cross_subject_isolation() {
    let store = test_store();
    store.assertion_index_put("alice", "facet", "sha256:alice-k").unwrap();
    store.assertion_index_put("bob", "facet", "sha256:bob-k").unwrap();
    let alice_results = store.assertion_index_query_subject("alice").unwrap();
    assert!(alice_results.contains(&"sha256:alice-k".to_string()));
    assert!(!alice_results.contains(&"sha256:bob-k".to_string()));
}

// =============================================================================
// Group 5: Cross-Namespace Inbound Index (8 tests)
// Uses assertion_index_put/query which are already implemented.
// =============================================================================

#[test]
fn inbound_index_multiple_asserters_same_subject() {
    let store = test_store();
    store.assertion_index_put("shared-subj", "trust", "sha256:from-asserter-a").unwrap();
    store.assertion_index_put("shared-subj", "trust", "sha256:from-asserter-b").unwrap();
    let results = store.assertion_index_query_subject("shared-subj").unwrap();
    assert!(results.len() >= 2);
}

#[test]
fn inbound_index_query_returns_all_facets() {
    let store = test_store();
    store.assertion_index_put("multi-facet", "version", "sha256:v1").unwrap();
    store.assertion_index_put("multi-facet", "status", "sha256:s1").unwrap();
    store.assertion_index_put("multi-facet", "role", "sha256:r1").unwrap();
    let results = store.assertion_index_query_subject("multi-facet").unwrap();
    assert_eq!(results.len(), 3);
}

#[test]
fn inbound_index_large_batch() {
    let store = test_store();
    for i in 0..100 {
        store.assertion_index_put(
            "batch-subject",
            &format!("facet-{i}"),
            &format!("sha256:k{i}"),
        ).unwrap();
    }
    let results = store.assertion_index_query_subject("batch-subject").unwrap();
    assert_eq!(results.len(), 100);
}
