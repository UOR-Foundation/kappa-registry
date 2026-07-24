pub mod extract;
pub mod segments;

use std::collections::HashMap;

/// Parsed HTTP endpoint. Each variant is annotated with `#[op_class(...)]`
/// for tiered rate limiting. The `ClassifyEndpoint` derive macro generates
/// `op_class(&self) -> OpClass` from these annotations. Adding a new variant
/// without an `#[op_class(...)]` attribute is a compile error.
///
/// Operation classes:
///   Exempt -- health probes, version check (never rate limited)
///   Read   -- GET/HEAD on content, metadata, listings
///   Write  -- PUT/POST/PATCH on content, manifests, edges, uploads
///   Admin  -- DELETE, GC, transactions, reconcile
#[derive(Debug, kappa_macros::ClassifyEndpoint)]
pub enum Endpoint<'a> {
    #[op_class(Exempt)]
    Version,
    #[op_class(Exempt)]
    Health,

    // L1 blobs
    #[op_class(Read)]
    BlobGet { ns: &'a str, kappa: &'a str },
    #[op_class(Read)]
    BlobHead { ns: &'a str, kappa: &'a str },
    #[op_class(Write)]
    BlobPut { ns: &'a str, kappa: &'a str },
    #[op_class(Admin)]
    BlobDelete { ns: &'a str, kappa: &'a str },
    #[op_class(Read)]
    BlobList { ns: &'a str },
    #[op_class(Read)]
    MetaList { ns: &'a str },

    // L1 uploads
    #[op_class(Write)]
    UploadStart { ns: &'a str },
    #[op_class(Write)]
    UploadChunk { id: &'a str },
    #[op_class(Read)]
    UploadStatus { id: &'a str },
    #[op_class(Write)]
    UploadComplete { id: &'a str },
    #[op_class(Admin)]
    UploadCancel { id: &'a str },

    // L2 manifests (atomic store+tag)
    #[op_class(Read)]
    ManifestHead { ns: &'a str, version: &'a str },
    #[op_class(Read)]
    ManifestGet { ns: &'a str, version: &'a str },
    #[op_class(Write)]
    ManifestPut { ns: &'a str, tag: &'a str },
    #[op_class(Admin)]
    ManifestDelete { ns: &'a str, tag: &'a str },

    // L2 tags
    #[op_class(Read)]
    TagList { ns: &'a str },
    #[op_class(Read)]
    TagGet { ns: &'a str, name: &'a str },
    #[op_class(Write)]
    TagPut { ns: &'a str, name: &'a str },
    #[op_class(Write)]
    TagBatch { ns: &'a str },

    // OCI referrers
    #[op_class(Read)]
    Referrers { ns: &'a str, digest: &'a str },

    // L3 edges
    #[op_class(Write)]
    EdgePut { ns: &'a str },
    #[op_class(Read)]
    EdgeQuery { ns: &'a str, node: &'a str },
    #[op_class(Admin)]
    EdgeDelete { ns: &'a str, kappa: &'a str },
    #[op_class(Read)]
    EdgeDiff { ns: &'a str },

    // Set reconciliation
    #[op_class(Admin)]
    Reconcile { ns: &'a str },

    // Bundles
    #[op_class(Read)]
    BundleCreate { ns: &'a str },
    #[op_class(Write)]
    BundleIngest { ns: &'a str },

    // Transactions
    #[op_class(Admin)]
    TransactionBegin { ns: &'a str },
    #[op_class(Write)]
    TransactionPut {
        ns: &'a str,
        id: &'a str,
        kappa: &'a str,
    },
    #[op_class(Admin)]
    TransactionCommit { ns: &'a str, id: &'a str },
    #[op_class(Admin)]
    TransactionAbort { ns: &'a str, id: &'a str },

    // L4 composition
    #[op_class(Write)]
    Compose { ns: &'a str, op: &'a str },
    #[op_class(Read)]
    Witness { ns: &'a str, kappa: &'a str },

    // L4 schemas
    #[op_class(Write)]
    SchemaPut { ns: &'a str, scope: &'a str },
    #[op_class(Read)]
    SchemaGet { ns: &'a str, scope: &'a str },
    #[op_class(Read)]
    SchemaList { ns: &'a str },

    // L5 GC
    #[op_class(Admin)]
    GcPin { ns: &'a str },
    #[op_class(Admin)]
    GcUnpin { ns: &'a str },
    #[op_class(Admin)]
    GcSweep { ns: &'a str },
    #[op_class(Read)]
    GcStatus { ns: &'a str },

    // L5 filters
    #[op_class(Write)]
    FilterPut { ns: &'a str, scope: &'a str },
    #[op_class(Read)]
    FilterList { ns: &'a str },
    #[op_class(Admin)]
    FilterDelete { ns: &'a str, kappa: &'a str },

    // Namespace root
    #[op_class(Read)]
    NamespaceRoot { ns: &'a str },
    #[op_class(Read)]
    NamespaceProof { ns: &'a str, name: &'a str },

    #[op_class(Read)]
    NotFound,
}

pub fn parse<'a>(method: &str, path: &'a str) -> Endpoint<'a> {
    if path == segments::PREFIX_BARE || path == segments::PREFIX {
        return Endpoint::Version;
    }

    if extract::health_probe(path).is_some() {
        return Endpoint::Health;
    }

    if let Some(id) = extract::upload_id(path) {
        return match method {
            "PATCH" => Endpoint::UploadChunk { id },
            "GET" => Endpoint::UploadStatus { id },
            "PUT" => Endpoint::UploadComplete { id },
            "DELETE" => Endpoint::UploadCancel { id },
            _ => Endpoint::NotFound,
        };
    }

    if !path.starts_with(segments::PREFIX) {
        return Endpoint::NotFound;
    }

    let inner = &path[segments::PREFIX.len()..];

    // Meta list: {ns}/blobs/_meta (must match before blobs/uploads and general blobs)
    if inner.ends_with(segments::BLOBS_META) && method == "GET" {
        if let Some(ns) = extract::ns_before_suffix(path, segments::BLOBS_META) {
            return Endpoint::MetaList { ns };
        }
    }

    // Upload start: {ns}/blobs/uploads/
    if inner.contains(segments::BLOBS_UPLOADS) || inner.ends_with(segments::BLOBS_UPLOADS_BARE) {
        if let Some((ns, _)) = extract::split_at_allow_empty(path, segments::BLOBS_UPLOADS) {
            return Endpoint::UploadStart { ns };
        }
        if let Some((ns, _)) = extract::split_at_allow_empty(path, segments::BLOBS_UPLOADS_BARE) {
            return Endpoint::UploadStart { ns };
        }
    }

    // Tag batch: {ns}/tags/_batch (must match before general tag routing)
    if inner.ends_with(segments::TAGS_BATCH) && method == "POST" {
        if let Some(ns) = extract::ns_before_suffix(path, segments::TAGS_BATCH) {
            return Endpoint::TagBatch { ns };
        }
    }

    // Tag list: {ns}/tags/list
    if inner.ends_with(segments::TAGS_LIST) {
        if let Some(ns) = extract::ns_before_suffix(path, segments::TAGS_LIST) {
            return Endpoint::TagList { ns };
        }
    }

    // Tags: {ns}/tags/{name}
    if inner.contains(segments::TAGS) && !inner.ends_with(segments::TAGS_LIST) {
        if let Some((ns, name)) = extract::split_at(path, segments::TAGS) {
            if !name.is_empty() && !name.contains('/') {
                return match method {
                    "GET" => Endpoint::TagGet { ns, name },
                    "PUT" => Endpoint::TagPut { ns, name },
                    _ => Endpoint::NotFound,
                };
            }
        }
    }

    // Manifests: {ns}/manifests/{version}
    if inner.contains(segments::MANIFESTS) {
        if let Some((ns, version)) = extract::split_at(path, segments::MANIFESTS) {
            if !version.is_empty() {
                return match method {
                    "HEAD" => Endpoint::ManifestHead { ns, version },
                    "GET" => Endpoint::ManifestGet { ns, version },
                    "PUT" => Endpoint::ManifestPut { ns, tag: version },
                    "DELETE" => Endpoint::ManifestDelete { ns, tag: version },
                    _ => Endpoint::NotFound,
                };
            }
        }
    }

    // Referrers: {ns}/referrers/{digest}
    if inner.contains(segments::REFERRERS) {
        if let Some((ns, digest)) = extract::split_at(path, segments::REFERRERS) {
            if !digest.is_empty() && method == "GET" {
                return Endpoint::Referrers { ns, digest };
            }
        }
    }

    // Compose: {ns}/compose/{op}
    if inner.contains(segments::COMPOSE) {
        if let Some((ns, op)) = extract::split_at(path, segments::COMPOSE) {
            if !op.is_empty() {
                return Endpoint::Compose { ns, op };
            }
        }
    }

    // Witnesses: {ns}/witnesses/{kappa}
    if inner.contains(segments::WITNESSES) {
        if let Some((ns, kappa)) = extract::split_at(path, segments::WITNESSES) {
            if !kappa.is_empty() {
                return Endpoint::Witness { ns, kappa };
            }
        }
    }

    // GC: {ns}/gc/{action}
    if inner.ends_with(segments::GC_PIN) {
        if let Some(ns) = extract::ns_before_suffix(path, segments::GC_PIN) {
            return Endpoint::GcPin { ns };
        }
    }
    if inner.ends_with(segments::GC_UNPIN) {
        if let Some(ns) = extract::ns_before_suffix(path, segments::GC_UNPIN) {
            return Endpoint::GcUnpin { ns };
        }
    }
    if inner.ends_with(segments::GC_SWEEP) {
        if let Some(ns) = extract::ns_before_suffix(path, segments::GC_SWEEP) {
            return Endpoint::GcSweep { ns };
        }
    }
    if inner.ends_with(segments::GC_STATUS) {
        if let Some(ns) = extract::ns_before_suffix(path, segments::GC_STATUS) {
            return Endpoint::GcStatus { ns };
        }
    }

    // Schemas: {ns}/schemas/{scope} or {ns}/schemas/
    if inner.contains(segments::SCHEMAS) {
        if let Some((ns, scope)) = extract::split_at_allow_empty(path, segments::SCHEMAS) {
            if scope.is_empty() {
                return Endpoint::SchemaList { ns };
            }
            return match method {
                "PUT" => Endpoint::SchemaPut { ns, scope },
                "GET" => Endpoint::SchemaGet { ns, scope },
                _ => Endpoint::NotFound,
            };
        }
    }
    if inner.ends_with(segments::SCHEMAS_BARE) {
        if let Some(ns) = extract::ns_before_suffix(path, segments::SCHEMAS_BARE) {
            return Endpoint::SchemaList { ns };
        }
    }

    // Filters: {ns}/filters/{scope} or {ns}/filters/
    if inner.contains(segments::FILTERS) {
        if let Some((ns, trailing)) = extract::split_at_allow_empty(path, segments::FILTERS) {
            if trailing.is_empty() {
                return Endpoint::FilterList { ns };
            }
            return match method {
                "PUT" => Endpoint::FilterPut {
                    ns,
                    scope: trailing,
                },
                "DELETE" => Endpoint::FilterDelete {
                    ns,
                    kappa: trailing,
                },
                "GET" => Endpoint::FilterList { ns },
                _ => Endpoint::NotFound,
            };
        }
    }
    if inner.ends_with(segments::FILTERS_BARE) {
        if let Some(ns) = extract::ns_before_suffix(path, segments::FILTERS_BARE) {
            return Endpoint::FilterList { ns };
        }
    }

    // Transactions: {ns}/_transaction/begin, {ns}/_transaction/{id}/commit,
    // {ns}/_transaction/{id}/{kappa}, {ns}/_transaction/{id}
    if inner.contains(segments::TRANSACTION) {
        if inner.ends_with(segments::TRANSACTION_BEGIN) && method == "POST" {
            if let Some(ns) = extract::ns_before_suffix(path, segments::TRANSACTION_BEGIN) {
                return Endpoint::TransactionBegin { ns };
            }
        }
        if let Some((ns, rest)) = extract::split_at(path, segments::TRANSACTION) {
            if !rest.is_empty() {
                // rest is "{id}/commit" or "{id}/{kappa}" or "{id}"
                if let Some((id, suffix)) = rest.split_once('/') {
                    if suffix == "commit" && method == "POST" {
                        return Endpoint::TransactionCommit { ns, id };
                    }
                    if method == "PUT" {
                        return Endpoint::TransactionPut {
                            ns,
                            id,
                            kappa: suffix,
                        };
                    }
                }
                // DELETE {ns}/_transaction/{id}
                if method == "DELETE" && !rest.contains('/') {
                    return Endpoint::TransactionAbort { ns, id: rest };
                }
            }
        }
    }

    // Edge diff: {ns}/edges/_diff (must match before general edge routing)
    if inner.ends_with(segments::EDGE_DIFF) && method == "POST" {
        if let Some(ns) = extract::ns_before_suffix(path, segments::EDGE_DIFF) {
            return Endpoint::EdgeDiff { ns };
        }
    }

    // Namespace proof: {ns}/_root/proof/{name} (must match before _root)
    if inner.contains(segments::NAMESPACE_PROOF) && method == "GET" {
        if let Some((ns, name)) = extract::split_at(path, segments::NAMESPACE_PROOF) {
            if !name.is_empty() {
                return Endpoint::NamespaceProof { ns, name };
            }
        }
    }

    // Namespace root: {ns}/_root
    if inner.ends_with(segments::NAMESPACE_ROOT) && !inner.contains("proof") && method == "GET" {
        if let Some(ns) = extract::ns_before_suffix(path, segments::NAMESPACE_ROOT) {
            return Endpoint::NamespaceRoot { ns };
        }
    }

    // Reconcile: {ns}/_reconcile
    if inner.ends_with(segments::RECONCILE) && method == "POST" {
        if let Some(ns) = extract::ns_before_suffix(path, segments::RECONCILE) {
            return Endpoint::Reconcile { ns };
        }
    }

    // Bundle create/ingest: {ns}/_bundle/create, {ns}/_bundle/ingest
    if inner.ends_with(segments::BUNDLE_CREATE) && method == "POST" {
        if let Some(ns) = extract::ns_before_suffix(path, segments::BUNDLE_CREATE) {
            return Endpoint::BundleCreate { ns };
        }
    }
    if inner.ends_with(segments::BUNDLE_INGEST) && method == "POST" {
        if let Some(ns) = extract::ns_before_suffix(path, segments::BUNDLE_INGEST) {
            return Endpoint::BundleIngest { ns };
        }
    }

    // Edges: {ns}/edges/ or {ns}/edges/{node}
    if inner.contains(segments::EDGES) || inner.ends_with(segments::EDGES_BARE) {
        if let Some((ns, trailing)) = extract::split_at_allow_empty(path, segments::EDGES) {
            if trailing.is_empty() && method == "PUT" {
                return Endpoint::EdgePut { ns };
            }
            if !trailing.is_empty() {
                return match method {
                    "GET" => Endpoint::EdgeQuery { ns, node: trailing },
                    "DELETE" => Endpoint::EdgeDelete {
                        ns,
                        kappa: trailing,
                    },
                    _ => Endpoint::NotFound,
                };
            }
        }
        if inner.ends_with(segments::EDGES_BARE) {
            if let Some(ns) = extract::ns_before_suffix(path, segments::EDGES_BARE) {
                if method == "PUT" {
                    return Endpoint::EdgePut { ns };
                }
            }
        }
    }

    // Blobs: {ns}/blobs/{kappa} (must be last - widest match)
    if inner.contains(segments::BLOBS) {
        if let Some((ns, kappa)) = extract::split_at(path, segments::BLOBS) {
            if kappa.is_empty() {
                return Endpoint::BlobList { ns };
            }
            return match method {
                "HEAD" => Endpoint::BlobHead { ns, kappa },
                "GET" => Endpoint::BlobGet { ns, kappa },
                "PUT" => Endpoint::BlobPut { ns, kappa },
                "DELETE" => Endpoint::BlobDelete { ns, kappa },
                _ => Endpoint::NotFound,
            };
        }
    }

    Endpoint::NotFound
}

pub fn query_params(uri: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if let Some((_, query)) = uri.split_once('?') {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                let key = url_decode(k);
                let val = url_decode(v);
                params.insert(key, val);
            }
        }
    }
    params
}

fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().and_then(hex_val);
            let lo = chars.next().and_then(hex_val);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h << 4 | l) as char);
            } else {
                result.push('%');
            }
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version() {
        assert!(matches!(parse("GET", "/v2/"), Endpoint::Version));
        assert!(matches!(parse("GET", "/v2"), Endpoint::Version));
    }

    #[test]
    fn health() {
        assert!(matches!(parse("GET", "/v2/_health/live"), Endpoint::Health));
        assert!(matches!(
            parse("GET", "/v2/_health/ready"),
            Endpoint::Health
        ));
    }

    #[test]
    fn blob_crud() {
        assert!(matches!(
            parse("PUT", "/v2/ns/blobs/sha256:abc"),
            Endpoint::BlobPut {
                ns: "ns",
                kappa: "sha256:abc"
            }
        ));
        assert!(matches!(
            parse("GET", "/v2/org/sub/v1/blobs/sha256:def"),
            Endpoint::BlobGet {
                ns: "org/sub/v1",
                kappa: "sha256:def"
            }
        ));
        assert!(matches!(
            parse("HEAD", "/v2/ns/blobs/blake3:abc"),
            Endpoint::BlobHead {
                ns: "ns",
                kappa: "blake3:abc"
            }
        ));
        assert!(matches!(
            parse("DELETE", "/v2/ns/blobs/sha256:abc"),
            Endpoint::BlobDelete {
                ns: "ns",
                kappa: "sha256:abc"
            }
        ));
    }

    #[test]
    fn upload_lifecycle() {
        assert!(matches!(
            parse("POST", "/v2/ns/blobs/uploads/"),
            Endpoint::UploadStart { ns: "ns" }
        ));
        assert!(matches!(
            parse("PATCH", "/v2/_uploads/uuid-123"),
            Endpoint::UploadChunk { id: "uuid-123" }
        ));
        assert!(matches!(
            parse("GET", "/v2/_uploads/uuid-123"),
            Endpoint::UploadStatus { id: "uuid-123" }
        ));
        assert!(matches!(
            parse("PUT", "/v2/_uploads/uuid-123"),
            Endpoint::UploadComplete { id: "uuid-123" }
        ));
        assert!(matches!(
            parse("DELETE", "/v2/_uploads/uuid-123"),
            Endpoint::UploadCancel { id: "uuid-123" }
        ));
    }

    #[test]
    fn manifests() {
        assert!(matches!(
            parse("PUT", "/v2/ns/manifests/v1.0"),
            Endpoint::ManifestPut {
                ns: "ns",
                tag: "v1.0"
            }
        ));
        assert!(matches!(
            parse("GET", "/v2/ns/manifests/latest"),
            Endpoint::ManifestGet {
                ns: "ns",
                version: "latest"
            }
        ));
        assert!(matches!(
            parse("GET", "/v2/ns/manifests/sha256:abc"),
            Endpoint::ManifestGet {
                ns: "ns",
                version: "sha256:abc"
            }
        ));
        assert!(matches!(
            parse("DELETE", "/v2/ns/manifests/v1.0"),
            Endpoint::ManifestDelete {
                ns: "ns",
                tag: "v1.0"
            }
        ));
    }

    #[test]
    fn tags() {
        assert!(matches!(
            parse("GET", "/v2/ns/tags/list"),
            Endpoint::TagList { ns: "ns" }
        ));
        assert!(matches!(
            parse("GET", "/v2/ns/tags/v1.0"),
            Endpoint::TagGet {
                ns: "ns",
                name: "v1.0"
            }
        ));
        assert!(matches!(
            parse("PUT", "/v2/ns/tags/latest"),
            Endpoint::TagPut {
                ns: "ns",
                name: "latest"
            }
        ));
    }

    #[test]
    fn edges() {
        assert!(matches!(
            parse("PUT", "/v2/ns/edges/"),
            Endpoint::EdgePut { ns: "ns" }
        ));
        assert!(matches!(
            parse("GET", "/v2/ns/edges/sha256:abc"),
            Endpoint::EdgeQuery {
                ns: "ns",
                node: "sha256:abc"
            }
        ));
        assert!(matches!(
            parse("DELETE", "/v2/ns/edges/sha256:abc"),
            Endpoint::EdgeDelete {
                ns: "ns",
                kappa: "sha256:abc"
            }
        ));
    }

    #[test]
    fn compose_and_witness() {
        assert!(matches!(
            parse("POST", "/v2/ns/compose/g2"),
            Endpoint::Compose { ns: "ns", op: "g2" }
        ));
        assert!(matches!(
            parse("GET", "/v2/ns/witnesses/sha256:abc"),
            Endpoint::Witness {
                ns: "ns",
                kappa: "sha256:abc"
            }
        ));
    }

    #[test]
    fn schemas() {
        assert!(matches!(
            parse("PUT", "/v2/ns/schemas/test-scope"),
            Endpoint::SchemaPut {
                ns: "ns",
                scope: "test-scope"
            }
        ));
        assert!(matches!(
            parse("GET", "/v2/ns/schemas/test-scope"),
            Endpoint::SchemaGet {
                ns: "ns",
                scope: "test-scope"
            }
        ));
        assert!(matches!(
            parse("GET", "/v2/ns/schemas/"),
            Endpoint::SchemaList { ns: "ns" }
        ));
    }

    #[test]
    fn gc() {
        assert!(matches!(
            parse("POST", "/v2/ns/gc/pin"),
            Endpoint::GcPin { ns: "ns" }
        ));
        assert!(matches!(
            parse("POST", "/v2/ns/gc/unpin"),
            Endpoint::GcUnpin { ns: "ns" }
        ));
        assert!(matches!(
            parse("POST", "/v2/ns/gc/sweep"),
            Endpoint::GcSweep { ns: "ns" }
        ));
        assert!(matches!(
            parse("GET", "/v2/ns/gc/status"),
            Endpoint::GcStatus { ns: "ns" }
        ));
    }

    #[test]
    fn filters() {
        assert!(matches!(
            parse("PUT", "/v2/ns/filters/scope1"),
            Endpoint::FilterPut {
                ns: "ns",
                scope: "scope1"
            }
        ));
        assert!(matches!(
            parse("GET", "/v2/ns/filters/"),
            Endpoint::FilterList { ns: "ns" }
        ));
        assert!(matches!(
            parse("DELETE", "/v2/ns/filters/sha256:abc"),
            Endpoint::FilterDelete {
                ns: "ns",
                kappa: "sha256:abc"
            }
        ));
    }

    #[test]
    fn deep_namespace() {
        assert!(matches!(
            parse("GET", "/v2/atlas.cern.ch/calibration/v1/blobs/sha256:abc"),
            Endpoint::BlobGet {
                ns: "atlas.cern.ch/calibration/v1",
                kappa: "sha256:abc"
            }
        ));
    }

    #[test]
    fn unknown() {
        assert!(matches!(parse("GET", "/other"), Endpoint::NotFound));
        assert!(matches!(
            parse("GET", "/v2/_health/bogus"),
            Endpoint::NotFound
        ));
    }

    #[test]
    fn query_params_with_digest() {
        let params = query_params("/v2/_uploads/abc?digest=sha256:0123456789abcdef");
        assert_eq!(
            params.get("digest").map(|s| s.as_str()),
            Some("sha256:0123456789abcdef")
        );
    }

    #[test]
    fn query_params_url_encoded_digest() {
        let params =
            query_params("/v2/_uploads/abc?digest=sha256%3A0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        assert_eq!(
            params.get("digest").map(|s| s.as_str()),
            Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn query_params_multiple() {
        let params = query_params("/v2/ns/tags/list?n=5&last=v1.0");
        assert_eq!(params.get("n").map(|s| s.as_str()), Some("5"));
        assert_eq!(params.get("last").map(|s| s.as_str()), Some("v1.0"));
    }

    #[test]
    fn query_params_empty() {
        let params = query_params("/v2/ns/blobs/sha256:abc");
        assert!(params.is_empty());
    }

    #[test]
    fn manifest_head_routing() {
        assert!(matches!(
            parse("HEAD", "/v2/ns/manifests/latest"),
            Endpoint::ManifestHead {
                ns: "ns",
                version: "latest"
            }
        ));
        assert!(matches!(
            parse("HEAD", "/v2/ns/manifests/sha256:abc"),
            Endpoint::ManifestHead {
                ns: "ns",
                version: "sha256:abc"
            }
        ));
    }

    #[test]
    fn referrers_routing() {
        assert!(matches!(
            parse("GET", "/v2/ns/referrers/sha256:abc"),
            Endpoint::Referrers {
                ns: "ns",
                digest: "sha256:abc"
            }
        ));
    }

    #[test]
    fn meta_list_routing() {
        assert!(matches!(
            parse("GET", "/v2/ns/blobs/_meta"),
            Endpoint::MetaList { ns: "ns" }
        ));
        assert!(matches!(
            parse("GET", "/v2/org/sub/blobs/_meta"),
            Endpoint::MetaList { ns: "org/sub" }
        ));
    }

    #[test]
    fn upload_complete_with_digest_param() {
        // The upload URL is /v2/_uploads/{id}, PUT dispatches to UploadComplete
        assert!(matches!(
            parse("PUT", "/v2/_uploads/uuid-123"),
            Endpoint::UploadComplete { id: "uuid-123" }
        ));
    }
}
