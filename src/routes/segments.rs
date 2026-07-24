pub const PREFIX: &str = "/v2/";
pub const PREFIX_BARE: &str = "/v2";
pub const BLOBS: &str = "/blobs/";
pub const BLOBS_META: &str = "/blobs/_meta";
pub const BLOBS_UPLOADS: &str = "/blobs/uploads/";
pub const BLOBS_UPLOADS_BARE: &str = "/blobs/uploads";
pub const MANIFESTS: &str = "/manifests/";
pub const TAGS: &str = "/tags/";
pub const TAGS_LIST: &str = "/tags/list";
pub const TAGS_BATCH: &str = "/tags/_batch";
pub const EDGES: &str = "/edges/";
pub const EDGES_BARE: &str = "/edges";
pub const COMPOSE: &str = "/compose/";
pub const WITNESSES: &str = "/witnesses/";
pub const SCHEMAS: &str = "/schemas/";
pub const SCHEMAS_BARE: &str = "/schemas";
pub const GC_PIN: &str = "/gc/pin";
pub const GC_UNPIN: &str = "/gc/unpin";
pub const GC_SWEEP: &str = "/gc/sweep";
pub const GC_STATUS: &str = "/gc/status";
pub const REFERRERS: &str = "/referrers/";
pub const FILTERS: &str = "/filters/";
pub const FILTERS_BARE: &str = "/filters";
pub const EDGE_DIFF: &str = "/edges/_diff";
pub const RECONCILE: &str = "/_reconcile";
pub const NAMESPACE_ROOT: &str = "/_root";
pub const NAMESPACE_PROOF: &str = "/_root/proof/";
pub const BUNDLE_CREATE: &str = "/_bundle/create";
pub const BUNDLE_INGEST: &str = "/_bundle/ingest";
pub const TRANSACTION: &str = "/_transaction/";
pub const TRANSACTION_BEGIN: &str = "/_transaction/begin";
pub const TRANSACTION_COMMIT_SUFFIX: &str = "/commit";
pub const UPLOADS: &str = "/v2/_uploads/";
pub const HEALTH: &str = "/v2/_health/";

pub fn blob_url(ns: &str, kappa: &str) -> String {
    format!("/v2/{ns}/blobs/{kappa}")
}

pub fn manifest_url(ns: &str, reference: &str) -> String {
    format!("/v2/{ns}/manifests/{reference}")
}

pub fn upload_url(id: &str) -> String {
    format!("/v2/_uploads/{id}")
}

pub fn tag_list_link(ns: &str, last: &str) -> String {
    format!("</v2/{ns}/tags/list?last={last}>; rel=\"next\"")
}
