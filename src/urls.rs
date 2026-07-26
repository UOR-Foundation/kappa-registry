//! URL construction helpers used by handlers and tests.
//! No routing logic -- all routing is handled by topcoat's matchit router.

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
