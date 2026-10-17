use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use crate::protocol_id;
use kappa_handler::{HandlerError, blocking, page_request_from, store};
use kappa_store::NamespaceFilter;
use kappa_store::error::StoreError;

const MAX_LIST_LIMIT: usize = 100;

/// GET /xrpc/com.atproto.sync.listRepos
///
/// Returns paginated list of AT Protocol repositories with their
/// current commit head (CID) and rev (TID). The relay compares
/// these against its local state and syncs only changed repos.
pub async fn list_repos(
    cx: &Cx,
    _body: Body, // GET — body not expected
) -> Result<topcoat::router::response::Response, HandlerError> {
    let page_req = page_request_from(cx, MAX_LIST_LIMIT)?;
    let s = store(cx);

    let filter = NamespaceFilter {
        protocol: Some(protocol_id().clone()),
        ..NamespaceFilter::default()
    };

    let result = blocking(move || -> Result<_, HandlerError> {
        let page = s.namespace_list(&filter, &page_req)?;
        let mut repos = Vec::with_capacity(page.items.len());
        for ns_info in &page.items {
            // Read actual commit head and rev from tags.
            let (head, rev) = match s.tag_get(&ns_info.ns, "commit/head") {
                Ok(head_entry) => {
                    let head_cid = head_entry.kappa.to_string();
                    let rev = match s.tag_get(&ns_info.ns, "commit/rev") {
                        Ok(rev_entry) => rev_entry.kappa.to_string(),
                        Err(StoreError::NotFound(_)) => String::new(),
                        Err(e) => return Err(e.into()),
                    };
                    (head_cid, rev)
                }
                Err(StoreError::NotFound(_)) => {
                    // No commits — skip this repo. A repo with no
                    // commits has no content for the relay to sync.
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            repos.push(serde_json::json!({
                "did": ns_info.name,
                "head": head,
                "rev": rev,
                "active": true,
            }));
        }
        Ok((repos, page.next_after))
    })
    .await?;

    let (repos, next_cursor) = result;
    let mut body = serde_json::json!({ "repos": repos });
    if let Some(c) = next_cursor {
        body["cursor"] = serde_json::Value::String(c);
    }
    kappa_handler::json_response(StatusCode::OK, &body)
}
