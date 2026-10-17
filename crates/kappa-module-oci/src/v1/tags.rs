//! Tag reads: content discovery (`tags/list`) and single-tag lookups.
//! Tag writes publish through executions in `tag_writes`.

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    HandlerError, blocking, json_response, path_param, query_optional, query_optional_parsed,
    query_required, resolve_ns_read, store,
};
use kappa_store::NamespaceRef;
use kappa_store::tag::TagEntry;
use kappa_store::traits::KappaStore;

use crate::header;

pub use crate::tag_writes::{batch, delete_prefix, put_by_name};

/// Every published tag of `ns` under `prefix`. Internal `_` tags appear only
/// when the prefix itself names them.
///
/// # Errors
///
/// Store failures, and a store cursor that does not advance.
pub(crate) fn list_all_tags(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    prefix: Option<&str>,
) -> Result<Vec<TagEntry>, kappa_store::StoreError> {
    let mut tags = Vec::new();
    let mut request = kappa_store::PageRequest::first(1024);
    loop {
        let page = store.tag_list(ns, prefix, &request)?;
        tags.extend(page.items);
        let Some(after) = page.next_after else { break };
        if request
            .after
            .as_ref()
            .is_some_and(|previous| after <= *previous)
        {
            return Err(kappa_store::StoreError::Internal(
                "tag cursor did not advance".into(),
            ));
        }
        request.after = Some(after);
    }
    Ok(tags)
}

pub async fn tag_list(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let s = store(cx);

    let n_param: Option<usize> = query_optional_parsed(cx, "n")?;
    let last_param = query_optional(cx, "last");
    let order_param = query_optional(cx, "order");
    let after_param = query_optional(cx, "after");
    let before_param = query_optional(cx, "before");

    if n_param == Some(0) {
        return json_response(
            StatusCode::OK,
            &serde_json::json!({"name": ns.display_name(), "tags": []}),
        );
    }

    let n = ns.clone();
    let all_tags = blocking(move || list_all_tags(&*s, &n, None)).await?;

    let mut tag_names: Vec<&str> = all_tags
        .iter()
        .filter(|t| !t.name.starts_with('_'))
        .map(|t| t.name.as_str())
        .collect();

    if let Some(ref after) = after_param {
        tag_names.retain(|t| *t > after.as_str());
    }
    if let Some(ref before) = before_param {
        tag_names.retain(|t| *t < before.as_str());
    }

    if order_param.as_deref() == Some("desc") {
        tag_names.sort_by(|a, b| b.cmp(a));
    } else {
        tag_names.sort_unstable();
    }

    if let Some(ref last) = last_param
        && let Some(pos) = tag_names.iter().position(|t| *t == last.as_str())
    {
        tag_names = tag_names[pos + 1..].to_vec();
    }

    let has_more = match n_param {
        Some(limit) if tag_names.len() > limit => {
            tag_names.truncate(limit);
            true
        }
        _ => false,
    };

    let mut resp = json_response(
        StatusCode::OK,
        &serde_json::json!({"name": ns.display_name(), "tags": tag_names}),
    )?;
    if has_more && let Some(last_tag) = tag_names.last() {
        let link = format!(
            "</v2/{}/tags/list?last={}>; rel=\"next\"",
            ns.display_name(),
            last_tag
        );
        resp.headers_mut().insert("link", header(&link)?);
    }
    Ok(resp)
}

/// `/tags/` with the tag named by the `name` query parameter (GET, DELETE)
/// or the JSON body (POST).
pub async fn crud(cx: &Cx, body: Body) -> Result<Response, HandlerError> {
    let method = topcoat::router::request::method(cx).to_string();
    match method.as_str() {
        "POST" => crate::tag_writes::tag_create(cx, body).await,
        "GET" => {
            let ns = resolve_ns_read(cx)?;
            let name = query_required(cx, "name")?;
            tag_get(cx, ns, name).await
        }
        "DELETE" => crate::tag_writes::tag_delete_by_query(cx).await,
        _ => Err(HandlerError::BadRequest {
            reason: "method not allowed".into(),
        }),
    }
}

async fn tag_get(cx: &Cx, ns: NamespaceRef, name: String) -> Result<Response, HandlerError> {
    let s = store(cx);
    let lookup = name.clone();
    let entry = blocking(move || s.tag_get(&ns, &lookup)).await?;

    let kappa_str = entry.kappa.to_string();
    let mut resp = json_response(
        StatusCode::OK,
        &serde_json::json!({"name": name, "kappa": kappa_str}),
    )?;
    resp.headers_mut()
        .insert("x-kappa-label", header(&kappa_str)?);
    Ok(resp)
}

pub async fn get_by_name(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let name = path_param(cx, "name")?;
    let raw = query_optional(cx, "raw").as_deref() == Some("true");

    let s = store(cx);
    let nm = name.clone();
    let entry = blocking(move || {
        if raw {
            s.tag_get_raw(&ns, &nm)
        } else {
            s.tag_get(&ns, &nm)
        }
    })
    .await?;

    let kappa_str = entry.kappa.to_string();
    let body = if raw {
        serde_json::json!({"name": name, "value": kappa_str})
    } else {
        serde_json::json!({"name": name, "kappa": kappa_str})
    };
    let mut resp = json_response(StatusCode::OK, &body)?;
    resp.headers_mut()
        .insert("x-kappa-label", header(&kappa_str)?);
    Ok(resp)
}
