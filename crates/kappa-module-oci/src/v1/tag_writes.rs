//! Tag writes. Each request runs as one execution: its tag changes publish
//! together in one epoch or not at all. A repository first written by a
//! tag request is created inside that same execution.

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{
    HandlerError, OperationResult, Outcome, empty_response, execute, json_response, path_param,
    query_optional, query_required, read_body, read_json_with_bytes, store, write_target,
};
use kappa_store::kappa::Kappa;
use kappa_store::tag::TagUpdate;
use kappa_store::traits::KappaStore;

use crate::header;
use crate::tags::list_all_tags;

const MAX_TAG_BODY: usize = 1024 * 1024;

/// Content-before-tag: a tag may only name content its namespace admitted.
/// Read inside the execution, which holds the namespace's writer, so the
/// check and the tag publish against the same state.
fn require_content(
    store: &dyn KappaStore,
    ns: &kappa_store::NamespaceRef,
    kappa: &Kappa,
) -> Result<(), HandlerError> {
    if store.blob_exists_in(ns, kappa)? {
        Ok(())
    } else {
        Err(HandlerError::protocol(
            StatusCode::NOT_FOUND,
            "TAG_CONTENT_ABSENT",
            format!("content {kappa} does not exist"),
        ))
    }
}

fn non_empty<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value[field].as_str().filter(|text| !text.is_empty())
}

/// Atomic tag batch. Every member's precondition is checked against the
/// state before the batch; one rejected member fails the request and
/// nothing publishes.
pub async fn batch(cx: &Cx, body: Body) -> Result<Response, HandlerError> {
    let (req, bytes): (serde_json::Value, _) = read_json_with_bytes(body, MAX_TAG_BODY).await?;
    let target = write_target(cx)?;

    let raw_updates = req["updates"]
        .as_array()
        .ok_or_else(|| HandlerError::bad_request("missing updates array"))?;
    let updates = raw_updates
        .iter()
        .map(parse_batch_entry)
        .collect::<Result<Vec<_>, _>>()?;

    let committed = execute(cx, target, &bytes, move |execution| {
        if updates.is_empty() {
            return Ok(Outcome::Discard(()));
        }
        execution.tag_batch_update(&updates)?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let mut resp = empty_response(StatusCode::OK);
    committed.annotate(&mut resp);
    Ok(resp)
}

fn parse_batch_entry(entry: &serde_json::Value) -> Result<(String, TagUpdate), HandlerError> {
    let name =
        non_empty(entry, "name").ok_or_else(|| HandlerError::bad_request("update missing name"))?;
    let kappa_str = non_empty(entry, "kappa")
        .ok_or_else(|| HandlerError::bad_request("update missing kappa"))?;
    let kappa = Kappa::parse(kappa_str)?;
    let update = match entry["expected_version"].as_u64() {
        Some(0) => TagUpdate::CreateIfAbsent { kappa },
        Some(expected_version) => TagUpdate::CompareAndSwap {
            kappa,
            expected_version,
        },
        None => TagUpdate::Set { kappa },
    };
    Ok((name.to_string(), update))
}

/// Delete every tag under a prefix in one epoch. A prefix matching no tag
/// publishes nothing.
pub async fn delete_prefix(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let target = write_target(cx)?;
    let prefix = query_required(cx, "prefix")?;
    let s = store(cx);

    let committed = execute(cx, target, &[], move |execution| {
        // Listed through the store while the execution holds its writer, so
        // no tag under the prefix can publish between listing and deletion.
        let names: Vec<String> = list_all_tags(&*s, execution.namespace(), Some(&prefix))?
            .into_iter()
            .map(|tag| tag.name)
            .collect();
        for name in &names {
            execution.tag_delete(name)?;
        }
        Ok(if names.is_empty() {
            Outcome::Discard(names)
        } else {
            Outcome::Publish(names)
        })
    })
    .await?;

    let mut resp = json_response(
        StatusCode::OK,
        &serde_json::json!({"deleted": committed.value.len()}),
    )?;
    committed.annotate(&mut resp);
    Ok(resp)
}

/// `POST /tags/` with `{"name", "kappa"}`.
pub async fn tag_create(cx: &Cx, body: Body) -> Result<Response, HandlerError> {
    let target = write_target(cx)?;
    let bytes = read_body(body, MAX_TAG_BODY).await?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| HandlerError::bad_request(format!("invalid JSON: {e}")))?;
    let name = non_empty(&v, "name")
        .ok_or_else(|| HandlerError::bad_request("missing or empty name"))?
        .to_string();
    let kappa_str = non_empty(&v, "kappa")
        .ok_or_else(|| HandlerError::bad_request("missing or empty kappa"))?;
    let kappa = Kappa::parse(kappa_str)?;
    let s = store(cx);

    let committed = execute(cx, target, &bytes, move |execution| {
        require_content(&*s, execution.namespace(), &kappa)?;
        execution.tag_put(
            &name,
            &TagUpdate::Set {
                kappa: kappa.clone(),
            },
        )?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let mut resp = empty_response(StatusCode::CREATED);
    committed.annotate(&mut resp);
    Ok(resp)
}

/// `DELETE /tags/?name=`. An absent tag is 404 and publishes nothing.
pub async fn tag_delete_by_query(cx: &Cx) -> Result<Response, HandlerError> {
    let target = write_target(cx)?;
    let name = query_required(cx, "name")?;

    let committed = execute(cx, target, &[], move |execution| {
        // Checked before deleting: a failed delete would latch the execution.
        if execution.tag_get_raw(&name)?.is_none() {
            return Err(HandlerError::not_found(format!(
                "{}/{name}",
                execution.namespace()
            )));
        }
        execution.tag_delete(&name)?;
        Ok(Outcome::Publish(()))
    })
    .await?;

    let mut resp = empty_response(StatusCode::ACCEPTED);
    committed.annotate(&mut resp);
    Ok(resp)
}

/// Whether an unconditional tag set replaced an existing tag; decides 200
/// against 201 and is replayed with the operation.
struct Replaced(bool);

impl OperationResult for Replaced {
    fn encode(&self) -> Vec<u8> {
        vec![u8::from(self.0)]
    }

    fn decode(bytes: &[u8]) -> Result<Self, HandlerError> {
        match bytes {
            [0] => Ok(Self(false)),
            [1] => Ok(Self(true)),
            _ => Err(HandlerError::internal(
                "operation receipt result: tag replacement flag is not one byte 0 or 1",
            )),
        }
    }
}

/// The write requested by `PUT /tags/{name}`.
enum TagWrite {
    Symref(String),
    CompareAndSwap { kappa: Kappa, expected_version: u64 },
    CreateIfAbsent(Kappa),
    Set(Kappa),
}

fn requested_write(cx: &Cx) -> Result<TagWrite, HandlerError> {
    if let Some(target) = query_optional(cx, "symref") {
        return Ok(TagWrite::Symref(target));
    }
    let kappa = Kappa::parse(&query_required(cx, "kappa")?)?;
    let headers = topcoat::router::request::headers(cx);
    if let Some(expected) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
        let expected_version = expected
            .parse()
            .map_err(|_| HandlerError::bad_request("If-Match must be a version number"))?;
        return Ok(TagWrite::CompareAndSwap {
            kappa,
            expected_version,
        });
    }
    if headers.get("if-none-match").and_then(|v| v.to_str().ok()) == Some("*") {
        return Ok(TagWrite::CreateIfAbsent(kappa));
    }
    Ok(TagWrite::Set(kappa))
}

/// `PUT /tags/{name}`: one tag write, published in one epoch.
///
/// Symbolic reference (`?symref=`), compare-and-swap (`If-Match:
/// <version>`, 200), create-if-absent (`If-None-Match: *`, 201), or
/// unconditional set (200 replacing, 201 creating). A failed precondition
/// fails the request and publishes nothing.
pub async fn put_by_name(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    let target = write_target(cx)?;
    let name = path_param(cx, "name")?;
    let write = requested_write(cx)?;
    let s = store(cx);

    let (label, fixed_status) = match &write {
        TagWrite::Symref(target) => (format!("ref:{target}"), Some(StatusCode::CREATED)),
        TagWrite::CompareAndSwap { kappa, .. } => (kappa.to_string(), Some(StatusCode::OK)),
        TagWrite::CreateIfAbsent(kappa) => (kappa.to_string(), Some(StatusCode::CREATED)),
        TagWrite::Set(kappa) => (kappa.to_string(), None),
    };

    let committed = execute(cx, target, &[], move |execution| {
        let (update, replaced) = match &write {
            TagWrite::Symref(target) => (
                TagUpdate::SetSymref {
                    target: target.clone(),
                },
                false,
            ),
            TagWrite::CompareAndSwap {
                kappa,
                expected_version,
            } => {
                require_content(&*s, execution.namespace(), kappa)?;
                let replaced = execution.tag_get_raw(&name)?.is_some();
                let update = TagUpdate::CompareAndSwap {
                    kappa: kappa.clone(),
                    expected_version: *expected_version,
                };
                (update, replaced)
            }
            TagWrite::CreateIfAbsent(kappa) => {
                require_content(&*s, execution.namespace(), kappa)?;
                (
                    TagUpdate::CreateIfAbsent {
                        kappa: kappa.clone(),
                    },
                    false,
                )
            }
            TagWrite::Set(kappa) => {
                require_content(&*s, execution.namespace(), kappa)?;
                let replaced = execution.tag_get(&name)?.is_some();
                (
                    TagUpdate::Set {
                        kappa: kappa.clone(),
                    },
                    replaced,
                )
            }
        };
        execution.tag_put(&name, &update)?;
        Ok(Outcome::Publish(Replaced(replaced)))
    })
    .await?;

    let status = fixed_status.unwrap_or(if committed.value.0 {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    });
    let mut resp = empty_response(status);
    resp.headers_mut().insert("x-kappa-label", header(&label)?);
    committed.annotate(&mut resp);
    Ok(resp)
}
