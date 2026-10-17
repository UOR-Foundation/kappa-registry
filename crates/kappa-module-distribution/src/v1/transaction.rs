//! Staging transactions over staged resources: begin, put, commit, abort.
//!
//! A transaction is a membership resource in its namespace
//! (`kappa_store::resource`). Every put prepares the content outside the
//! writer and stages it as a member in one epoch, so an acknowledged put
//! is epoch-committed and a retry of the same identity converges. Commit
//! pins every member in the namespace and discards the resource in one
//! epoch, so the content stays retained under the namespace's own
//! authority; abort discards the resource and the members become
//! collectable.

use topcoat::context::Cx;
use topcoat::router::{Body, Method, RouterBuilder, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, blocking, clock_now, empty_response, execute, json_response, path_param,
    prepare_body, principal, read_body, store, write_target,
};
use kappa_store::kappa::Kappa;
use kappa_store::resource;
use kappa_store::{ClockMs, ContentIdentity, Execution, NamespaceRef, ResourceKind, StoreError};

/// Transactions not committed within this window expire.
const TRANSACTION_TTL_MS: u64 = 60 * 60 * 1000;
const MAX_STAGED_BODY: usize = 256 * 1024 * 1024;

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(dist_route!(
            Method::POST,
            "/v2/{*ns}/_transaction/begin",
            txn_begin
        ))
        .route(dist_route!(
            Method::PUT,
            "/v2/{*ns}/_transaction/{id}/{kappa}",
            txn_put
        ))
        .route(dist_route!(
            Method::POST,
            "/v2/{*ns}/_transaction/{id}/commit",
            txn_commit
        ))
        .route(dist_route!(
            Method::DELETE,
            "/v2/{*ns}/_transaction/{id}",
            txn_abort
        ))
}

fn transaction_unknown(id: &str) -> HandlerError {
    HandlerError::NotFound {
        reason: format!("transaction {id} not found"),
    }
}

/// Resolve the transaction in `ns`. A transaction is addressed only
/// through the namespace it began under: its head is a tag there.
async fn resolve_transaction(
    cx: &Cx,
    ns: &NamespaceRef,
    id: &str,
) -> Result<resource::Resource, HandlerError> {
    let s = store(cx);
    let ns = ns.clone();
    let id_owned = id.to_string();
    blocking(move || resource::resolve(&*s, &ns, &id_owned))
        .await?
        .ok_or_else(|| transaction_unknown(id))
}

async fn txn_begin(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = write_target(cx)?;
    let now = clock_now(cx)?;
    let asserter = principal(cx);
    let max_bytes = kappa_handler::try_service::<kappa_handler::MaxBlobSize>(cx)
        .map_or(MAX_STAGED_BODY as u64, |m| m.0 as u64);
    let expires_at = now.add_physical_ms(TRANSACTION_TTL_MS);
    // Reserved while the open publishes. The work holds the reservation,
    // so it is returned on the worker after `execute` projected the
    // published head, never by a dropped request.
    let admission = kappa_handler::staging_budget(cx)?.admit_open()?;
    let committed = execute(
        cx,
        target,
        &[],
        admission.held_by(move |execution| {
            let head = resource::open(
                execution,
                &asserter,
                ResourceKind::Membership,
                max_bytes,
                expires_at,
                None,
            )?;
            Ok(Outcome::Publish(head.id()))
        }),
    )
    .await?;
    let mut response = json_response(
        StatusCode::CREATED,
        &serde_json::json!({"transaction_id": committed.value}),
    )?;
    committed.annotate(&mut response);
    Ok(response)
}

async fn txn_put(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let bytes = read_body(body, MAX_STAGED_BODY).await?;
    let target = write_target(cx)?;
    let id = path_param(cx, "id")?;
    let kappa_str = path_param(cx, "kappa")?;
    let kappa = Kappa::parse(&kappa_str)?;
    let ns = target.namespace().clone();
    let resource = resolve_transaction(cx, &ns, &id).await?;
    // Membership is keyed by identity: the committed member reference is
    // one metadata lookup, never an enumeration.
    let already = blocking({
        let s = store(cx);
        let ns = ns.clone();
        let key = kappa_store::ResourceHead::member_key(&resource.head.id(), &kappa_str);
        move || Ok::<_, StoreError>(kappa_store::absent(s.namespace_get_meta(&ns, &key))?.is_some())
    })
    .await?;
    let created = if already {
        false
    } else {
        // Reserved from preparation until the stage publishes. The work
        // holds the reservation, so it is returned on the worker after
        // `execute` projected the staged total, never by a dropped request.
        let admission = kappa_handler::staging_budget(cx)?.admit_bytes(bytes.len() as u64)?;
        let prepared =
            prepare_body(cx, ContentIdentity::Verified(kappa.clone()), bytes.to_vec()).await?;
        let asserter = principal(cx);
        let resource_id = resource.head.id();
        let committed = execute(
            cx,
            target,
            &kappa_str.clone().into_bytes(),
            admission.held_by(move |execution| {
                let (_, installed) = resource::stage(
                    execution,
                    &asserter,
                    &resource_id,
                    kappa_handler::take_prepared(&prepared)?,
                    0,
                    None,
                )?;
                Ok(Outcome::Publish(installed.kappa.to_string()))
            }),
        )
        .await?;
        committed.value == kappa_str
    };

    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let mut resp = empty_response(status);
    resp.headers_mut().insert(
        "x-kappa-label",
        kappa_str.parse().map_err(|error| {
            HandlerError::internal(format!("invalid kappa response header: {error}"))
        })?,
    );
    Ok(resp)
}

async fn txn_commit(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = write_target(cx)?;
    let id = path_param(cx, "id")?;
    let ns = target.namespace().clone();
    let resource = resolve_transaction(cx, &ns, &id).await?;
    let now = clock_now(cx)?;
    let members: Vec<Kappa> = blocking({
        let s = store(cx);
        let ns = ns.clone();
        let head = resource.head.clone();
        move || {
            Ok::<_, StoreError>(
                resource::members(&*s, &ns, &head)?
                    .into_iter()
                    .map(|member| member.identity)
                    .collect(),
            )
        }
    })
    .await?;
    let committed = execute(
        cx,
        target,
        id.as_bytes(),
        commit_transaction(principal(cx), resource.head.id(), members, now),
    )
    .await?;
    let mut response = json_response(
        StatusCode::OK,
        &serde_json::json!({"promoted": committed.value}),
    )?;
    committed.annotate(&mut response);
    Ok(response)
}

/// Execution work committing transaction `resource_id` whose committed
/// members are `members`: every member is pinned in the namespace and the
/// resource is discarded, in one epoch. The pins and the discard are state
/// changes, so a commit always publishes, including the commit of an empty
/// transaction, which ends it. A resource already gone is `NotFound`.
pub fn commit_transaction(
    asserter: Kappa,
    resource_id: String,
    members: Vec<Kappa>,
    now: ClockMs,
) -> impl FnMut(&mut dyn Execution) -> Result<Outcome<Vec<String>>, HandlerError> + Send + 'static {
    move |execution| {
        let mut promoted = Vec::with_capacity(members.len());
        for identity in &members {
            // Committed content stays retained under the namespace's own
            // authority: a pin without expiry, removed only by an explicit
            // epoch-committed unpin.
            execution.namespace_put_meta(
                &format!("_pin/{identity}"),
                serde_json::json!({"created_at_ms": now.as_i64(), "ttl": 0})
                    .to_string()
                    .as_bytes(),
            )?;
            promoted.push(identity.to_string());
        }
        if !resource::discard(execution, &asserter, &resource_id)? {
            return Err(transaction_unknown(&resource_id));
        }
        Ok(Outcome::Publish(promoted))
    }
}

async fn txn_abort(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = write_target(cx)?;
    let id = path_param(cx, "id")?;
    let ns = target.namespace().clone();
    let resource = resolve_transaction(cx, &ns, &id).await?;
    let asserter = principal(cx);
    let resource_id = resource.head.id();
    execute(cx, target, &[], move |execution| {
        Ok(if resource::discard(execution, &asserter, &resource_id)? {
            Outcome::Publish(())
        } else {
            Outcome::Discard(())
        })
    })
    .await?;
    Ok(empty_response(StatusCode::NO_CONTENT))
}
