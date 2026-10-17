use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, Method, RouterBuilder, StatusCode};

use kappa_handler::{
    HandlerError, Outcome, blocking, caller_anchor, empty_response, execute, json_response,
    path_param, principal, query_optional, read_json, read_json_with_bytes, resolve_ns_read, store,
    write_target,
};
use kappa_store::canonical::from_canonical;
use kappa_store::edge::{
    BuiltinRelation, Direction, EdgeInput, EdgeQuery, EdgeRelation, SemanticRelation, semantic,
};
use kappa_store::kappa::Kappa;
use kappa_store::{Execution, KappaStore, NamespaceRef, PageRequest, StoreError};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(dist_route!(Method::PUT, "/v2/{*ns}/edges/", put))
        .route(dist_route!(
            Method::GET,
            "/v2/{*ns}/edges/{edge_key}",
            query
        ))
        .route(dist_route!(
            Method::DELETE,
            "/v2/{*ns}/edges/{edge_key}",
            delete
        ))
        .route(dist_route!(Method::POST, "/v2/{*ns}/edges/_diff", diff))
}

fn required_str<'a>(req: &'a serde_json::Value, field: &str) -> Result<&'a str, HandlerError> {
    req.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::BadRequest {
            reason: format!("missing {field}"),
        })
}

/// Target of a capability edge: the namespace's identity. The request names
/// the namespace by its display name or by that identity; any other target
/// would grant authority over a different namespace than the one holding
/// the edge.
fn capability_target(ns: &NamespaceRef, requested: &str) -> Result<Kappa, HandlerError> {
    let identity = kappa_handler::authority::namespace_identity(ns);
    if requested == ns.display_name() || requested == identity.to_string() {
        Ok(identity)
    } else {
        Err(HandlerError::bad_request(format!(
            "capability target must name namespace '{}'",
            ns.display_name()
        )))
    }
}

/// Delegator key carried by a delegation request: `algorithm` and hex
/// `public_key` fields.
fn delegator_key(req: &serde_json::Value) -> Result<crate::delegation::DelegatorKey, HandlerError> {
    let algorithm = required_str(req, "algorithm")?.to_string();
    let public_key = hex::decode(required_str(req, "public_key")?)
        .map_err(|error| HandlerError::bad_request(format!("public_key is not hex: {error}")))?;
    Ok(crate::delegation::DelegatorKey {
        algorithm,
        public_key,
    })
}

/// Unix milliseconds of an execution's timestamp, the unit grant validity
/// windows use.
fn physical_ms(execution: &dyn Execution) -> Result<i64, HandlerError> {
    i64::try_from(execution.now().physical_ms())
        .map_err(|_| HandlerError::internal("execution time exceeds Unix millisecond range"))
}

async fn put(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let (req, raw): (serde_json::Value, _) = read_json_with_bytes(body, 1024 * 1024).await?;
    let target = write_target(cx)?;

    let source_str = required_str(&req, "source")?;
    let target_str = required_str(&req, "target")?;
    let relation_str = required_str(&req, "relation")?;

    let relation = parse_relation(relation_str).ok_or_else(|| HandlerError::BadRequest {
        reason: format!("unknown relation: {relation_str}"),
    })?;
    let source = Kappa::parse(source_str)?;
    let grant = match relation {
        EdgeRelation::Builtin(BuiltinRelation::Capability) => Some(BuiltinRelation::Capability),
        EdgeRelation::Builtin(BuiltinRelation::Delegation) => Some(BuiltinRelation::Delegation),
        _ => None,
    };
    let edge_target = match grant {
        Some(BuiltinRelation::Capability) => capability_target(target.namespace(), target_str)?,
        _ => Kappa::parse(target_str)?,
    };
    let delegator = match grant {
        Some(BuiltinRelation::Delegation) => Some(delegator_key(&req)?),
        _ => None,
    };

    let s = store(cx);

    if grant.is_none() && relation != EdgeRelation::Builtin(BuiltinRelation::Assertion) {
        let src = source.clone();
        let ns = target.namespace().clone();
        let blob_exists = blocking({
            let s = s.clone();
            move || s.blob_exists_in(&ns, &src)
        })
        .await?;
        if !blob_exists {
            return Err(HandlerError::BadRequest {
                reason: "source kappa does not exist".into(),
            });
        }
    }

    // Grants confer authority, so they name an authenticated grantor; other
    // edges are attributed to the caller or the anonymous principal.
    let asserter = match grant {
        Some(_) => caller_anchor(cx).ok_or_else(|| HandlerError::Unauthorized {
            reason: "granting authority requires authentication".into(),
        })?,
        None => principal(cx),
    };

    let metadata = match req.get("metadata") {
        Some(m) => Some(serde_json::to_vec(m).map_err(|e| HandlerError::Internal {
            reason: format!("metadata serialization: {e}"),
        })?),
        None => None,
    };

    let creates = target.creates();
    let committed = execute(cx, target, &raw, move |execution| {
        let now_ms = physical_ms(execution)?;
        match (grant, &delegator) {
            (Some(BuiltinRelation::Delegation), Some(key)) => {
                crate::delegation::admit_delegation(
                    &*s,
                    execution.namespace(),
                    &asserter,
                    &crate::delegation::DelegationRequest {
                        delegator: &source,
                        delegate: &edge_target,
                        metadata: metadata.as_deref(),
                        key,
                    },
                    now_ms,
                )?;
            }
            (Some(BuiltinRelation::Capability), _) => {
                crate::delegation::admit_capability(
                    &*s,
                    execution.namespace(),
                    &asserter,
                    metadata.as_deref(),
                    creates,
                    now_ms,
                )?;
            }
            _ => {}
        }
        // A concurrent creator may have won the namespace; a capability
        // targets the namespace this execution actually writes.
        let target = match grant {
            Some(BuiltinRelation::Capability) => {
                kappa_handler::authority::namespace_identity(execution.namespace())
            }
            _ => edge_target.clone(),
        };
        let input = EdgeInput {
            source: source.clone(),
            target,
            relation: relation.clone(),
            asserter: asserter.clone(),
            metadata: metadata.clone(),
            created_at_ms: execution.now().as_i64(),
        };
        Ok(Outcome::Publish(execution.edge_put(&input)?))
    })
    .await?;

    let mut resp = empty_response(StatusCode::CREATED);
    resp.headers_mut().insert(
        "x-kappa-label",
        committed.value.to_string().parse().map_err(|error| {
            HandlerError::internal(format!("invalid edge response header: {error}"))
        })?,
    );
    committed.annotate(&mut resp);
    Ok(resp)
}

async fn query(cx: &Cx, _body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let ns = resolve_ns_read(cx)?;
    let anchor_str = path_param(cx, "edge_key")?;
    let direction_str = query_optional(cx, "direction").unwrap_or_else(|| "outbound".to_string());
    let relation_str = query_optional(cx, "relation");
    let limit = query_optional(cx, "n")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| HandlerError::bad_request("n must be a positive integer"))
        })
        .transpose()?
        .unwrap_or(1024);
    if limit == 0 {
        return Err(HandlerError::bad_request("n must be a positive integer"));
    }
    let after = query_optional(cx, "after");

    let anchor = Kappa::parse(&anchor_str)?;
    let relation = relation_str
        .as_deref()
        .map(|value| {
            parse_relation(value).ok_or_else(|| HandlerError::bad_request("unknown relation"))
        })
        .transpose()?;
    let direction = match direction_str.as_str() {
        "inbound" => Direction::Inbound,
        "both" => Direction::Both,
        "outbound" => Direction::Outbound,
        _ => return Err(HandlerError::bad_request("unknown edge direction")),
    };

    let s = store(cx);
    let q = EdgeQuery {
        anchor,
        direction,
        relation,
        asserter: None,
    };
    let edges = blocking({
        let s = s.clone();
        let n = ns.clone();
        move || s.edge_query(&n, &q, &PageRequest { limit, after })
    })
    .await?;

    let edge_json: Vec<serde_json::Value> = edges
        .items
        .iter()
        .map(|e| {
            let meta_value = match e.metadata() {
                Some(b) => serde_json::from_slice::<serde_json::Value>(b)
                    .unwrap_or_else(|_| serde_json::Value::String(kappa_handler::base64_encode(b))),
                None => serde_json::Value::Null,
            };
            serde_json::json!({
                "edge_kappa": e.kappa.to_string(),
                "source": e.source().to_string(),
                "target": e.target().to_string(),
                "relation": e.relation().to_string(),
                "asserter": e.asserter().to_string(),
                "metadata": meta_value,
            })
        })
        .collect();

    json_response(
        StatusCode::OK,
        &serde_json::json!({"edges": edge_json, "next_after": edges.next_after}),
    )
}

/// Execution work removing edge `edge` from the namespace. An edge the
/// namespace does not hold publishes nothing.
pub fn remove_edge(
    store: Arc<dyn KappaStore>,
    edge: Kappa,
) -> impl FnMut(&mut dyn Execution) -> Result<Outcome<()>, HandlerError> + Send + 'static {
    move |execution| {
        if !edge_present(&*store, execution.namespace(), &edge)? {
            return Ok(Outcome::Discard(()));
        }
        execution.edge_delete(&edge)?;
        Ok(Outcome::Publish(()))
    }
}

/// Whether namespace `ns` holds the edge identified by `edge`.
///
/// An edge's identity is the digest of its canonical `EdgeInput`, published
/// as content; the namespace holds it when its source's outbound edges of the
/// same relation and asserter include that identity.
fn edge_present(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    edge: &Kappa,
) -> Result<bool, StoreError> {
    let Some(content) = kappa_store::absent(store.blob_get_in(ns, edge))? else {
        return Ok(false);
    };
    // Content that does not decode as an edge identifies no edge.
    let Ok(input) = from_canonical::<EdgeInput>(&content) else {
        return Ok(false);
    };
    let query = EdgeQuery {
        anchor: input.source,
        direction: Direction::Outbound,
        relation: Some(input.relation),
        asserter: Some(input.asserter),
    };
    let mut request = PageRequest::first(1024);
    loop {
        let Some(page) = kappa_store::absent(store.edge_query(ns, &query, &request))? else {
            return Ok(false);
        };
        if page.items.iter().any(|candidate| &candidate.kappa == edge) {
            return Ok(true);
        }
        let Some(next) = page.next_after else {
            return Ok(false);
        };
        if request
            .after
            .as_ref()
            .is_some_and(|previous| previous >= &next)
        {
            return Err(StoreError::Internal(
                "edge pagination did not advance".into(),
            ));
        }
        request.after = Some(next);
    }
}

async fn delete(cx: &Cx, _body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let target = write_target(cx)?;
    let edge_kappa_str = path_param(cx, "edge_key")?;
    let edge_kappa = Kappa::parse(&edge_kappa_str)?;

    let committed = execute(cx, target, &[], remove_edge(store(cx), edge_kappa)).await?;

    let mut response = empty_response(StatusCode::ACCEPTED);
    committed.annotate(&mut response);
    Ok(response)
}

async fn diff(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let req: serde_json::Value = read_json(body, 1024 * 1024).await?;
    let ns = resolve_ns_read(cx)?;

    let have = kappa_list(&req, "have")?;
    let want = kappa_list(&req, "want")?;

    let s = store(cx);
    let result = blocking({
        let s = s.clone();
        let n = ns.clone();
        move || s.edge_diff(&n, &have, &want, &kappa_store::gc::gc_reachable_relations())
    })
    .await?;

    let labels: Vec<String> = result.iter().map(ToString::to_string).collect();
    json_response(StatusCode::OK, &serde_json::json!({"diff": labels}))
}

fn kappa_list(req: &serde_json::Value, field: &str) -> Result<Vec<Kappa>, HandlerError> {
    req[field]
        .as_array()
        .ok_or_else(|| HandlerError::BadRequest {
            reason: format!("{field} must be an array"),
        })?
        .iter()
        .map(|v| {
            let s = v.as_str().ok_or_else(|| HandlerError::BadRequest {
                reason: format!("each {field} entry must be a string"),
            })?;
            Kappa::parse(s).map_err(HandlerError::from)
        })
        .collect()
}

/// Parse a relation from its builtin name, the short name of a well-known
/// semantic IRI, or an absolute `http`/`https` IRI.
///
/// A short name resolves to its published IRI, so the stored relation, its
/// edge identity and its GC reachability are those of the IRI itself.
fn parse_relation(value: &str) -> Option<EdgeRelation> {
    // Builtin names are their `Display` form, the one name table; no copy
    // of it is kept here to drift.
    if let Some(builtin) = BuiltinRelation::ALL
        .into_iter()
        .find(|builtin| EdgeRelation::Builtin(*builtin).to_string() == value)
    {
        return Some(EdgeRelation::Builtin(builtin));
    }
    let iri = match value {
        "witness-of" => return Some(EdgeRelation::Builtin(BuiltinRelation::WitnessReceipt)),
        "derived-from" | "derives-from" => semantic::DERIVED_FROM,
        "attributed-to" => semantic::ATTRIBUTED_TO,
        "generated-by" => semantic::GENERATED_BY,
        "section-of" | "is-part-of" => semantic::IS_PART_OF,
        "refers-to" | "references" => semantic::REFERENCES,
        "certified-by" => semantic::CERTIFIED_BY,
        "composed-of" => semantic::COMPOSED_OF,
        "evidence-provenance" => semantic::EVIDENCE_PROVENANCE,
        iri if iri.starts_with("https://") || iri.starts_with("http://") => iri,
        _ => return None,
    };
    Some(EdgeRelation::Semantic(SemanticRelation(iri.into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names_resolve_to_their_published_iris() {
        for (name, iri, reachable) in [
            ("derived-from", semantic::DERIVED_FROM, true),
            ("derives-from", semantic::DERIVED_FROM, true),
            ("composed-of", semantic::COMPOSED_OF, true),
            ("section-of", semantic::IS_PART_OF, true),
            ("is-part-of", semantic::IS_PART_OF, true),
            ("refers-to", semantic::REFERENCES, false),
            ("references", semantic::REFERENCES, false),
            ("attributed-to", semantic::ATTRIBUTED_TO, false),
            ("generated-by", semantic::GENERATED_BY, false),
            ("certified-by", semantic::CERTIFIED_BY, false),
            ("evidence-provenance", semantic::EVIDENCE_PROVENANCE, false),
        ] {
            let relation = EdgeRelation::Semantic(SemanticRelation(iri.into()));
            assert_eq!(parse_relation(name), Some(relation.clone()), "{name}");
            assert_eq!(parse_relation(iri), Some(relation.clone()), "{iri}");
            assert_eq!(relation.gc_reachable(), reachable, "{name}");
        }
    }

    #[test]
    fn builtin_names_round_trip_through_display() {
        for builtin in BuiltinRelation::ALL {
            let relation = EdgeRelation::Builtin(builtin);
            assert_eq!(parse_relation(&relation.to_string()), Some(relation));
        }
        assert_eq!(
            parse_relation("witness-of"),
            Some(EdgeRelation::Builtin(BuiltinRelation::WitnessReceipt))
        );
    }

    #[test]
    fn unknown_names_and_relative_iris_are_rejected() {
        for value in ["", "derived", "Derived-From", "ftp://x/y", "urn:x", "owns "] {
            assert_eq!(parse_relation(value), None, "{value:?}");
        }
    }
}
