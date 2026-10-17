use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, StatusCode};

use kappa_handler::{HandlerError, blocking, path_param, store};
use kappa_store::{Kappa, ResolutionResult, resolve_all_filtered};

use crate::AsserterFilter;

pub async fn handler(
    cx: &Cx,
    _body: Body,
) -> Result<topcoat::router::response::Response, HandlerError> {
    let subject = path_param(cx, "subject")?;
    let asserter_filter: Option<Arc<AsserterFilter>> =
        kappa_handler::try_service::<Arc<AsserterFilter>>(cx).cloned();
    let s = store(cx);

    let result: ResolutionResult = blocking(move || -> Result<_, kappa_store::StoreError> {
        let mut assertions = Vec::new();
        let mut request = kappa_store::PageRequest {
            limit: 1024,
            after: None,
        };
        loop {
            let page = s.assertion_list_by_subject(&subject, &request)?;
            assertions.extend(page.items);
            match page.next_after {
                None => break,
                Some(after) => {
                    if request
                        .after
                        .as_ref()
                        .is_some_and(|previous| after <= *previous)
                    {
                        return Err(kappa_store::StoreError::Internal(
                            "assertion cursor did not advance".into(),
                        ));
                    }
                    request.after = Some(after);
                }
            }
        }

        let mut unique_asserters = HashSet::new();
        for (_, assertion) in &assertions {
            unique_asserters.insert(assertion.asserter.clone());
        }

        let mut revocations = Vec::new();
        let mut watermarks = Vec::new();
        for asserter in &unique_asserters {
            let mut revs = s.revocation_list_by_asserter(asserter)?;
            revocations.append(&mut revs);
            let mut wms = s.watermark_list_by_asserter(asserter)?;
            watermarks.append(&mut wms);
        }

        let filter_ref: Option<&dyn Fn(&Kappa) -> bool> = asserter_filter
            .as_ref()
            .map(|af| &af.0 as &dyn Fn(&Kappa) -> bool);

        Ok(resolve_all_filtered(
            &assertions,
            &revocations,
            &watermarks,
            filter_ref,
        ))
    })
    .await?;

    let valid: Vec<serde_json::Value> = result
        .valid
        .iter()
        .map(|a| {
            serde_json::json!({
                "asserter": a.asserter.to_string(),
                "subject": a.subject,
                "facet": a.facet,
                "basis": a.basis,
                "valid_from_ms": a.valid_from_ms,
            })
        })
        .collect();

    let subject_display = path_param(cx, "subject")?;
    let mut resp = serde_json::json!({
        "subject": subject_display,
        "valid": valid,
        "revoked_count": result.revoked.len(),
        "watermarked_count": result.watermarked.len(),
    });

    // `proof=true` attaches, per facet of the valid assertions, the
    // identity directory's verified history proof for the pair.
    let with_proof = match kappa_handler::query::query_optional(cx, "proof").as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(other) => {
            return Err(HandlerError::bad_request(format!(
                "proof must be true or false, got {other}"
            )));
        }
    };
    if with_proof {
        let facets: BTreeSet<String> = result.valid.iter().map(|a| a.facet.clone()).collect();
        let directory = crate::directory::directory(cx);
        let subject = subject_display.clone();
        let labels: Vec<(String, Vec<u8>)> = facets
            .into_iter()
            .map(|facet| {
                let key = crate::directory::label(&subject, &facet);
                (facet, key)
            })
            .collect();
        let histories = blocking(move || {
            labels
                .into_iter()
                .map(|(facet, key)| directory.history(&key).map(|proof| (facet, proof)))
                .collect::<Result<Vec<_>, _>>()
                .map_err(crate::directory::directory_error)
        })
        .await?;
        let mut proofs = Vec::with_capacity(histories.len());
        for (facet, proof) in &histories {
            let mut entry = crate::directory::history_json(cx, proof)?;
            entry["facet"] = facet.as_str().into();
            proofs.push(entry);
        }
        resp["proofs"] = proofs.into();
    }
    kappa_handler::json_response(StatusCode::OK, &resp)
}
