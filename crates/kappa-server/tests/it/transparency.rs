//! Identity directory proofs over HTTP, verified by the client from the
//! proof bytes and the signer the response names.

use super::helpers::*;

use kappa_store::canonical::from_canonical;
use kappa_transparency::{AuditProof, HistoryProof, HistoryState, verify};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The directory namespace id and the signer's public key, from a proof
/// response; the key is checked against the anchor it is claimed for.
fn verification_inputs(
    body: &serde_json::Value,
) -> Result<([u8; 16], Vec<u8>), Box<dyn std::error::Error>> {
    let namespace = hex::decode(
        body["namespace"]
            .as_str()
            .ok_or("proof response names no namespace")?,
    )?;
    let namespace_id: [u8; 16] = namespace
        .as_slice()
        .try_into()
        .map_err(|_| "namespace id is not 16 bytes")?;
    let signer = &body["signer"];
    let public_key = hex::decode(signer["public_key"].as_str().ok_or("no signer key")?)?;
    let algorithm = signer["algorithm"].as_str().ok_or("no signer algorithm")?;
    let anchor = kappa_store::Kappa::from_key(algorithm, &public_key)?;
    assert_eq!(
        anchor.to_string(),
        signer["anchor"].as_str().ok_or("no signer anchor")?,
        "signer key does not derive the anchor it is claimed for"
    );
    Ok((namespace_id, public_key))
}

fn history(
    body: &serde_json::Value,
) -> Result<(HistoryState, HistoryProof), Box<dyn std::error::Error>> {
    let (namespace_id, public_key) = verification_inputs(body)?;
    let proof: HistoryProof = from_canonical(&hex::decode(
        body["proof"].as_str().ok_or("no proof bytes")?,
    )?)?;
    let (state, root) = verify::history(&proof, &namespace_id, &public_key)?;
    assert_eq!(
        root.epoch_number(),
        body["epoch"].as_u64().ok_or("no epoch")?
    );
    assert_eq!(state.as_str(), body["state"].as_str().ok_or("no state")?);
    Ok((state, proof))
}

fn assert_ok(c: &reqwest::blocking::Client, base: &str, body: &serde_json::Value) -> TestResult {
    let resp = c
        .post(format!("{base}/identity/assert"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(body)?)
        .send()?;
    let status = resp.status().as_u16();
    let text = resp.text()?;
    assert_eq!(status, 201, "assertion refused: {text}");
    Ok(())
}

#[test]
fn absence_then_presence_are_verifiable_from_the_proof_bytes() -> TestResult {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let absent = c
        .get(format!("{base}/identity/absence/sha256:nobody/name/legal"))
        .send()?;
    assert_eq!(absent.status(), 200);
    let absent: serde_json::Value = absent.json()?;
    let (state, _) = history(&absent)?;
    assert_eq!(state, HistoryState::NeverAsserted);
    assert_eq!(absent["exists"], false);

    assert_ok(
        &c,
        &base,
        &signed_assertion("sha256:charlie", "name/legal", "Q2hhcmxpZQ")?,
    )?;
    let present = c
        .get(format!("{base}/identity/absence/sha256:charlie/name/legal"))
        .send()?;
    assert_eq!(present.status(), 200);
    let present: serde_json::Value = present.json()?;
    let (state, proof) = history(&present)?;
    assert_eq!(state, HistoryState::Active);
    assert_eq!(present["exists"], true);
    assert_eq!(
        present["value"].as_str().ok_or("no value")?,
        proof
            .leaf
            .as_ref()
            .ok_or("no leaf")?
            .entry
            .value
            .to_string()
    );
    // A neighbour of the published label is still provably absent, now
    // against a non-empty map.
    let neighbour = c
        .get(format!("{base}/identity/absence/sha256:charlie/name/other"))
        .send()?;
    assert_eq!(neighbour.status(), 200);
    let (state, _) = history(&neighbour.json()?)?;
    assert_eq!(state, HistoryState::NeverAsserted);
    drop(guard);
    Ok(())
}

#[test]
fn resolve_with_proof_attaches_verifiable_history_per_facet() -> TestResult {
    let (guard, base, _tmp) = start_server();
    let c = client();
    assert_ok(
        &c,
        &base,
        &signed_assertion("sha256:alice", "name/legal", "QWxpY2U")?,
    )?;
    assert_ok(
        &c,
        &base,
        &signed_assertion("sha256:alice", "name/display", "QWxp")?,
    )?;
    let resp = c
        .get(format!("{base}/identity/resolve/sha256:alice?proof=true"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json()?;
    let proofs = body["proofs"].as_array().ok_or("no proofs")?;
    assert_eq!(proofs.len(), 2, "{body}");
    for entry in proofs {
        let (state, _) = history(entry)?;
        assert_eq!(state, HistoryState::Active, "{entry}");
    }
    drop(guard);
    Ok(())
}

#[test]
fn revocation_retracts_the_label_and_audit_proves_the_append_only_log() -> TestResult {
    let (guard, base, _tmp) = start_server();
    let c = client();
    let (body, key) = signed_assertion_with_key("sha256:dave", "name/legal", "dGVzdA", None)?;
    assert_ok(&c, &base, &body)?;
    let resp = c
        .post(format!("{base}/identity/assert"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&body)?)
        .send()?;
    assert_eq!(resp.status(), 201);
    let kappa = resp.json::<serde_json::Value>()?["kappa"]
        .as_str()
        .ok_or("no kappa")?
        .to_owned();
    let before = c
        .get(format!("{base}/identity/absence/sha256:dave/name/legal"))
        .send()?
        .json::<serde_json::Value>()?;
    let epoch_before = before["epoch"].as_u64().ok_or("no epoch")?;

    let revocation = signed_revocation(&kappa, &key, 1_700_000_000_000)?;
    let resp = c
        .post(format!("{base}/identity/revoke"))
        .header("content-type", "application/json")
        .body(serde_json::to_string(&revocation)?)
        .send()?;
    let status = resp.status().as_u16();
    let text = resp.text()?;
    assert_eq!(status, 201, "revocation refused: {text}");

    let after = c
        .get(format!("{base}/identity/absence/sha256:dave/name/legal"))
        .send()?
        .json::<serde_json::Value>()?;
    let (state, proof) = history(&after)?;
    assert_eq!(state, HistoryState::Retracted);
    let retracted_at = proof
        .leaf
        .as_ref()
        .and_then(|leaf| leaf.entry.retracted_at)
        .ok_or("no retraction epoch")?;
    assert!(retracted_at > epoch_before);

    let audit = c
        .get(format!(
            "{base}/identity/audit/{epoch_before}/{retracted_at}"
        ))
        .send()?;
    assert_eq!(audit.status(), 200);
    let audit: serde_json::Value = audit.json()?;
    let (namespace_id, public_key) = verification_inputs(&audit)?;
    let proof: AuditProof = from_canonical(&hex::decode(
        audit["proof"].as_str().ok_or("no proof bytes")?,
    )?)?;
    verify::audit(&proof, &namespace_id, &public_key)?;
    assert_eq!(proof.from.commitment.epoch, epoch_before);
    assert_eq!(proof.to.commitment.epoch, retracted_at);
    assert_eq!(proof.transitions.len(), 1, "{audit}");
    assert_eq!(proof.transitions[0].transition.value, None);
    // A reversed range is refused, as is the creation epoch, which
    // commits no directory state.
    let reversed = c
        .get(format!(
            "{base}/identity/audit/{retracted_at}/{epoch_before}"
        ))
        .send()?;
    assert_eq!(reversed.status(), 400);
    let creation = c
        .get(format!("{base}/identity/audit/1/{retracted_at}"))
        .send()?;
    assert_eq!(creation.status(), 400);
    drop(guard);
    Ok(())
}
