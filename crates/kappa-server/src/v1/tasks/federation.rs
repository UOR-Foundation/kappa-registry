use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use kappa_crypto::node::NodeIdentity;
use kappa_store::identity::{PeerRecord, ProbeResult};
use kappa_store::kappa::Kappa;
use kappa_store::tag::TagUpdate;
use kappa_store::time::Clock;
use kappa_store::traits::KappaStore;
use kappa_store::{StoreError, publish_if_changed};

/// Publish the node's trust position under `trust/position/{anchor}` in
/// `_system` as one execution. A position the tag already holds publishes
/// nothing. Returns the published epoch number, if any.
pub fn publish_trust_position<S: KappaStore + ?Sized>(
    store: &S,
    anchor: &Kappa,
    position: &str,
    clock: &dyn Clock,
) -> Result<Option<u64>, StoreError> {
    let system_ns = store.namespace_resolve("_system", None)?;
    let position_kappa = Kappa::sha256(position.as_bytes());
    let key = format!("trust/position/{anchor}");
    let published = publish_if_changed(store, &system_ns, clock, |execution| {
        if execution
            .tag_get_raw(&key)?
            .is_some_and(|entry| entry.kappa == position_kappa && entry.symref.is_none())
        {
            return Ok(false);
        }
        execution.tag_put(
            &key,
            &TagUpdate::Set {
                kappa: position_kappa,
            },
        )?;
        Ok(true)
    })?;
    Ok(published.map(|published| published.epoch_number))
}

pub async fn run_federation_probe_loop<S>(
    store: Arc<S>,
    clock: Arc<dyn Clock>,
    node_identity: Arc<NodeIdentity>,
    peers: Vec<String>,
    interval_secs: u64,
) where
    S: KappaStore + 'static + ?Sized,
{
    if peers.is_empty() {
        return;
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to build federation probe HTTP client");
            return;
        }
    };
    let peer_epochs: Arc<DashMap<Kappa, (u64, Kappa)>> = Arc::new(DashMap::new());
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        ticker.tick().await;
        let mut results = Vec::new();
        for peer_url in &peers {
            let result = probe_peer(&client, peer_url, &peer_epochs).await;
            results.push(result);
        }
        node_identity.update_from_probes(&results);
        let store = store.clone();
        let clock = clock.clone();
        // The anchor the node signs under now, after any rotation.
        let anchor = match node_identity.anchor() {
            Ok(anchor) => anchor,
            Err(error) => {
                tracing::error!(%error, "federation: node identity unavailable");
                continue;
            }
        };
        let position = node_identity.position();
        let result = kappa_handler::blocking(move || {
            publish_trust_position(&*store, &anchor, position.as_str(), &*clock)
        })
        .await;
        match result {
            Ok(Some(epoch)) => {
                tracing::debug!(epoch, "federation: trust position published");
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "federation: trust position publication failed");
            }
        }
    }
}

async fn probe_peer(
    client: &reqwest::Client,
    peer_url: &str,
    peer_epochs: &DashMap<Kappa, (u64, Kappa)>,
) -> ProbeResult {
    let url = format!("{}/v2/_root?signed=true", peer_url.trim_end_matches('/'));
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return ProbeResult::Unreachable(format!("{}: {}", peer_url, e)),
    };
    if !resp.status().is_success() {
        return ProbeResult::Unreachable(format!("{}: HTTP {}", peer_url, resp.status()));
    }
    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => return ProbeResult::Unreachable(format!("{}: parse error: {}", peer_url, e)),
    };

    let root_str = match body.get("root").and_then(|v| v.as_str()) {
        Some(r) if !r.is_empty() => r,
        _ => return ProbeResult::Unreachable(format!("{}: missing root field", peer_url)),
    };
    let count = match body.get("count").and_then(|v| v.as_u64()) {
        Some(c) => c,
        None => return ProbeResult::Unreachable(format!("{}: missing count field", peer_url)),
    };
    let namespace = body
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or("_system");
    let algorithm = match body.get("algorithm").and_then(|v| v.as_str()) {
        Some(a) if !a.is_empty() => a,
        _ => return ProbeResult::Unreachable(format!("{}: missing algorithm field", peer_url)),
    };
    let public_key_hex = match body.get("public_key").and_then(|v| v.as_str()) {
        Some(pk) if !pk.is_empty() => pk,
        _ => return ProbeResult::Unreachable(format!("{}: missing public_key field", peer_url)),
    };
    let signature_hex = match body.get("signature").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return ProbeResult::Unreachable(format!("{}: missing signature field", peer_url)),
    };
    // The signed root carries `timestamp_ms` as a number, and the signed
    // message is `{namespace}\n{root}\n{timestamp_ms}`.
    let timestamp = match body.get("timestamp_ms").and_then(serde_json::Value::as_i64) {
        Some(timestamp) => timestamp,
        None => {
            return ProbeResult::Unreachable(format!("{peer_url}: missing timestamp_ms field"));
        }
    };

    let public_key = match hex::decode(public_key_hex) {
        Ok(pk) => pk,
        Err(e) => {
            return ProbeResult::SignatureInvalid(format!(
                "{}: invalid public_key hex: {}",
                peer_url, e
            ));
        }
    };
    let signature = match hex::decode(signature_hex) {
        Ok(sig) => sig,
        Err(e) => {
            return ProbeResult::SignatureInvalid(format!(
                "{}: invalid signature hex: {}",
                peer_url, e
            ));
        }
    };

    let message = format!("{}\n{}\n{}", namespace, root_str, timestamp);
    let verifier = match kappa_crypto::verifier_for(algorithm) {
        Ok(v) => v,
        Err(e) => return ProbeResult::SignatureInvalid(format!("{}: {}", peer_url, e)),
    };
    match verifier.verify(&public_key, message.as_bytes(), &signature) {
        Ok(true) => {}
        Ok(false) => {
            return ProbeResult::SignatureInvalid(format!(
                "{}: signature verification failed",
                peer_url
            ));
        }
        Err(e) => {
            return ProbeResult::SignatureInvalid(format!("{}: verify error: {}", peer_url, e));
        }
    }

    let peer_anchor = match Kappa::from_key(algorithm, &public_key) {
        Ok(anchor) => anchor,
        Err(error) => return ProbeResult::SignatureInvalid(format!("{peer_url}: {error}")),
    };

    let root_kappa = match Kappa::parse(root_str) {
        Ok(k) => k,
        Err(e) => {
            return ProbeResult::Unreachable(format!(
                "{}: malformed root kappa {}: {}",
                peer_url, root_str, e
            ));
        }
    };

    if let Some(prev) = peer_epochs.get(&peer_anchor) {
        let (prev_epoch, prev_root) = prev.value();
        if *prev_epoch == count && *prev_root != root_kappa {
            return ProbeResult::Equivocation {
                peer: peer_anchor,
                epoch: count,
                local_root: prev_root.clone(),
                remote_root: root_kappa,
            };
        }
    }

    peer_epochs.insert(peer_anchor.clone(), (count, root_kappa.clone()));

    ProbeResult::Verified(PeerRecord {
        endpoint: peer_url.to_string(),
        asserter_anchor: peer_anchor,
        last_epoch: count,
        state_root: root_kappa,
    })
}
