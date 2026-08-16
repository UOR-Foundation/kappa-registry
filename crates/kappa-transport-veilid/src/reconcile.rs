//! MST reconciliation protocol over Veilid app_call.
//!
//! Uses rekindle-transport-veilid's Caller for request/response and
//! kappa-reconcile's NamespaceMst for set reconciliation.
//!
//! The reconciliation flow:
//! 1. Compare epoch roots via fetch_epoch_root (PeerTransport).
//! 2. If epochs differ: pull all tags via app_call with DIFF_PULL protocol.
//! 3. Apply received tags to local KappaStore.
//!
//! Inbound reconciliation requests are handled by handle_reconcile_request,
//! called from the dispatch loop when an AppCall arrives with a recognized
//! protocol byte.

use std::collections::BTreeMap;
use std::sync::Arc;

use kappa_core::membership::MembershipView;
use kappa_core::store::KappaStore;
use kappa_core::transport::PeerTransport;
use kappa_core::types::NamespaceRef;
use kappa_reconcile::NamespaceMst;

/// Protocol bytes.
const PROTO_PING: u8 = 0x00;
const PROTO_EPOCH_ROOT_REQ: u8 = 0x01;
const PROTO_EPOCH_ROOT_RESP: u8 = 0x02;
const PROTO_DIFF_PULL_REQ: u8 = 0x05;
const PROTO_DIFF_PULL_RESP: u8 = 0x06;

/// Wire types.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EpochRootResponse {
    pub epoch_number: u64,
    pub root_kappa: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DiffPullRequest {
    pub namespace: String,
    pub tag_names: Vec<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DiffPullResponse {
    pub namespace: String,
    pub tags: Vec<TagEntryWire>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TagEntryWire {
    pub name: String,
    pub kappa: String,
    pub version: u64,
}

/// Reconciliation report.
#[derive(Debug, Default)]
pub struct ReconcileReport {
    pub peers_contacted: u32,
    pub namespaces_reconciled: u32,
    pub tags_pulled: u32,
    pub errors: Vec<(String, String)>,
}

/// Background reconciliation loop.
///
/// Periodically reconciles with all known peers by comparing epoch
/// roots and pulling tags for namespaces that differ.
pub struct ReconcileLoop<T: PeerTransport, M: MembershipView> {
    transport: Arc<T>,
    membership: Arc<M>,
    store: Arc<dyn KappaStore>,
    interval_secs: u64,
}

impl<T: PeerTransport + 'static, M: MembershipView + 'static> ReconcileLoop<T, M> {
    pub fn new(
        transport: Arc<T>,
        membership: Arc<M>,
        store: Arc<dyn KappaStore>,
        interval_secs: u64,
    ) -> Self {
        Self {
            transport,
            membership,
            store,
            interval_secs,
        }
    }

    /// Run one reconciliation round.
    pub fn reconcile_once(&self) -> ReconcileReport {
        let mut report = ReconcileReport::default();
        let peers = self.membership.members();
        let self_id = self.membership.self_id().to_string();

        let namespaces = match self.store.namespace_list() {
            Ok(ns) => ns,
            Err(e) => {
                report.errors.push(("self".into(), e.to_string()));
                return report;
            }
        };

        for peer in &peers {
            if peer.id == self_id || !peer.healthy {
                continue;
            }
            report.peers_contacted += 1;

            for ns in &namespaces {
                // Step 1: compare epoch roots
                let remote_bytes = match self.transport.fetch_epoch_root(&peer.id, ns) {
                    Ok(b) => b,
                    Err(e) => {
                        report.errors.push((peer.id.clone(), e.to_string()));
                        continue;
                    }
                };

                if remote_bytes.len() < 2 {
                    continue;
                }

                let remote: EpochRootResponse = match postcard::from_bytes(&remote_bytes[1..]) {
                    Ok(r) => r,
                    Err(e) => {
                        report.errors.push((peer.id.clone(), format!("decode: {e}")));
                        continue;
                    }
                };

                // Compare with local
                let ns_ref = NamespaceRef::from(ns.as_str());
                let local_kappa = self.store.epoch_current(&ns_ref).unwrap_or(None);
                if local_kappa.as_deref() == Some(&remote.root_kappa) {
                    continue; // identical
                }

                // Step 2: pull all tags (correct but suboptimal baseline)
                let pull_req = DiffPullRequest {
                    namespace: ns.clone(),
                    tag_names: Vec::new(),
                };
                let mut pull_bytes = vec![PROTO_DIFF_PULL_REQ];
                if let Ok(encoded) = postcard::to_stdvec(&pull_req) {
                    pull_bytes.extend_from_slice(&encoded);
                } else {
                    continue;
                }

                let pull_resp_bytes = match self.transport.call_peer(&peer.id, &pull_bytes) {
                    Ok(resp) => resp,
                    Err(e) => {
                        report.errors.push((peer.id.clone(), e.to_string()));
                        continue;
                    }
                };

                if pull_resp_bytes.len() < 2 {
                    continue;
                }

                let pull_resp: DiffPullResponse = match postcard::from_bytes(&pull_resp_bytes[1..]) {
                    Ok(r) => r,
                    Err(e) => {
                        report.errors.push((peer.id.clone(), format!("decode pull: {e}")));
                        continue;
                    }
                };

                let mut applied = 0u32;
                for tag in &pull_resp.tags {
                    match self.store.tag_set(&ns_ref, &tag.name, &tag.kappa) {
                        Ok(_) => applied += 1,
                        Err(e) => {
                            tracing::warn!(
                                ns = ns.as_str(), tag = %tag.name, error = %e,
                                "reconcile tag apply failed"
                            );
                        }
                    }
                }
                if applied > 0 {
                    report.namespaces_reconciled += 1;
                    report.tags_pulled += applied;
                }
            }
        }

        report
    }

    /// Build namespace MSTs from the store.
    pub fn build_msts(
        &self,
    ) -> Result<BTreeMap<String, NamespaceMst>, kappa_core::types::StoreError> {
        let namespaces = self.store.namespace_list()?;
        let mut msts = BTreeMap::new();
        for ns in &namespaces {
            let ns_ref = NamespaceRef::from(ns.as_str());
            let tags = self.store.tag_list(&ns_ref)?;
            let mut tag_map = BTreeMap::new();
            for tag in &tags {
                tag_map.insert(tag.name.clone(), tag.kappa.clone());
            }
            let mut mst = NamespaceMst::new(ns.clone());
            mst.rebuild(&tag_map);
            msts.insert(ns.clone(), mst);
        }
        Ok(msts)
    }

    /// Spawn the background loop.
    pub fn spawn(
        self: Arc<Self>,
        mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let interval_secs = self.interval_secs;
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let report = self.reconcile_once();
                        if report.tags_pulled > 0 || !report.errors.is_empty() {
                            tracing::info!(
                                peers = report.peers_contacted,
                                namespaces = report.namespaces_reconciled,
                                tags = report.tags_pulled,
                                errors = report.errors.len(),
                                "reconciliation round complete"
                            );
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("reconciliation loop shutting down");
                        break;
                    }
                }
            }
        })
    }
}

/// Handle an inbound reconciliation request.
///
/// Called from the kappa-server dispatch loop when an AppCall arrives
/// with a recognized protocol byte. Returns the response bytes to
/// send back via app_call_reply.
pub fn handle_reconcile_request(
    store: &dyn KappaStore,
    request: &[u8],
) -> Result<Vec<u8>, String> {
    if request.is_empty() {
        return Err("empty request".into());
    }

    match request[0] {
        PROTO_PING => Ok(vec![PROTO_PING]),

        PROTO_EPOCH_ROOT_REQ => {
            let namespace_str = std::str::from_utf8(&request[1..])
                .map_err(|e| format!("invalid namespace utf8: {e}"))?;
            let namespace = NamespaceRef::from(namespace_str);

            let (epoch_number, root_kappa) = match store.epoch_current(&namespace) {
                Ok(Some(ref ek)) => match store.epoch_get(ek) {
                    Ok(root) => (root.epoch_number, ek.clone()),
                    Err(e) => return Err(format!("epoch_get: {e}")),
                },
                Ok(None) => (0, String::new()),
                Err(e) => return Err(format!("epoch_current: {e}")),
            };

            let resp = EpochRootResponse {
                epoch_number,
                root_kappa,
            };
            let mut resp_bytes = vec![PROTO_EPOCH_ROOT_RESP];
            resp_bytes.extend_from_slice(
                &postcard::to_stdvec(&resp).map_err(|e| format!("encode: {e}"))?,
            );
            Ok(resp_bytes)
        }

        PROTO_DIFF_PULL_REQ => {
            let req: DiffPullRequest = postcard::from_bytes(&request[1..])
                .map_err(|e| format!("decode: {e}"))?;

            let req_ns = NamespaceRef::from(req.namespace.as_str());
            let tags = if req.tag_names.is_empty() {
                store
                    .tag_list(&req_ns)
                    .map_err(|e| format!("tag_list: {e}"))?
                    .into_iter()
                    .map(|t| TagEntryWire {
                        name: t.name,
                        kappa: t.kappa,
                        version: t.version,
                    })
                    .collect()
            } else {
                req.tag_names
                    .iter()
                    .filter_map(|name| {
                        store.tag_get(&req_ns, name).ok().map(|t| TagEntryWire {
                            name: t.name,
                            kappa: t.kappa,
                            version: t.version,
                        })
                    })
                    .collect()
            };

            let resp = DiffPullResponse {
                namespace: req.namespace,
                tags,
            };
            let mut resp_bytes = vec![PROTO_DIFF_PULL_RESP];
            resp_bytes.extend_from_slice(
                &postcard::to_stdvec(&resp).map_err(|e| format!("encode: {e}"))?,
            );
            Ok(resp_bytes)
        }

        proto => Err(format!("unknown protocol byte 0x{proto:02x}")),
    }
}
