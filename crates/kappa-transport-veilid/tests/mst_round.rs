//! One reconciliation round between two in-process stores over a loopback
//! transport: every request the initiator sends is answered by the
//! responder of the other store, with no network. The round must fetch a
//! key only the peer holds that lies strictly between two shared keys: the
//! case the MST diff reports as a range and an initiator that pulls only
//! its own names in that range never fetches.

use std::sync::Arc;

use async_trait::async_trait;
use kappa_handler::clock_at;
use kappa_reconcile::{PeerInfo, ReconcileTransport, TransportError};
use kappa_store::{ClockMs, EpochStore, ExecutionStore, Kappa, NamespaceRef, TagStore, TagUpdate};
use kappa_store_memory::{InMemoryStore, test_support};
use kappa_transport_veilid::reconcile::{PeerPhase, ReconcileLoop, handle_reconcile_request};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The peer's responder, reached as a transport: `call_peer` to the
/// peer's address answers through its store; any other address is a peer
/// the loopback does not know.
struct Loopback {
    address: String,
    store: Arc<InMemoryStore>,
}

#[async_trait]
impl ReconcileTransport for Loopback {
    async fn call_peer(&self, peer: &str, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        if peer != self.address {
            return Err(TransportError::PeerNotFound(peer.to_owned()));
        }
        handle_reconcile_request(self.store.as_ref(), request).map_err(TransportError::Rejected)
    }
}

fn at(offset_ms: i64) -> ClockMs {
    ClockMs::from_raw((1_700_000_000_000 + offset_ms) << 16)
}

fn store() -> Result<Arc<InMemoryStore>, Box<dyn std::error::Error>> {
    Ok(Arc::new(test_support::test_store()?.into_store()))
}

/// Publish `names` as tags of the namespace `name` on `store`, creating
/// the namespace with the deterministic identity both stores share.
fn publish(
    store: &InMemoryStore,
    name: &str,
    names: &[&str],
    time: i64,
) -> Result<NamespaceRef, Box<dyn std::error::Error>> {
    let ns = NamespaceRef::deterministic(name);
    let clock = clock_at(at(time))?;
    let mut execution = store.begin_execution(&ns, &clock)?;
    execution.namespace_create(None, None)?;
    for tag in names {
        execution.tag_put(
            tag,
            &TagUpdate::Set {
                kappa: Kappa::sha256(tag.as_bytes()),
            },
        )?;
    }
    execution.publish()?;
    Ok(ns)
}

#[tokio::test]
async fn a_round_fetches_a_key_only_the_peer_holds_inside_a_shared_range() -> TestResult {
    let local = store()?;
    let peer = store()?;
    let ns = publish(&local, "images", &["aaa", "mmm", "zzz"], 1)?;
    publish(&peer, "images", &["aaa", "mmm", "qqq", "zzz"], 2)?;

    let loopback = Arc::new(Loopback {
        address: "peer".into(),
        store: Arc::clone(&peer),
    });
    let round = ReconcileLoop::new(
        loopback,
        Arc::clone(&local),
        Arc::new(clock_at(at(10))?),
        Kappa::from_key("veilid", b"local")?,
        3600,
    );
    let peers = [PeerInfo {
        id: Kappa::from_key("veilid", b"peer")?,
        address: "peer".into(),
        healthy: true,
    }];
    let report = round.reconcile_once(&peers).await;
    assert_eq!(report.peers_contacted, 1, "{report:?}");
    assert_eq!(report.peers_failed, 0, "{report:?}");
    assert_eq!(report.namespaces_reconciled, 1, "{report:?}");
    assert_eq!(report.peer_outcomes.len(), 1);
    assert_eq!(
        report.peer_outcomes[0].phase,
        PeerPhase::Applied,
        "{report:?}"
    );
    assert!(
        report.peer_outcomes[0].errors.is_empty(),
        "{:?}",
        report.peer_outcomes[0].errors
    );

    let fetched = local.tag_get(&ns, "qqq")?;
    assert_eq!(
        fetched.kappa,
        Kappa::sha256(b"qqq"),
        "the remote-only key arrived"
    );
    for shared in ["aaa", "mmm", "zzz"] {
        assert_eq!(
            local.tag_get(&ns, shared)?.kappa,
            Kappa::sha256(shared.as_bytes())
        );
    }
    assert_eq!(local.epoch_current(&ns)?.0, 2, "one batch, one epoch");

    // Converged: a second round pulls nothing and publishes nothing.
    let again = round.reconcile_once(&peers).await;
    assert_eq!(again.total_tags_applied, 0, "{again:?}");
    assert_eq!(local.epoch_current(&ns)?.0, 2);
    Ok(())
}

#[tokio::test]
async fn self_and_unhealthy_peers_are_skipped_and_unknown_peers_fail() -> TestResult {
    let local = store()?;
    let peer = store()?;
    publish(&local, "charts", &["a"], 1)?;
    publish(&peer, "charts", &["a", "b"], 2)?;
    let own = Kappa::from_key("veilid", b"local")?;
    let round = ReconcileLoop::new(
        Arc::new(Loopback {
            address: "peer".into(),
            store: peer,
        }),
        Arc::clone(&local),
        Arc::new(clock_at(at(10))?),
        own.clone(),
        3600,
    );
    let report = round
        .reconcile_once(&[
            PeerInfo {
                id: own,
                address: "peer".into(),
                healthy: true,
            },
            PeerInfo {
                id: Kappa::from_key("veilid", b"down")?,
                address: "peer".into(),
                healthy: false,
            },
            PeerInfo {
                id: Kappa::from_key("veilid", b"stranger")?,
                address: "nowhere".into(),
                healthy: true,
            },
        ])
        .await;
    assert_eq!(report.peers_skipped, 2, "{report:?}");
    assert_eq!(report.peers_failed, 1, "{report:?}");
    assert_eq!(report.total_tags_applied, 0);
    Ok(())
}
