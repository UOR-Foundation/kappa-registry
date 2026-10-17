//! Node authority rotation through the real application boundary.
//!
//! Each rotation goes through `POST /_node/authority/rotate`, authorized as
//! a `_root` admin operation. Afterwards the live identity, its published
//! self-assertions, the store's committed authority, the signer of newly
//! published epochs, and the key store's custody must all agree, and a
//! restart must restore the same authority from the store's history.

use super::helpers::*;

use kappa_crypto::Signer;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_store::traits::{EdgeStore, EpochStore, NamespaceStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ROOT_SEED: [u8; 32] = [61u8; 32];
const OUTSIDER_SEED: [u8; 32] = [62u8; 32];
const ROTATE: &str = "/_node/authority/rotate";

fn anchor(seed: &[u8; 32]) -> Result<kappa_store::Kappa, Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_bytes(seed)?;
    Ok(kappa_store::Kappa::from_key(
        signer.algorithm(),
        signer.public_key(),
    )?)
}

const WITNESS_SEED: [u8; 32] = [63u8; 32];

fn env(
    witness: Option<&std::path::Path>,
) -> Result<Vec<(&'static str, String)>, Box<dyn std::error::Error>> {
    let mut env = vec![
        ("KAPPA_AUTH_REQUIRED", "true".to_owned()),
        (
            "KAPPA_ROOT_TOKEN",
            format!("root-token={}", anchor(&ROOT_SEED)?),
        ),
        (
            "KAPPA_AUTH_TOKENS",
            format!("outsider-token={}", anchor(&OUTSIDER_SEED)?),
        ),
    ];
    if let Some(path) = witness {
        env.push((
            "KAPPA_ROTATION_WITNESS_KEY_FILE",
            path.to_str()
                .ok_or("witness key path is not UTF-8")?
                .to_owned(),
        ));
    }
    Ok(env)
}

/// A server whose rotations are countersigned by the witness key, kept
/// beside its store root.
fn start(store_root: &std::path::Path) -> Result<ServerGuard, Box<dyn std::error::Error>> {
    let witness = store_root.join("rotation-witness.key");
    std::fs::write(&witness, hex::encode(WITNESS_SEED))?;
    start_with(store_root, Some(&witness))
}

fn start_with(
    store_root: &std::path::Path,
    witness: Option<&std::path::Path>,
) -> Result<ServerGuard, Box<dyn std::error::Error>> {
    let env = env(witness)?;
    let pairs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    Ok(start_server_at_with_env(store_root, &pairs))
}

fn whoami(
    c: &reqwest::blocking::Client,
    base: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let response = c
        .get(format!("{base}/identity/whoami"))
        .header("Authorization", "Bearer root-token")
        .send()?;
    let status = response.status();
    let text = response.text()?;
    assert_eq!(status, 200, "whoami: {text}");
    Ok(serde_json::from_str(&text)?)
}

fn rotate(
    c: &reqwest::blocking::Client,
    base: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let mut request = c.post(format!("{base}{ROTATE}"));
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send()?;
    Ok((response.status().as_u16(), response.text()?))
}

const GUARANTEES: [&str; 5] = [
    "custody",
    "key_removal",
    "authorization",
    "revocation",
    "activation",
];

/// Rotate with the root token and return the reported (retired, current),
/// requiring every follow-up guarantee to hold.
fn rotate_ok(
    c: &reqwest::blocking::Client,
    base: &str,
    body: Option<serde_json::Value>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let (status, text) = rotate(c, base, Some("root-token"), body)?;
    assert_eq!(status, 200, "rotation: {text}");
    let report: serde_json::Value = serde_json::from_str(&text)?;
    for guarantee in GUARANTEES {
        assert_eq!(
            report["completion"][guarantee], true,
            "{guarantee} incomplete after rotation: {text}"
        );
    }
    let retired = report["retired"]
        .as_str()
        .ok_or("no retired anchor")?
        .to_owned();
    let current = report["current"]
        .as_str()
        .ok_or("no current anchor")?
        .to_owned();
    assert_ne!(retired, current);
    Ok((retired, current))
}

/// `GET /_node/authority` as the root token sees it.
fn authority_status(
    c: &reqwest::blocking::Client,
    base: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let response = c
        .get(format!("{base}/_node/authority"))
        .header("Authorization", "Bearer root-token")
        .send()?;
    let status = response.status();
    let text = response.text()?;
    assert_eq!(status, 200, "authority status: {text}");
    Ok(serde_json::from_str(&text)?)
}

/// Status names `current` as the active committed authority with `retired`
/// in order and every guarantee holding, and readiness agrees.
fn assert_status(
    c: &reqwest::blocking::Client,
    base: &str,
    current: &str,
    retired: &[&str],
) -> TestResult {
    let status = authority_status(c, base)?;
    assert_eq!(status["current"], current, "{status}");
    assert_eq!(status["commit"], "known", "{status}");
    assert_eq!(status["availability"], "active", "{status}");
    assert_eq!(status["live"], serde_json::Value::Null, "{status}");
    assert_eq!(status["retired"], serde_json::json!(retired), "{status}");
    for guarantee in GUARANTEES {
        assert_eq!(
            status["completion"][guarantee], true,
            "{guarantee}: {status}"
        );
    }
    let ready = c.get(format!("{base}/v2/_health/ready")).send()?.status();
    assert_eq!(ready, 200, "readiness with every guarantee holding");
    Ok(())
}

/// Every `_root` edge of `relation` that `anchor` asserted from itself.
fn root_edges_from(
    store: &kappa_store_redb::PersistentStore,
    anchor: &str,
    relation: kappa_store::edge::BuiltinRelation,
) -> Result<usize, Box<dyn std::error::Error>> {
    let anchor = kappa_store::Kappa::parse(anchor)?;
    let root = store.namespace_resolve("_root", None)?;
    let query = kappa_store::edge::EdgeQuery {
        anchor: anchor.clone(),
        direction: kappa_store::edge::Direction::Outbound,
        relation: Some(kappa_store::edge::EdgeRelation::Builtin(relation)),
        asserter: Some(anchor),
    };
    let page = store.edge_query(&root, &query, &kappa_store::PageRequest::first(256))?;
    assert!(page.next_after.is_none(), "more edges than one page");
    Ok(page.items.len())
}

/// The live identity and its published self-assertions both name `expected`.
fn assert_identity(
    c: &reqwest::blocking::Client,
    base: &str,
    expected: &str,
    algorithm: &str,
) -> TestResult {
    let me = whoami(c, base)?;
    assert_eq!(me["anchor"], expected, "live identity: {me}");
    assert_eq!(me["algorithm"], algorithm, "live algorithm: {me}");
    assert_eq!(
        me["self_assertions"]["anchor"], expected,
        "published self-assertion: {me}"
    );
    assert_eq!(
        me["self_assertions"]["algorithm"], algorithm,
        "published algorithm: {me}"
    );
    Ok(())
}

fn entries(
    path: &std::path::Path,
    prefix: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with(prefix) {
            names.push(name);
        }
    }
    Ok(names)
}

#[test]
fn rotation_is_a_root_admin_operation() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let server = start(tmp.path())?;
    let c = client();
    let base = server.base();
    let before = whoami(&c, &base)?["anchor"].clone();

    let (status, text) = rotate(&c, &base, None, None)?;
    assert_eq!(status, 401, "anonymous rotation: {text}");
    let (status, text) = rotate(&c, &base, Some("outsider-token"), None)?;
    assert_eq!(status, 403, "ungranted rotation: {text}");
    let (status, text) = rotate(
        &c,
        &base,
        Some("root-token"),
        Some(serde_json::json!({"algorithm": "rsa-4096"})),
    )?;
    assert_eq!(status, 400, "unsupported algorithm: {text}");
    // Only a JSON object whose sole member is a supported algorithm string
    // is admitted; anything else is refused before any key is generated.
    for malformed in [
        serde_json::json!({"algorithm": 7}),
        serde_json::json!([]),
        serde_json::Value::Null,
        serde_json::json!(7),
        serde_json::json!("ed25519"),
        serde_json::json!({"algorithm": "ed25519", "extra": true}),
    ] {
        let (status, text) = rotate(&c, &base, Some("root-token"), Some(malformed.clone()))?;
        assert_eq!(status, 400, "malformed body {malformed}: {text}");
    }
    assert_eq!(
        whoami(&c, &base)?["anchor"],
        before,
        "a refused rotation changed the node's authority"
    );
    let status = authority_status(&c, &base)?;
    assert_eq!(status["retired"], serde_json::json!([]), "{status}");
    assert_eq!(status["completion"]["key_removal"], true, "{status}");
    drop(server);
    let keys = tmp.path().join("keys");
    assert_eq!(
        entries(&keys, "node-")?.len(),
        1,
        "a refused rotation generated a key"
    );
    assert!(entries(&keys, "successor")?.is_empty());
    let server = start(tmp.path())?;
    let base = server.base();
    for (token, expected) in [(None, 401), (Some("outsider-token"), 403)] {
        let mut request = c.get(format!("{base}/_node/authority"));
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = request.send()?;
        let status = response.status();
        let text = response.text()?;
        assert_eq!(
            status, expected,
            "authority status without _root read ({token:?}): {text}"
        );
    }
    assert_eq!(authority_status(&c, &base)?["current"], before);
    Ok(())
}

/// A node without a witness key refuses rotation before anything commits:
/// the authority, the key store and the history are unchanged.
#[test]
fn rotation_without_a_witness_is_refused() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let server = start_with(tmp.path(), None)?;
    let c = client();
    let base = server.base();
    let before = whoami(&c, &base)?["anchor"].clone();
    let (status, text) = rotate(&c, &base, Some("root-token"), None)?;
    assert_eq!(status, 409, "unwitnessed rotation: {text}");
    assert!(text.contains("ROTATION_UNWITNESSED"), "{text}");
    assert_eq!(whoami(&c, &base)?["anchor"], before);
    let status = authority_status(&c, &base)?;
    assert_eq!(status["retired"], serde_json::json!([]), "{status}");
    drop(server);
    let keys = tmp.path().join("keys");
    assert_eq!(
        entries(&keys, "node-")?.len(),
        1,
        "a refused rotation kept a key"
    );
    assert!(entries(&keys, "successor")?.is_empty());
    Ok(())
}

/// Identity, self-assertions, status, readiness, epoch signer, custody and
/// `_root` grants follow each rotation, and a restart restores them.
#[test]
fn rotation_moves_identity_publication_custody_and_grants_and_survives_restart() -> TestResult {
    let tmp = tempfile::tempdir()?;
    let c = client();
    let server = start(tmp.path())?;
    let base = server.base();
    let first = whoami(&c, &base)?["anchor"]
        .as_str()
        .ok_or("no anchor")?
        .to_owned();
    assert_identity(&c, &base, &first, "ed25519")?;
    assert_status(&c, &base, &first, &[])?;

    let (retired, second) = rotate_ok(&c, &base, None)?;
    assert_eq!(retired, first);
    assert_identity(&c, &base, &second, "ed25519")?;
    assert_status(&c, &base, &second, &[&first])?;

    // Published after the rotation, so signed by the second authority.
    let status = c
        .post(format!("{base}/v2/after-rotation/_namespace/create"))
        .header("Authorization", "Bearer root-token")
        .send()?
        .status();
    assert_eq!(status, 201);

    // The root token still authorizes: the incoming authority re-issued
    // its `_root` delegation. A second rotation changes algorithm.
    let (retired, third) = rotate_ok(&c, &base, Some(serde_json::json!({"algorithm": "p256"})))?;
    assert_eq!(retired, second);
    assert_identity(&c, &base, &third, "p256")?;
    assert_status(&c, &base, &third, &[&first, &second])?;
    drop(server);

    // Custody: one node key, no staged successor, no staging secret.
    let keys = tmp.path().join("keys");
    assert_eq!(entries(&keys, "node-")?.len(), 1, "retired keys survived");
    assert!(entries(&keys, "successor")?.is_empty());
    assert!(entries(&keys, ".stage-")?.is_empty());

    // The store's committed history names the third authority, and the
    // namespace published between rotations carries the second's signature.
    {
        let key_store = kappa_crypto::keystore::KeyStore::new(keys.clone())?;
        let lifecycle = key_store.node_keys()?;
        let candidates = lifecycle.candidates("ed25519")?;
        let current = candidates.current.ok_or("no current key")?;
        assert_eq!(current.anchor().to_string(), third);
        let store = kappa_store_redb::PersistentStore::new(
            kappa_store_redb::PersistentStoreConfig::new(
                tmp.path().join("blobs"),
                tmp.path().join("state.redb"),
                current,
            )
            .requiring_history(),
        )?;
        assert_eq!(store.node_anchor().to_string(), third);
        let oci = kappa_store::namespace::ProtocolId::new("oci")
            .map_err(|e| format!("oci protocol: {e}"))?;
        let ns = store.namespace_resolve("after-rotation", Some(&oci))?;
        let (_, root) = store.epoch_current(&ns)?;
        assert_eq!(
            store.epoch_get(&root)?.signer_anchor().to_string(),
            second,
            "epoch published between rotations"
        );

        // Revocation: neither retired authority keeps its `_root`
        // capability or any delegation it issued, while the current one
        // holds the capability and the root-token delegation.
        use kappa_store::edge::BuiltinRelation::{Capability, Delegation};
        for retired in [&first, &second] {
            assert_eq!(
                root_edges_from(&store, retired, Capability)?,
                0,
                "{retired} capability"
            );
            assert_eq!(
                root_edges_from(&store, retired, Delegation)?,
                0,
                "{retired} delegations"
            );
        }
        assert_eq!(root_edges_from(&store, &third, Capability)?, 1);
        assert_eq!(root_edges_from(&store, &third, Delegation)?, 1);

        // Activation: both transitions, with their witnesses, are published
        // in `_root`, and restored history re-admitted them.
        use kappa_store::traits::{BlobStore, TagStore};
        let root = store.namespace_resolve("_root", None)?;
        let witness = anchor(&WITNESS_SEED)?;
        let origin = store.authority_origin();
        for position in [1u64, 2] {
            let record = store
                .tag_get_raw(&root, &format!("_authority/{position:020}"))?
                .kappa;
            // Decoding re-admits the transition and its witnesses.
            let transition = kappa_store::AuthorityTransition::from_bytes(
                &store.blob_get_in(&root, &record)?,
                &origin,
            )?;
            assert_eq!(
                transition.activation().witnesses[0].assertion.asserter,
                witness,
                "transition {position} was witnessed by the provisioned key"
            );
        }
    }

    // Restart restores the committed authority, its identity and the
    // complete authority state.
    let restarted = start(tmp.path())?;
    assert_identity(&c, &restarted.base(), &third, "p256")?;
    assert_status(&c, &restarted.base(), &third, &[&first, &second])?;
    Ok(())
}
