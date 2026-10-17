use std::process::Command;

use kappa_fixture::{CloseError, FixtureRoot};

use super::node_keys::record_name;
use super::*;
use crate::Signer;
use crate::keystore_dir::Fault;
use crate::keystore_record::generate;
use crate::testing::{key_store, key_store_in};

#[path = "keystore_fault_tests.rs"]
mod faults;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Environment variable carrying a child process's action and directory.
const CHILD: &str = "KAPPA_KEYSTORE_CHILD";
/// Exit status of a child that could not open an owned store.
const CHILD_REFUSED: i32 = 3;
/// Exit status of a child that opened the store.
const CHILD_OPENED: i32 = 4;

/// Relative path of the key store inside its fixture scope.
fn keys() -> &'static Path {
    Path::new("keys")
}

fn pointer(ks: &KeyStore, name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match fs::read_to_string(ks.keys_dir().join(name)) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn entries(path: &Path, prefix: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(path)? {
        let file = entry?.file_name().to_string_lossy().into_owned();
        if file.starts_with(prefix) {
            names.push(file);
        }
    }
    names.sort();
    Ok(names)
}

fn node_records(ks: &KeyStore) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(entries(ks.keys_dir(), NODE_PREFIX)?
        .into_iter()
        .filter_map(|file| file.strip_suffix(".key").map(str::to_owned))
        .collect())
}

/// The first key of a fresh store, through the lifecycle guard.
fn first(ks: &KeyStore) -> Result<crate::SigningAuthority, Box<dyn std::error::Error>> {
    let candidates = ks.node_keys()?.candidates("ed25519")?;
    candidates.cleanup?;
    Ok(candidates.current.ok_or("first key not current")?)
}

/// Run this test binary's `subprocess_entry` with `action` on `dir`.
fn child(action: &str, dir: &Path) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
    Ok(Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "keystore::tests::subprocess_entry",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD, format!("{action}:{}", dir.display()))
        .status()?)
}

/// Entry point of child processes spawned by the tests; a no-op when run
/// as an ordinary test.
#[test]
fn subprocess_entry() -> TestResult {
    let Ok(spec) = std::env::var(CHILD) else {
        return Ok(());
    };
    let (action, dir) = spec.split_once(':').ok_or("malformed child spec")?;
    let dir = PathBuf::from(dir);
    match action {
        "open" => match KeyStore::new(dir) {
            Ok(_) => std::process::exit(CHILD_OPENED),
            Err(CryptoError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                std::process::exit(CHILD_REFUSED)
            }
            Err(error) => Err(error.into()),
        },
        // Stage a successor, then die while activating it: after `current`
        // was renamed to it and before that rename was synchronized.
        "abort-activation" => {
            let ks = KeyStore::new(dir)?;
            let keys = ks.node_keys()?;
            let next = keys.stage_successor("ed25519")?.authority;
            ks.dir().arm_abort(Fault::RenameUnacknowledged, 0);
            keys.settle(next.anchor())?;
            Err("activation completed instead of aborting".into())
        }
        // Die after a staging file holding a new key was synchronized and
        // before it was linked.
        "abort-staging" => {
            let ks = KeyStore::new(dir)?;
            let keys = ks.node_keys()?;
            ks.dir().arm_abort(Fault::Link, 0);
            keys.stage_successor("ed25519")?;
            Err("staging completed instead of aborting".into())
        }
        other => Err(format!("unknown child action {other}").into()),
    }
}

#[test]
fn ownership_is_exclusive_across_handles_and_processes() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let path = root.resolve(keys())?;
    let owner = key_store_in(&root, keys())?;
    assert!(
        matches!(KeyStore::new(path.clone()), Err(CryptoError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock),
        "a second handle opened a locked key store"
    );
    assert_eq!(child("open", &path)?.code(), Some(CHILD_REFUSED));
    drop(owner);
    assert_eq!(child("open", &path)?.code(), Some(CHILD_OPENED));
    key_store_in(&root, keys())?;
    Ok(())
}

/// A key store retains its scope: closing the scope is refused while the
/// store lives, a store moved into a detached worker keeps its directory
/// and its keys usable after every other holder is gone, and the scope is
/// removed once the last store is dropped.
#[test]
fn a_key_store_retains_its_scope_through_every_escaping_holder() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let path = root.resolve(keys())?;
    let ks = key_store_in(&root, keys())?;
    let created = first(&ks)?;
    let root = match root.close() {
        Err(CloseError::InUse(root)) => root,
        other => return Err(format!("scope closed beneath a live key store: {other:?}").into()),
    };
    drop(root);
    assert!(path.is_dir(), "scope removed while its key store lives");

    // The store alone keeps the scope. Moved into a detached worker, it
    // still settles its committed key and signs after the test thread has
    // released every other holder.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let anchor = created.anchor().clone();
    std::thread::spawn(move || {
        let outcome = ks
            .node_keys()
            .and_then(|custody| custody.settle(&anchor))
            .and_then(|settled| {
                settled.cleanup?;
                settled.authority.signer().sign(b"escaped")
            });
        // The receiver is gone only if the test already failed.
        let _ = done_tx.send(outcome);
    });
    let signature = done_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .map_err(|_| "the detached key store did not finish")??;
    assert!(crate::verifier_for("ed25519")?.verify(
        created.signer().public_key(),
        b"escaped",
        &signature
    )?);
    // The worker dropped the last holder when it finished.
    let removed = std::time::Instant::now();
    while path.exists() {
        if removed.elapsed() > std::time::Duration::from_secs(30) {
            return Err("scope survived its last holder".into());
        }
        std::thread::yield_now();
    }
    Ok(())
}

#[test]
fn directory_and_secrets_are_owner_only() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let root = FixtureRoot::temporary()?;
    let path = root.resolve(keys())?;
    fs::create_dir(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    let ks = key_store_in(&root, keys())?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o700);
    first(&ks)?;
    let current = pointer(&ks, "current")?.ok_or("no current pointer")?;
    let mode = fs::metadata(path.join(format!("{current}.key")))?
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "secret mode {mode:o}");
    Ok(())
}

#[test]
fn a_symlinked_store_directory_is_refused() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let real = root.resolve(Path::new("real"))?;
    fs::create_dir(&real)?;
    std::os::unix::fs::symlink(&real, root.resolve(keys())?)?;
    assert!(
        key_store_in(&root, keys()).is_err(),
        "opened a store through a symlink"
    );
    assert!(
        entries(&real, "")?.is_empty(),
        "the link target was written"
    );
    Ok(())
}

#[test]
fn group_or_world_accessible_records_are_refused() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let ks = key_store()?;
    let authority = first(&ks)?;
    let record = ks.keys_dir().join(format!(
        "{}.key",
        record_name(authority.signer().public_key())
    ));
    fs::set_permissions(&record, fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        ks.node_keys()?.settle(authority.anchor()),
        Err(CryptoError::IntegrityFailure { .. })
    ));
    Ok(())
}

#[test]
fn orphaned_staging_files_are_removed_at_open_and_nothing_else() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let path = root.resolve(keys())?;
    drop(key_store_in(&root, keys())?);
    let orphan = path.join(format!(".stage-{}", "ab".repeat(16)));
    fs::write(&orphan, b"secret left by a crash")?;
    let outside = root.resolve(Path::new("outside"))?;
    fs::write(&outside, b"")?;
    std::os::unix::fs::symlink(&outside, path.join(".stage-planted"))?;
    key_store_in(&root, keys())?;
    assert!(!orphan.exists(), "orphaned staging secret survived open");
    assert!(
        path.join(".stage-planted").symlink_metadata().is_ok(),
        "an entry this store never names was removed"
    );
    assert_eq!(fs::read(&outside)?, Vec::<u8>::new());
    Ok(())
}

#[test]
fn named_records_round_trip_and_reject_damage() -> TestResult {
    let ks = key_store()?;
    let signer = ks.load_or_generate_ed25519("vrf")?;
    assert_eq!(
        ks.load_or_generate_ed25519("vrf")?.public_key(),
        signer.public_key()
    );
    for name in ["", "../escape", "/abs", "node-0123", "Upper", "-lead"] {
        assert!(
            matches!(
                ks.load_or_generate_ed25519(name),
                Err(CryptoError::InvalidKey { .. })
            ),
            "{name:?} accepted"
        );
    }
    let path = ks.keys_dir().join("vrf.key");
    let mut bytes = fs::read(&path)?;
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    fs::remove_file(&path)?;
    fs::write(&path, &bytes)?;
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    assert!(matches!(
        ks.load_or_generate_ed25519("vrf"),
        Err(CryptoError::IntegrityFailure { .. })
    ));
    assert!(entries(ks.keys_dir(), ".stage-")?.is_empty());
    Ok(())
}

#[test]
fn records_bind_algorithm_public_key_and_name() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let ks = key_store()?;
    let current = first(&ks)?;
    let name = record_name(current.signer().public_key());
    // An internally consistent record of another key, placed under the
    // current record's name, does not derive that name.
    let (other, _) = generate("ed25519")?;
    let path = ks.keys_dir().join(format!("{name}.key"));
    fs::remove_file(&path)?;
    fs::write(&path, other.encode()?.as_slice())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert!(matches!(
        ks.node_keys()?.settle(current.anchor()),
        Err(CryptoError::IntegrityFailure { .. })
    ));
    // A record whose public key does not derive from its secret.
    let (mut mismatched, _) = generate("ed25519")?;
    let (donor, _) = generate("ed25519")?;
    mismatched.public_key = donor.public_key;
    assert!(matches!(
        crate::keystore_record::KeyRecord::decode(&mismatched.encode()?, "probe"),
        Err(CryptoError::IntegrityFailure { .. })
    ));
    Ok(())
}

#[test]
fn first_key_is_generated_once_and_then_stable() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let ks = key_store_in(&root, keys())?;
    let created = first(&ks)?;
    let again = ks.node_keys()?.candidates("ed25519")?;
    assert_eq!(
        again.current.ok_or("current lost")?.anchor(),
        created.anchor()
    );
    assert_eq!(again.keys.len(), 1);
    let settled = ks.node_keys()?.settle(created.anchor())?;
    settled.cleanup?;
    assert_eq!(settled.authority.anchor(), created.anchor());
    assert_eq!(node_records(&ks)?.len(), 1);
    // Reopening finds the same key: it and `current` were durable.
    drop(ks);
    let reopened = key_store_in(&root, keys())?;
    assert_eq!(first(&reopened)?.anchor(), created.anchor());
    Ok(())
}

#[test]
fn a_missing_pointer_never_creates_an_identity() -> TestResult {
    let ks = key_store()?;
    let existing = first(&ks)?;
    fs::remove_file(ks.keys_dir().join("current"))?;
    let candidates = ks.node_keys()?.candidates("ed25519")?;
    assert!(candidates.current.is_none());
    assert_eq!(candidates.keys.len(), 1, "a new identity was generated");
    assert_eq!(node_records(&ks)?.len(), 1);
    // Committed evidence restores the selection.
    let restored = ks.node_keys()?.settle(existing.anchor())?;
    assert_eq!(restored.authority.anchor(), existing.anchor());
    assert_eq!(
        pointer(&ks, "current")?,
        Some(record_name(existing.signer().public_key()))
    );
    Ok(())
}

#[test]
fn committed_successor_is_promoted_and_uncommitted_discarded() -> TestResult {
    let ks = key_store()?;
    let old = first(&ks)?;
    let keys = ks.node_keys()?;
    let next = keys.stage_successor("ed25519")?;
    next.cleanup?;
    let next = next.authority;
    assert_ne!(next.anchor(), old.anchor());
    assert!(matches!(
        keys.stage_successor("ed25519"),
        Err(CryptoError::KeyGeneration { .. })
    ));
    assert_eq!(
        keys.successor()?
            .ok_or("staged successor missing")?
            .anchor(),
        next.anchor()
    );
    // The backend kept the old authority: the successor is discarded.
    let kept = keys.settle(old.anchor())?;
    kept.cleanup?;
    assert_eq!(kept.authority.anchor(), old.anchor());
    assert!(keys.successor()?.is_none());
    assert_eq!(
        node_records(&ks)?,
        vec![record_name(old.signer().public_key())]
    );

    // The backend committed the successor: it is promoted.
    let next = keys.stage_successor("ed25519")?.authority;
    let settled = keys.settle(next.anchor())?;
    settled.cleanup?;
    assert_eq!(settled.authority.anchor(), next.anchor());
    assert!(keys.successor()?.is_none());
    assert_eq!(
        node_records(&ks)?,
        vec![record_name(next.signer().public_key())]
    );
    assert_eq!(
        keys.settle(next.anchor())?.authority.anchor(),
        next.anchor(),
        "settling again with the same evidence changed the selection"
    );
    Ok(())
}

#[test]
fn a_committed_anchor_without_a_key_is_refused() -> TestResult {
    let ks = key_store()?;
    first(&ks)?;
    let foreign = crate::testing::fixture_authority(42)?;
    assert!(matches!(
        ks.node_keys()?.settle(foreign.anchor()),
        Err(CryptoError::InvalidKey { .. })
    ));
    Ok(())
}

#[test]
fn algorithm_changes_only_through_committed_succession() -> TestResult {
    let ks = key_store()?;
    let old = first(&ks)?;
    let keys = ks.node_keys()?;
    // Configuration asking for another algorithm generates nothing: the
    // committed Ed25519 key stays the candidate.
    let candidates = keys.candidates("p256")?;
    assert_eq!(candidates.keys.len(), 1);
    assert_eq!(keys.settle(old.anchor())?.authority.anchor(), old.anchor());
    let p256 = keys.stage_successor("p256")?.authority;
    assert_eq!(p256.signer().algorithm(), "p256");
    assert_eq!(
        keys.settle(p256.anchor())?.authority.signer().algorithm(),
        "p256"
    );
    let k256 = keys.stage_successor("k256")?.authority;
    assert_eq!(
        keys.settle(k256.anchor())?.authority.signer().algorithm(),
        "k256"
    );
    Ok(())
}

#[test]
fn damaged_pointers_are_reported_and_repaired_by_evidence() -> TestResult {
    let ks = key_store()?;
    let current = first(&ks)?;
    for planted in [
        &b"../escape"[..],
        b"node-",
        b"node-abc",
        b"node-0123456789abcdef0123456789abcdeF",
    ] {
        fs::write(ks.keys_dir().join("current"), planted)?;
        let candidates = ks.node_keys()?.candidates("ed25519")?;
        assert!(candidates.current.is_none(), "{planted:?} accepted");
        assert_eq!(candidates.keys.len(), 1);
        assert!(
            candidates.damaged.iter().any(|d| d.starts_with("current")),
            "{planted:?} not reported"
        );
    }
    let settled = ks.node_keys()?.settle(current.anchor())?;
    settled.cleanup?;
    assert_eq!(
        pointer(&ks, "current")?,
        Some(record_name(current.signer().public_key()))
    );
    Ok(())
}

#[test]
fn a_damaged_unselected_record_neither_blocks_nor_survives_settlement() -> TestResult {
    let ks = key_store()?;
    let old = first(&ks)?;
    let keys = ks.node_keys()?;
    let next = keys.stage_successor("ed25519")?.authority;
    let old_record = ks
        .keys_dir()
        .join(format!("{}.key", record_name(old.signer().public_key())));
    let mut bytes = fs::read(&old_record)?;
    bytes[0] ^= 0xff;
    fs::remove_file(&old_record)?;
    fs::write(&old_record, &bytes)?;
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&old_record, fs::Permissions::from_mode(0o600))?;
    }
    let settled = keys.settle(next.anchor())?;
    settled.cleanup?;
    assert_eq!(settled.authority.anchor(), next.anchor());
    assert!(!old_record.exists(), "damaged retired record survived");
    // A damaged committed key is refused, naming the damage.
    let other = key_store()?;
    let only = first(&other)?;
    let record = other
        .keys_dir()
        .join(format!("{}.key", record_name(only.signer().public_key())));
    fs::write(&record, b"torn")?;
    assert!(matches!(
        other.node_keys()?.settle(only.anchor()),
        Err(CryptoError::IntegrityFailure { .. })
    ));
    Ok(())
}

#[test]
fn concurrent_first_starts_agree_on_one_identity() -> TestResult {
    let ks = key_store()?;
    let barrier = std::sync::Barrier::new(8);
    let anchors = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    ks.node_keys()
                        .and_then(|keys| keys.candidates("ed25519"))
                        .map(|candidates| candidates.current.map(|c| c.anchor().clone()))
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join())
            .collect::<Vec<_>>()
    });
    let mut distinct = Vec::new();
    for anchor in anchors {
        let anchor = anchor
            .map_err(|_| "candidates worker panicked")??
            .ok_or("no current key")?;
        if !distinct.contains(&anchor) {
            distinct.push(anchor);
        }
    }
    assert_eq!(distinct.len(), 1, "concurrent first starts disagreed");
    assert_eq!(node_records(&ks)?.len(), 1);
    Ok(())
}
