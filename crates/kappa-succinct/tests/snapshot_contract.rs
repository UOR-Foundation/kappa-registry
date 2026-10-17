use kappa_cursor::{KappaCursor, TERMINATED};
use kappa_succinct::{IncrementalDigest, TrieConfig, TrieError, TrieIndex};

fn collect(mut cursor: Box<dyn KappaCursor>) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    while cursor.key() != TERMINATED {
        keys.push(cursor.key().to_vec());
        cursor.advance();
    }
    keys
}

#[test]
fn retained_snapshot_binds_mapping_cursor_and_digest_after_rebuild() -> Result<(), TrieError> {
    let index = TrieIndex::new(TrieConfig::default());
    index.build_initial([b"a".as_slice(), b"c"])?;
    index.insert(b"b".to_vec())?;
    let snapshot = index.trie_snapshot()?;
    let expected = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    let mut digest = IncrementalDigest::new();
    for key in &expected {
        digest.insert(key);
    }
    index.delete(b"a".to_vec())?;
    index.insert(b"d".to_vec())?;
    index.rebuild()?;
    assert_eq!(snapshot.keys(), expected.as_slice());
    assert_eq!(collect(snapshot.cursor()), expected);
    assert_eq!(snapshot.logical_digest(), digest.value());
    assert_ne!(collect(index.trie_snapshot()?.cursor()), expected);
    Ok(())
}

#[test]
fn rebuild_does_not_change_logical_snapshot_digest() -> Result<(), TrieError> {
    let index = TrieIndex::new(TrieConfig::default());
    index.insert(b"binary\0key".to_vec())?;
    let before = index.trie_snapshot()?;
    index.rebuild()?;
    let after = index.trie_snapshot()?;
    assert_eq!(before.keys(), after.keys());
    assert_eq!(before.logical_digest(), after.logical_digest());
    assert!(after.generation() > before.generation());
    Ok(())
}

#[test]
fn write_only_overlay_reaches_configured_rebuild_threshold() -> Result<(), TrieError> {
    let config = TrieConfig {
        max_overflow_bound: 3,
        ..TrieConfig::default()
    };
    let index = TrieIndex::new(config);
    index.build_initial([b"base".as_slice()])?;
    for key in [b"a", b"b", b"c"] {
        index.insert(key.to_vec())?;
    }
    assert!(index.should_rebuild()?);
    let digest = index.logical_digest()?;
    index.rebuild()?;
    assert_eq!(index.overflow_size()?, 0);
    assert_eq!(index.logical_digest()?, digest);
    Ok(())
}

#[test]
fn native_snapshot_cursor_merges_and_filters_retained_overlays() -> Result<(), TrieError> {
    let index = TrieIndex::new(TrieConfig::default());
    index.build_initial([b"aa".as_slice(), b"cc", b"ee"])?;
    index.delete(b"cc".to_vec())?;
    index.insert(b"bb".to_vec())?;
    let retained_counter = index.overflow_counter();
    let snapshot = index.trie_snapshot()?;
    let mut cursor = snapshot.cursor();
    index.insert(b"dd".to_vec())?;
    index.rebuild()?;
    let before = retained_counter.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(cursor.key(), b"aa");
    assert_eq!(cursor.seek(b"ab"), b"bb");
    assert_eq!(cursor.advance(), b"ee");
    assert_eq!(cursor.advance(), TERMINATED);
    assert!(retained_counter.load(std::sync::atomic::Ordering::Relaxed) > before);
    assert_eq!(
        index
            .overflow_counter()
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    Ok(())
}

#[test]
fn cursor_owns_captured_state_after_snapshot_and_index_drop() -> Result<(), TrieError> {
    let mut cursor = {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice(), b"cc"])?;
        index.insert(b"bb".to_vec())?;
        index.trie_snapshot()?.cursor()
    };
    assert_eq!(cursor.key(), b"aa");
    assert_eq!(cursor.advance(), b"bb");
    assert_eq!(cursor.advance(), b"cc");
    assert_eq!(cursor.advance(), TERMINATED);
    assert_eq!(cursor.seek(b"aa"), TERMINATED);
    assert_eq!(cursor.advance(), TERMINATED);
    Ok(())
}

#[test]
fn snapshot_navigation_covers_empty_base_and_empty_overlays() -> Result<(), TrieError> {
    let index = TrieIndex::new(TrieConfig::default());
    assert_eq!(index.trie_snapshot()?.cursor().key(), TERMINATED);
    index.insert(b"xx".to_vec())?;
    let mut overlay_only = index.trie_snapshot()?.cursor();
    assert_eq!(overlay_only.key(), b"xx");
    assert_eq!(overlay_only.advance(), TERMINATED);
    index.rebuild()?;
    let mut base_only = index.trie_snapshot()?.cursor();
    assert_eq!(base_only.key(), b"xx");
    assert_eq!(base_only.seek(b"aa"), b"xx");
    assert_eq!(base_only.advance(), TERMINATED);
    index.delete(b"xx".to_vec())?;
    assert_eq!(index.trie_snapshot()?.cursor().key(), TERMINATED);
    index.rebuild()?;
    assert_eq!(index.trie_snapshot()?.cursor().key(), TERMINATED);
    Ok(())
}

#[test]
fn snapshot_seek_preserves_lower_bounds_and_never_moves_backward() -> Result<(), TrieError> {
    let index = TrieIndex::new(TrieConfig::default());
    index.build_initial([b"aa".as_slice(), b"cc", b"ee"])?;
    index.insert(b"bb".to_vec())?;
    index.insert(b"dd".to_vec())?;
    index.insert(b"cc".to_vec())?;
    let mut cursor = index.trie_snapshot()?.cursor();
    assert_eq!(cursor.seek(b"cc"), b"cc");
    assert_eq!(cursor.seek(b"aa"), b"cc");
    assert_eq!(cursor.seek(b"cd"), b"dd");
    assert_eq!(cursor.advance(), b"ee");
    assert_eq!(cursor.seek(b"ff"), TERMINATED);
    assert_eq!(cursor.seek(b"aa"), TERMINATED);
    Ok(())
}

#[test]
fn retained_overlay_reads_do_not_charge_rebuilt_base() -> Result<(), TrieError> {
    use std::sync::atomic::Ordering;
    let index = TrieIndex::new(TrieConfig::default());
    index.build_initial([b"aa".as_slice()])?;
    index.insert(b"bb".to_vec())?;
    let old_counter = index.overflow_counter();
    let retained = index.trie_snapshot()?;
    index.rebuild()?;
    let current_counter = index.overflow_counter();
    assert!(!std::sync::Arc::ptr_eq(&old_counter, &current_counter));
    let before = old_counter.load(Ordering::Relaxed);
    assert_eq!(
        collect(retained.cursor()),
        vec![b"aa".to_vec(), b"bb".to_vec()]
    );
    assert!(old_counter.load(Ordering::Relaxed) > before);
    assert_eq!(current_counter.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn concurrent_retained_readers_keep_each_publications_counter() -> Result<(), TrieError> {
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Barrier};

    let index = TrieIndex::new(TrieConfig::default());
    index.build_initial([b"aa".as_slice()])?;
    let mut retained = Vec::new();
    for key in [b"bb", b"cc", b"dd"] {
        index.insert(key.to_vec())?;
        let snapshot = index.trie_snapshot()?;
        let expected = snapshot.keys().to_vec();
        let counter = index.overflow_counter();
        let before = counter.load(Ordering::Relaxed);
        retained.push((snapshot, expected, counter, before));
        index.rebuild()?;
    }
    let current = index.overflow_counter();
    let start = Arc::new(Barrier::new(retained.len() + 1));
    std::thread::scope(|scope| {
        let workers: Vec<_> = retained
            .iter()
            .map(|(snapshot, expected, counter, before)| {
                let start = start.clone();
                scope.spawn(move || {
                    start.wait();
                    for _ in 0..32 {
                        assert_eq!(&collect(snapshot.cursor()), expected);
                    }
                    assert!(counter.load(Ordering::Relaxed) > *before);
                })
            })
            .collect();
        start.wait();
        // Writers and publication proceed while readers traverse three older
        // captured states. Reader completion must not charge any new base.
        for key in [b"ee", b"ff", b"gg"] {
            index.insert(key.to_vec())?;
            index.rebuild()?;
        }
        for worker in workers {
            worker.join().map_err(|_| TrieError::VerificationFailed)?;
        }
        Ok::<(), TrieError>(())
    })?;
    assert_eq!(current.load(Ordering::Relaxed), 0);
    assert_eq!(index.overflow_counter().load(Ordering::Relaxed), 0);
    for (snapshot, expected, _, _) in retained {
        assert_eq!(snapshot.keys(), expected);
    }
    Ok(())
}
