use kappa_succinct::{SortedKeySet, TrieError};

#[test]
fn unsorted_construction_normalizes_without_exposing_mutation() {
    let keys = SortedKeySet::from_unsorted(vec![b"b".to_vec(), b"a".to_vec(), b"b".to_vec()]);
    assert_eq!(keys.iter().collect::<Vec<_>>(), vec![b"a".as_slice(), b"b"]);
    assert_eq!(keys.len(), 2);
    assert!(!keys.is_empty());
}

#[test]
fn sorted_admission_rejects_duplicate_and_descending_inputs() -> Result<(), TrieError> {
    assert!(matches!(
        SortedKeySet::try_from_sorted(vec![b"a".to_vec(), b"a".to_vec()]),
        Err(TrieError::Duplicate { index: 1 })
    ));
    assert!(matches!(
        SortedKeySet::try_from_sorted(vec![b"b".to_vec(), b"a".to_vec()]),
        Err(TrieError::NotSorted { index: 1 })
    ));
    assert!(SortedKeySet::try_from_sorted(Vec::new())?.is_empty());
    Ok(())
}
