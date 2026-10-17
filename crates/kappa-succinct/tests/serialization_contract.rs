use kappa_succinct::{LoudsDsTrie, TrieConfig, TrieError};

#[test]
fn trailing_bytes_are_not_an_alternate_encoding() -> Result<(), TrieError> {
    let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"aa".as_slice(), b"bb"])?;
    let mut bytes = trie.serialize()?;
    bytes.push(0);
    assert!(LoudsDsTrie::deserialize(&bytes).is_err());
    Ok(())
}

#[test]
fn corrupt_parent_cannot_create_a_cycle_or_out_of_bounds_walk()
-> Result<(), Box<dyn std::error::Error>> {
    let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"aa".as_slice(), b"bb"])?;
    let original = trie.serialize()?;
    for parent in [u32::MAX, u32::try_from(trie.total_nodes())? - 1] {
        let mut bytes = original.clone();
        let last_parent = bytes.len() - 5;
        bytes[last_parent..last_parent + 4].copy_from_slice(&parent.to_le_bytes());
        assert!(LoudsDsTrie::deserialize(&bytes).is_err());
    }
    Ok(())
}

#[test]
fn every_accepted_mutation_is_canonical_and_navigable() -> Result<(), Box<dyn std::error::Error>> {
    let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"a".as_slice(), b"ab", b"bcd"])?;
    let original = trie.serialize()?;
    for position in 0..original.len() {
        let mut bytes = original.clone();
        bytes[position] ^= 0x80;
        let result = std::panic::catch_unwind(|| LoudsDsTrie::deserialize(&bytes));
        assert!(result.is_ok(), "decoder panicked at byte {position}");
        if let Ok(Ok(decoded)) = result {
            assert_eq!(decoded.serialize()?, bytes);
            assert!(decoded.key_count() <= original.len() as u64);
            for ordinal in 0..u32::try_from(decoded.key_count())? {
                assert!(decoded.key_at(ordinal).is_some());
            }
        }
    }
    Ok(())
}
