use kappa_cursor::{KappaCursor, TERMINATED};
use kappa_succinct::{LoudsDsTrie, TrieConfig, TrieCursor};

#[test]
fn cutover_preserves_prefixes_leaves_and_binary_labels() -> Result<(), kappa_succinct::TrieError> {
    let keys: &[&[u8]] = &[b"a", b"a\0", b"ab", b"ab\xff", b"b", b"b\xff", b"cde"];
    for cutover_depth in [0, 1, 2, 3, 4] {
        let trie = LoudsDsTrie::build(
            &TrieConfig {
                cutover_depth,
                ..Default::default()
            },
            keys.iter().copied(),
        )?;
        let mut cursor = TrieCursor::new(&trie);
        for key in keys {
            assert_eq!(cursor.key(), *key, "cutover={cutover_depth}");
            cursor.advance();
        }
        assert_eq!(cursor.key(), TERMINATED);
        assert_eq!(cursor.advance(), TERMINATED);
        for target in [
            b"a".as_slice(),
            b"a\x01",
            b"ab\xff",
            b"ab\xff\0",
            b"b\xfe",
            b"z",
        ] {
            let mut cursor = TrieCursor::new(&trie);
            let expected = keys
                .iter()
                .copied()
                .find(|key| *key >= target)
                .unwrap_or(TERMINATED);
            assert_eq!(
                cursor.seek(target),
                expected,
                "cutover={cutover_depth}, target={target:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn maximum_length_binary_key_is_complete_and_oversized_key_is_rejected()
-> Result<(), kappa_succinct::TrieError> {
    let key = vec![0; 65];
    for cutover_depth in [0, 1, 2] {
        let config = TrieConfig {
            cutover_depth,
            ..Default::default()
        };
        let trie = LoudsDsTrie::build(&config, [key.as_slice()])?;
        let mut cursor = TrieCursor::new(&trie);
        assert_eq!(cursor.key(), key);
        assert_eq!(cursor.advance(), TERMINATED);
        assert!(LoudsDsTrie::build(&config, [vec![0; 66].as_slice()]).is_err());
    }
    Ok(())
}
