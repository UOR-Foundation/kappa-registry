#![no_main]
use kappa_succinct::LoudsDsTrie;
use libfuzzer_sys::fuzz_target;

// Peer-supplied trie bytes (FF-8). Deserialization never panics (C-6);
// rejection is a valid outcome. A trie it accepts is a trie: it serializes,
// and its serialization deserializes back to the same bytes.
fuzz_target!(|data: &[u8]| {
    let Ok(trie) = LoudsDsTrie::deserialize(data) else {
        return;
    };
    let encoded = match trie.serialize() {
        Ok(encoded) => encoded,
        Err(error) => panic!("an accepted trie does not serialize: {error}"),
    };
    let reread = match LoudsDsTrie::deserialize(&encoded) {
        Ok(reread) => reread,
        Err(error) => panic!("a serialized trie is rejected: {error}"),
    };
    match reread.serialize() {
        Ok(again) => assert_eq!(again, encoded, "trie serialization is not idempotent"),
        Err(error) => panic!("a re-read trie does not serialize: {error}"),
    }
});
