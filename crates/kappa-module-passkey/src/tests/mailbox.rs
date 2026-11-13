//! The Prism mailbox: opaque messages under derived names, newest kept.

use super::fixture;
use crate::mailbox::{self, KEEP, MAX_MESSAGE_BYTES};
use crate::PasskeyError;

const TOPIC: &str = "prism-sync:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const LOCATOR: &str = "sha256:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

#[test]
fn a_topic_keeps_messages_in_order_once_each() {
    let f = fixture();
    let ns = &f.state.mailbox;
    assert!(mailbox::post(&f.store, ns, TOPIC, b"first").unwrap());
    assert!(mailbox::post(&f.store, ns, TOPIC, b"second").unwrap());
    assert!(!mailbox::post(&f.store, ns, TOPIC, b"first").unwrap());
    assert_eq!(
        mailbox::messages(&f.store, ns, TOPIC).unwrap(),
        vec![b"first".to_vec(), b"second".to_vec()]
    );
    assert!(mailbox::post(&f.store, ns, LOCATOR, b"first").unwrap());
    assert_eq!(
        mailbox::messages(&f.store, ns, LOCATOR).unwrap(),
        vec![b"first".to_vec()]
    );
}

#[test]
fn a_topic_keeps_only_its_newest_messages() {
    let f = fixture();
    let ns = &f.state.mailbox;
    for i in 0..KEEP + 3 {
        assert!(mailbox::post(&f.store, ns, TOPIC, format!("message {i}").as_bytes()).unwrap());
    }
    let kept = mailbox::messages(&f.store, ns, TOPIC).unwrap();
    assert_eq!(kept.len(), KEEP);
    assert_eq!(kept[0], b"message 3".to_vec());
    assert_eq!(kept[KEEP - 1], format!("message {}", KEEP + 2).into_bytes());
}

#[test]
fn an_unknown_topic_is_not_found() {
    let f = fixture();
    match mailbox::messages(&f.store, &f.state.mailbox, TOPIC) {
        Err(PasskeyError::UnknownTopic) => {}
        other => panic!("expected UnknownTopic, got {other:?}"),
    }
}

#[test]
fn malformed_topics_and_messages_are_refused() {
    let f = fixture();
    let ns = &f.state.mailbox;
    let long_scheme = format!("{}:{}", "a".repeat(33), "0".repeat(64));
    for topic in [
        "prism-sync",
        "prism-sync:",
        "Prism:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "prism-sync:00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff",
        "prism-sync:0011",
        ":00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        long_scheme.as_str(),
    ] {
        match mailbox::post(&f.store, ns, topic, b"m") {
            Err(PasskeyError::Request(_)) => {}
            other => panic!("topic {topic:?}: expected Request, got {other:?}"),
        }
    }
    match mailbox::post(&f.store, ns, TOPIC, b"") {
        Err(PasskeyError::Request(_)) => {}
        other => panic!("empty message: expected Request, got {other:?}"),
    }
    match mailbox::post(&f.store, ns, TOPIC, &vec![0u8; MAX_MESSAGE_BYTES + 1]) {
        Err(PasskeyError::Request(_)) => {}
        other => panic!("oversized message: expected Request, got {other:?}"),
    }
}
