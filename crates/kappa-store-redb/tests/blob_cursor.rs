//! The native blob cursor retains the committed root it was opened on,
//! never revives after exhaustion, and listing by prefix agrees with it.

mod support;

use kappa_store::{Axis, BlobStore, Kappa, Retirement, VerifiedContent};
use kappa_store_redb::test_support::persistent_store;

use support::{T0, TestResult, at, create, publish, retire};

#[test]
fn native_cursor_retains_old_root_and_never_revives_exhaustion() -> TestResult {
    let store = persistent_store()?;
    let ns = create(store.store(), "cursor")?;
    assert_eq!(store.blob_cursor()?.key()?, None);
    let records: Vec<VerifiedContent> = (0..256u32)
        .map(|number| VerifiedContent::compute(Axis::Sha256, &number.to_be_bytes()))
        .collect::<Result<_, _>>()?;
    let mut expected: Vec<Kappa> = records.iter().map(|r| r.kappa().clone()).collect();
    publish(store.store(), &ns, at(T0 + 1), |e| {
        for record in &records {
            e.blob_put(record)?;
        }
        Ok(())
    })?;
    expected.sort();
    let mut cursor = store.blob_cursor()?;
    assert_eq!(
        retire(store.store(), &ns, &expected[128])?,
        Retirement::Retired
    );
    let middle = expected[128].key_bytes();
    assert_eq!(cursor.seek(&middle)?, Some(middle.as_slice()));
    let first = expected[0].key_bytes();
    assert_eq!(cursor.seek(&first)?, Some(middle.as_slice()));
    for (position, key) in expected[128..].iter().enumerate() {
        assert!(cursor.size_hint() >= (128 - position) as u64);
        let bytes = key.key_bytes();
        assert_eq!(cursor.key()?, Some(bytes.as_slice()));
        cursor.advance()?;
    }
    assert_eq!(cursor.key()?, None);
    assert_eq!(cursor.size_hint(), 0);
    assert_eq!(cursor.seek(&first)?, None);
    assert_eq!(cursor.advance()?, None);
    let mut latest = store.blob_cursor()?;
    assert_ne!(latest.seek(&middle)?, Some(middle.as_slice()));

    let mut request = kappa_types::PageRequest::first(17);
    let mut listed = Vec::new();
    loop {
        let page = store.blob_list(Some(&[0]), &request)?;
        assert!(page.items.len() <= request.limit);
        listed.extend(page.items);
        match page.next_after {
            Some(next) => {
                assert_ne!(request.after.as_ref(), Some(&next));
                request.after = Some(next);
            }
            None => break,
        }
    }
    expected.remove(128);
    assert_eq!(listed, expected);
    for key in &expected {
        let bytes = key.key_bytes();
        let prefix = &bytes[..2];
        let page = store.blob_list(Some(prefix), &kappa_types::PageRequest::first(256))?;
        let oracle: Vec<_> = expected
            .iter()
            .filter(|item| item.key_bytes().starts_with(prefix))
            .cloned()
            .collect();
        assert_eq!(page.items, oracle);
        assert_eq!(page.next_after, None);
    }
    Ok(())
}
