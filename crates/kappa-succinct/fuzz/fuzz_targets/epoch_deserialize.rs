#![no_main]
use kappa_store::epoch_root::EpochRoot;
use libfuzzer_sys::fuzz_target;

// Epoch roots arrive from federation peers (FF-8) and are structurally
// validated without panicking (C-6); rejection is a valid outcome. A root
// it accepts re-encodes to bytes that decode to the same encoding.
fuzz_target!(|data: &[u8]| {
    let Ok(root) = EpochRoot::from_bytes(data) else {
        return;
    };
    let encoded = root.to_bytes();
    match EpochRoot::from_bytes(&encoded) {
        Ok(reread) => assert_eq!(
            reread.to_bytes(),
            encoded,
            "epoch root encoding is not idempotent"
        ),
        Err(error) => panic!("an encoded epoch root is rejected: {error}"),
    }
});
