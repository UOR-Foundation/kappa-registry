#![no_main]
use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::epoch::EpochMutation;
use libfuzzer_sys::fuzz_target;

// Mutation ledgers arrive from peers during replay (FF-8) and are
// validated without panicking (C-6); rejection is a valid outcome.
// `from_canonical` admits only canonical dCBOR, so a ledger it accepts
// re-encodes to exactly the bytes it was decoded from: one ledger, one
// encoding, one content address.
fuzz_target!(|data: &[u8]| {
    let Ok(ledger) = from_canonical::<Vec<EpochMutation>>(data) else {
        return;
    };
    assert_eq!(
        canonical_bytes(&ledger),
        data,
        "an accepted ledger is not in its canonical encoding"
    );
});
