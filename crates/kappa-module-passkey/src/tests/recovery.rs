//! Recovery keys: an account outlives every device it was made on.

use super::{code, fixture, ORIGIN};
use crate::records::KeyRecord;
use crate::service;
use crate::testing::{Authenticator, RecoveryKey};

#[test]
fn a_recovery_key_brings_a_lost_account_to_a_new_device() {
    let f = fixture();
    let lost = Authenticator::p256();
    let account = f.register(&lost).unwrap().account;
    let recovery = RecoveryKey::new();
    let record = f
        .add_recovery(&recovery, &account, &lost)
        .expect("a passkey adds a recovery key");
    assert_eq!(record.key, recovery.key());
    assert_eq!(record.account, account);
    assert_eq!(record.credential, recovery.credential_id());
    assert_eq!(record.alg, crate::webauthn::EDDSA);
    assert_eq!(record.origin, ORIGIN);
    let bytes = service::credential(&f.store, &f.state.namespace, &recovery.credential_id())
        .expect("the recovery code alone finds its record");
    let read: KeyRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(read, record);

    // The device is gone. The recovery code binds a passkey on a new one...
    let new = Authenticator::p256();
    let message = format!("prism/identity/bind/1\n{account}\n{}", new.key());
    let bound = f
        .bind_with(&new, &account, recovery.assert(&message))
        .expect("a recovery key binds a new device");
    assert_eq!(bound.account, account);

    // ...and takes the lost one out.
    let revoke = format!("prism/identity/revoke/1\n{account}\n{}", lost.key());
    assert!(f
        .revoke(&account, &lost.key(), recovery.assert(&revoke))
        .unwrap());

    // The new device carries on alone: it adds the next recovery key and
    // retires the used one.
    let next = RecoveryKey::new();
    f.add_recovery(&next, &account, &new)
        .expect("the recovered device adds a recovery key");
    let retire = format!("prism/identity/revoke/1\n{account}\n{}", recovery.key());
    assert!(f
        .revoke(
            &account,
            &recovery.key(),
            new.assert(&retire, ORIGIN, |_| {})
        )
        .unwrap());
    let listing = service::account(&f.store, &f.state.namespace, &account).unwrap();
    assert_eq!(listing["keys"].as_array().map(Vec::len), Some(4));
}

#[test]
fn recovery_checks_fail_closed_with_their_codes() {
    let f = fixture();
    let first = Authenticator::p256();
    let stranger = Authenticator::p256();
    let account = f.register(&first).unwrap().account;
    f.register(&stranger).unwrap();
    let recovery = RecoveryKey::new();

    assert_eq!(
        code(f.add_recovery(&recovery, &account, &stranger)),
        "binding"
    );
    let wrong = first.assert("prism/identity/bind/1\nsomething else", ORIGIN, |_| {});
    assert_eq!(code(f.recovery(&recovery, &account, wrong)), "signature");

    let mut body = recovery.recovery(
        &account,
        &first.assert(
            &format!("prism/identity/bind/1\n{account}\n{}", first.key()),
            ORIGIN,
            |_| {},
        ),
    );
    body["spki"] = serde_json::Value::String(crate::webauthn::b64u(&first.spki));
    assert_eq!(code(f.recovery_body(body, Some(ORIGIN))), "key");

    f.add_recovery(&recovery, &account, &first).unwrap();
    assert_eq!(code(f.add_recovery(&recovery, &account, &first)), "exists");

    // A recovery signature is a bare signature over the message: dressed as
    // a WebAuthn assertion, or over another message, it is refused.
    let new = Authenticator::p256();
    let message = format!("prism/identity/bind/1\n{account}\n{}", new.key());
    let mut dressed = recovery.assert(&message);
    dressed.client_data_json = Some("e30".into());
    assert_eq!(code(f.bind_with(&new, &account, dressed)), "signature");
    let other = recovery.assert("prism/identity/bind/1\nsomething else");
    assert_eq!(code(f.bind_with(&new, &account, other)), "signature");

    // A passkey assertion stripped of its WebAuthn fields is not a signature.
    let mut stripped = first.assert(&message, ORIGIN, |_| {});
    stripped.client_data_json = None;
    assert_eq!(code(f.bind_with(&new, &account, stripped)), "signature");
}

#[test]
fn identity_1_account_ids_are_still_accepted() {
    let legacy = crate::webauthn::legacy_key_id(&Authenticator::p256().spki);
    assert_eq!(legacy.len(), 43);
    service::check_id("account", &legacy).expect("a prism/identity/1 ID is an ID");
    service::check_id("account", &Authenticator::p256().key()).expect("a kappa is an ID");
    for bad in [
        "sha256:ABCDEF",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000x",
        "blake3:0000000000000000000000000000000000000000000000000000000000000000",
    ] {
        assert_eq!(code(service::check_id("account", bad)), "request", "{bad}");
    }
}

#[test]
fn a_recovery_key_can_be_an_accounts_first_key() {
    let f = fixture();
    let root = RecoveryKey::new();
    let record = f
        .recovery_body(root.genesis(), Some(ORIGIN))
        .expect("a recovery key starts an account");
    assert_eq!(record.account, root.key());
    assert_eq!(record.key, root.key());
    assert_eq!(record.binding, None);
    assert_eq!(record.origin, ORIGIN);

    // The device's passkey joins with no prompt beyond its own creation.
    let device = Authenticator::p256();
    let account = record.account;
    let message = format!("prism/identity/bind/1\n{account}\n{}", device.key());
    let bound = f
        .bind_with(&device, &account, root.assert(&message))
        .expect("the first key binds the device");
    assert_eq!(bound.account, account);

    // A first key needs an identity origin, and a half-bound request is malformed.
    let other = RecoveryKey::new();
    assert_eq!(code(f.recovery_body(other.genesis(), None)), "origin");
    assert_eq!(
        code(f.recovery_body(other.genesis(), Some("https://evil.example"))),
        "origin"
    );
    let mut half = other.genesis();
    half["account"] = serde_json::Value::String(account.clone());
    assert_eq!(code(f.recovery_body(half, Some(ORIGIN))), "request");
    assert_eq!(
        code(f.recovery_body(root.genesis(), Some(ORIGIN))),
        "exists"
    );
}
