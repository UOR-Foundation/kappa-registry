//! Unit tests: every protocol error code, against an in-memory store and
//! real P-256 and RSA signatures from the software authenticator.

use std::sync::Arc;

use kappa_core::clock::ntp_lamport::NtpLamportClock;
use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
use kappa_core::store::KappaStore;

use crate::records::KeyRecord;
use crate::service::{self, Registration, Revocation};
use crate::testing::{Authenticator, Ceremony, AT, UP};
use crate::webauthn::Assertion;
use crate::{PasskeyConfig, PasskeyError, PasskeyState};

mod mailbox;

/// An expected error code and the ceremony change that must produce it.
type Case<'a> = (&'static str, Box<dyn Fn(&mut Ceremony) + 'a>);

const ORIGIN: &str = "https://id.uor.foundation";
const NOW: u64 = 1_762_516_800_000;

struct Fixture {
    store: InMemoryStore,
    state: PasskeyState,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("create a temporary store directory");
    let store = InMemoryStore::new(
        MemoryStoreConfig::new(dir.path().join("blobs")),
        Arc::new(NtpLamportClock::new()),
    )
    .expect("create the in-memory store");
    let config = PasskeyConfig::parse(&format!("{ORIGIN},http://localhost:8790"))
        .expect("the test origins parse");
    let state =
        PasskeyState::new(config, &store, "test-node-anchor").expect("bootstrap the namespace");
    Fixture {
        store,
        state,
        _dir: dir,
    }
}

impl Fixture {
    fn register_body(&self, body: serde_json::Value) -> Result<KeyRecord, PasskeyError> {
        let request: Registration =
            serde_json::from_value(body).expect("the body is a registration");
        service::register(
            &self.store,
            &self.state.namespace,
            &self.state.config,
            &self.state.challenges,
            request,
            NOW,
        )
    }

    fn challenge(&self) -> String {
        self.state
            .challenges
            .issue(NOW)
            .expect("issue a challenge")
            .0
    }

    fn register(&self, auth: &Authenticator) -> Result<KeyRecord, PasskeyError> {
        let challenge = self.challenge();
        self.register_body(auth.register(&challenge, ORIGIN, |_| {}))
    }

    fn bind(
        &self,
        new: &Authenticator,
        account: &str,
        binder: &Authenticator,
    ) -> Result<KeyRecord, PasskeyError> {
        let message = format!("prism/identity/bind/1\n{account}\n{}", new.key());
        let assertion = binder.assert(&message, ORIGIN, |_| {});
        self.bind_with(new, account, assertion)
    }

    fn bind_with(
        &self,
        new: &Authenticator,
        account: &str,
        assertion: Assertion,
    ) -> Result<KeyRecord, PasskeyError> {
        let mut body = new.register(&self.challenge(), ORIGIN, |_| {});
        let mut binding = serde_json::to_value(assertion).expect("an assertion serializes");
        binding["account"] = serde_json::Value::String(account.to_string());
        body["binding"] = binding;
        self.register_body(body)
    }

    fn revoke(&self, account: &str, key: &str, assertion: Assertion) -> Result<bool, PasskeyError> {
        let request = Revocation {
            account: account.into(),
            key: key.into(),
            assertion,
        };
        service::revoke(
            &self.store,
            &self.state.namespace,
            &self.state.config,
            &request,
        )
    }
}

fn code<T: std::fmt::Debug>(result: Result<T, PasskeyError>) -> &'static str {
    result.expect_err("the request must be refused").code()
}

#[test]
fn origins_parse_strictly() {
    let config = PasskeyConfig::parse("https://ID.uor.foundation/, http://localhost:8790").unwrap();
    assert_eq!(config.origins().len(), 2);
    assert_eq!(config.origins()[0].origin, "https://id.uor.foundation");
    assert_eq!(config.origins()[0].rp_id, "id.uor.foundation");
    assert_eq!(config.origins()[1].rp_id, "localhost");
    for bad in [
        "http://id.uor.foundation",
        "https://id.uor.foundation/path",
        "id.uor.foundation",
        "https://[::1]",
        "https://a.b:x",
    ] {
        assert!(PasskeyConfig::parse(bad).is_err(), "{bad} must be refused");
    }
}

#[test]
fn first_key_is_its_own_account_and_reads_back() {
    let f = fixture();
    let auth = Authenticator::p256();
    let record = f.register(&auth).expect("register the first key");
    assert_eq!(record.key, auth.key());
    assert_eq!(record.account, auth.key());
    assert_eq!(record.origin, ORIGIN);
    assert_eq!(record.binding, None);
    let bytes = service::credential(&f.store, &f.state.namespace, &auth.credential_id()).unwrap();
    let read: KeyRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(read, record);
}

#[test]
fn rs256_keys_register_and_sign() {
    let f = fixture();
    let first = Authenticator::rsa();
    f.register(&first).expect("register an RSA key");
    let second = Authenticator::p256();
    let bound = f
        .bind(&second, &first.key(), &first)
        .expect("an RSA key binds a device");
    assert_eq!(bound.account, first.key());
}

#[test]
fn a_challenge_is_used_once() {
    let f = fixture();
    let challenge = f.challenge();
    f.register_body(Authenticator::p256().register(&challenge, ORIGIN, |_| {}))
        .unwrap();
    let replay = f.register_body(Authenticator::p256().register(&challenge, ORIGIN, |_| {}));
    assert_eq!(code(replay), "challenge");
}

#[test]
fn a_failed_registration_still_spends_its_challenge() {
    let f = fixture();
    let challenge = f.challenge();
    let auth = Authenticator::p256();
    assert_eq!(
        code(f.register_body(auth.register(&challenge, "https://evil.example", |_| {}))),
        "origin"
    );
    assert_eq!(
        code(f.register_body(auth.register(&challenge, ORIGIN, |_| {}))),
        "challenge"
    );
}

#[test]
fn unknown_and_expired_challenges_are_refused() {
    let f = fixture();
    let auth = Authenticator::p256();
    assert_eq!(
        code(f.register_body(auth.register("bm90LWlzc3VlZA", ORIGIN, |_| {}))),
        "challenge"
    );
    let (challenge, expires) = f.state.challenges.issue(NOW).unwrap();
    assert!(!f.state.challenges.consume(&challenge, expires));
}

#[test]
fn registration_checks_fail_closed_with_their_codes() {
    let f = fixture();
    let auth = Authenticator::p256();
    let other = Authenticator::p256();
    let cases: Vec<Case<'_>> = vec![
        ("challenge", Box::new(|c| c.kind = "webauthn.get".into())),
        (
            "origin",
            Box::new(|c| c.origin = "https://id.uor.foundation.evil".into()),
        ),
        ("rp", Box::new(|c| c.rp_id = "uor.foundation".into())),
        ("flags", Box::new(|c| c.flags = UP | AT)),
        (
            "credential",
            Box::new(|c| c.attested_credential = vec![7; 16]),
        ),
        ("key", Box::new(|c| c.attested_cose = other.cose())),
    ];
    for (expected, edit) in cases {
        let body = auth.register(&f.challenge(), ORIGIN, |c| edit(c));
        assert_eq!(code(f.register_body(body)), expected, "case {expected}");
    }
}

#[test]
fn malformed_requests_are_request_errors() {
    let f = fixture();
    let mut body = Authenticator::p256().register(&f.challenge(), ORIGIN, |_| {});
    body["spki"] = serde_json::Value::String("not base64url!".into());
    assert_eq!(code(f.register_body(body)), "request");
    let mut body = Authenticator::p256().register(&f.challenge(), ORIGIN, |_| {});
    body["alg"] = serde_json::Value::from(-8);
    assert_eq!(code(f.register_body(body)), "key");
}

#[test]
fn a_credential_registers_once() {
    let f = fixture();
    let auth = Authenticator::p256();
    f.register(&auth).unwrap();
    assert_eq!(code(f.register(&auth)), "exists");
}

#[test]
fn a_bound_device_joins_the_account() {
    let f = fixture();
    let first = Authenticator::p256();
    let second = Authenticator::p256();
    let account = f.register(&first).unwrap().account;
    let bound = f.bind(&second, &account, &first).unwrap();
    assert_eq!(bound.account, account);
    assert_eq!(
        bound.binding.as_ref().map(|b| b.credential.clone()),
        Some(first.credential_id())
    );
    let listing = service::account(&f.store, &f.state.namespace, &account).unwrap();
    assert_eq!(listing["keys"].as_array().map(Vec::len), Some(2));
    assert_eq!(listing["revoked"], serde_json::json!([]));
}

#[test]
fn binding_checks_fail_closed_with_their_codes() {
    let f = fixture();
    let first = Authenticator::p256();
    let stranger = Authenticator::p256();
    let account = f.register(&first).unwrap().account;
    f.register(&stranger).unwrap();

    let new = Authenticator::p256();
    let wrong_message = first.assert("prism/identity/bind/1\nsomething else", ORIGIN, |_| {});
    assert_eq!(
        code(f.bind_with(&new, &account, wrong_message)),
        "signature"
    );

    let mut forged = first.assert(
        &format!("prism/identity/bind/1\n{account}\n{}", new.key()),
        ORIGIN,
        |_| {},
    );
    forged.signature = stranger.assert("x", ORIGIN, |_| {}).signature;
    assert_eq!(code(f.bind_with(&new, &account, forged)), "signature");

    assert_eq!(code(f.bind(&new, &account, &stranger)), "binding");

    let no_uv = first.assert(
        &format!("prism/identity/bind/1\n{account}\n{}", new.key()),
        ORIGIN,
        |c| c.flags = UP,
    );
    assert_eq!(code(f.bind_with(&new, &account, no_uv)), "flags");

    let elsewhere = first.assert(
        &format!("prism/identity/bind/1\n{account}\n{}", new.key()),
        ORIGIN,
        |c| c.rp_id = "localhost".into(),
    );
    assert_eq!(code(f.bind_with(&new, &account, elsewhere)), "rp");
}

#[test]
fn a_binding_chain_is_at_most_five_long() {
    let f = fixture();
    let mut binder = Authenticator::p256();
    let account = f.register(&binder).unwrap().account;
    for _ in 0..5 {
        let next = Authenticator::p256();
        f.bind(&next, &account, &binder)
            .expect("chains up to five bind");
        binder = next;
    }
    assert_eq!(
        code(f.bind(&Authenticator::p256(), &account, &binder)),
        "binding"
    );
}

#[test]
fn revocation_takes_a_key_out_and_is_idempotent() {
    let f = fixture();
    let first = Authenticator::p256();
    let second = Authenticator::p256();
    let account = f.register(&first).unwrap().account;
    f.bind(&second, &account, &first).unwrap();
    let message = format!("prism/identity/revoke/1\n{account}\n{}", second.key());

    assert_eq!(
        code(f.revoke(
            &account,
            &second.key(),
            first.assert("prism/identity/revoke/1\nother", ORIGIN, |_| {})
        )),
        "signature"
    );
    assert!(f
        .revoke(
            &account,
            &second.key(),
            first.assert(&message, ORIGIN, |_| {})
        )
        .unwrap());
    assert!(!f
        .revoke(
            &account,
            &second.key(),
            first.assert(&message, ORIGIN, |_| {})
        )
        .unwrap());

    assert_eq!(
        code(service::credential(
            &f.store,
            &f.state.namespace,
            &second.credential_id()
        )),
        "revoked"
    );
    let listing = service::account(&f.store, &f.state.namespace, &account).unwrap();
    assert_eq!(listing["revoked"], serde_json::json!([second.key()]));

    // A revoked key can neither bind a device nor revoke another key.
    assert_eq!(
        code(f.bind(&Authenticator::p256(), &account, &second)),
        "revoked"
    );
    let again = format!("prism/identity/revoke/1\n{account}\n{}", first.key());
    assert_eq!(
        code(f.revoke(
            &account,
            &first.key(),
            second.assert(&again, ORIGIN, |_| {})
        )),
        "revoked"
    );
}

#[test]
fn unknown_lookups_are_typed() {
    let f = fixture();
    let missing = Authenticator::p256();
    assert_eq!(
        code(service::credential(
            &f.store,
            &f.state.namespace,
            &missing.credential_id()
        )),
        "credential"
    );
    assert_eq!(
        code(service::account(
            &f.store,
            &f.state.namespace,
            &missing.key()
        )),
        "account"
    );
    assert_eq!(
        code(service::account(&f.store, &f.state.namespace, "short")),
        "request"
    );
}

#[test]
fn the_namespace_is_never_owned_by_anonymous() {
    let f = fixture();
    let refused = PasskeyState::new(
        PasskeyConfig::default(),
        &f.store as &dyn KappaStore,
        "anonymous",
    );
    assert_eq!(refused.err().map(|e| e.code()), Some("request"));
}
