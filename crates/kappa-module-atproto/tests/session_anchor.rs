//! Sessions and credentials are epoch-governed rows: every transition is
//! a published epoch of the `_sessions` namespace, a revoked pair is
//! refused from the epoch that revoked it, a refresh token is consumed
//! exactly once under concurrency, an account registers exactly once
//! under concurrency, and the account anchor survives session rotation.

use std::sync::Arc;
use std::time::Duration;

use kappa_handler::clock_at;
use kappa_module_atproto::session::{
    SESSIONS_NAMESPACE, SessionConfig, SessionError, SessionStore,
};
use kappa_store::clock::ClockMs;
use kappa_store::traits::KappaStore;
use kappa_store::{Kappa, time::Clock};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn at(ms: i64) -> ClockMs {
    ClockMs::from_raw(ms << 16)
}

type Fixture = (Arc<dyn KappaStore>, Arc<SessionStore>);

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let substrate: Arc<dyn KappaStore> =
        Arc::new(kappa_store_memory::test_support::test_store()?.into_store());
    let clock: Arc<dyn Clock> = Arc::new(clock_at(at(1000))?);
    let store = SessionStore::new(
        Arc::clone(&substrate),
        clock,
        SessionConfig {
            session_ttl_ms: 60_000,
            dpop_clock_skew_secs: 30,
            max_jtis: 128,
        },
    )?;
    Ok((substrate, Arc::new(store)))
}

#[test]
fn account_anchor_survives_session_rotation_and_rejects_substitution() -> TestResult {
    let (substrate, store) = fixture()?;
    store.register_credentials("did:plc:alice", "alice-password")?;
    store.register_credentials("did:plc:bob", "bob-password")?;
    let alice = store.account_anchor("did:plc:alice", "alice-password", at(1002))?;
    let bob = store.account_anchor("did:plc:bob", "bob-password", at(1002))?;
    assert_ne!(alice, bob);
    assert!(matches!(
        store.account_anchor("did:plc:alice", "wrong-password", at(1002)),
        Err(SessionError::AuthenticationRequired)
    ));
    for forged in [&bob, &Kappa::sha256(b"forged anchor")] {
        assert!(matches!(
            store.create_session(
                "did:plc:alice",
                "alice-password",
                "alice.test",
                forged,
                "",
                at(1003)
            ),
            Err(SessionError::KeyMismatch)
        ));
    }
    let sessions = substrate.namespace_resolve(SESSIONS_NAMESPACE, None)?;
    let before = substrate.epoch_current(&sessions)?.0;
    let session = store.create_session(
        "did:plc:alice",
        "alice-password",
        "alice.test",
        &alice,
        "",
        at(1004),
    )?;
    assert_eq!(
        substrate.epoch_current(&sessions)?.0,
        before + 1,
        "a session creation is one published epoch"
    );
    assert_eq!(
        store.validate_token(&session.access_token, at(1005))?,
        Some(("did:plc:alice".into(), alice.clone()))
    );
    let refreshed = store.refresh_session(&session.refresh_token, at(1006))?;
    assert_eq!(substrate.epoch_current(&sessions)?.0, before + 2);
    assert_eq!(refreshed.anchor, alice);
    assert!(
        store
            .validate_token(&session.access_token, at(1007))?
            .is_none(),
        "the replaced access token is refused from the refreshing epoch"
    );
    assert!(matches!(
        store.refresh_session(&session.refresh_token, at(1007)),
        Err(SessionError::InvalidToken)
    ));
    assert_eq!(
        store
            .get_session(&refreshed.access_token, at(1007))?
            .refresh_token,
        refreshed.refresh_token
    );
    // Expiry is decided by the row's deadline.
    assert!(matches!(
        store.get_session(&refreshed.access_token, at(1006 + 60_001)),
        Err(SessionError::ExpiredToken)
    ));
    store.delete_session(&refreshed.access_token)?;
    assert_eq!(substrate.epoch_current(&sessions)?.0, before + 3);
    assert!(matches!(
        store.get_session(&refreshed.access_token, at(1009)),
        Err(SessionError::InvalidToken)
    ));
    assert!(matches!(
        store.refresh_session(&refreshed.refresh_token, at(1009)),
        Err(SessionError::InvalidToken)
    ));
    assert!(matches!(
        store.register_credentials("did:plc:alice", "replacement"),
        Err(SessionError::AccountExists)
    ));
    assert_eq!(
        store.account_anchor("did:plc:alice", "alice-password", at(1011))?,
        alice
    );
    Ok(())
}

/// Run `work` on `n` threads released together; returns each outcome in
/// thread index order.
fn race<T: Send + 'static>(
    n: usize,
    work: impl Fn(usize) -> T + Send + Sync + 'static,
) -> Result<Vec<T>, Box<dyn std::error::Error>> {
    let work = Arc::new(work);
    let barrier = Arc::new(std::sync::Barrier::new(n));
    let (done, completion) = std::sync::mpsc::channel();
    for index in 0..n {
        let (work, barrier, done) = (Arc::clone(&work), Arc::clone(&barrier), done.clone());
        std::thread::spawn(move || {
            barrier.wait();
            let outcome = work(index);
            // A test that stopped waiting reports its own deadline.
            let _ = done.send((index, outcome));
        });
    }
    drop(done);
    let mut outcomes = Vec::with_capacity(n);
    for _ in 0..n {
        outcomes.push(completion.recv_timeout(Duration::from_secs(30))?);
    }
    outcomes.sort_by_key(|(index, _)| *index);
    Ok(outcomes.into_iter().map(|(_, outcome)| outcome).collect())
}

#[test]
fn a_refresh_token_is_consumed_exactly_once_under_concurrency() -> TestResult {
    let (_, store) = fixture()?;
    store.register_credentials("did:plc:carol", "carol-password")?;
    let carol = store.account_anchor("did:plc:carol", "carol-password", at(1002))?;
    let session = store.create_session(
        "did:plc:carol",
        "carol-password",
        "carol.test",
        &carol,
        "",
        at(1003),
    )?;
    let refresh = session.refresh_token.clone();
    let racing = Arc::clone(&store);
    let outcomes = race(8, move |index| {
        racing.refresh_session(&refresh, at(1010 + index as i64))
    })?;
    let succeeded: Vec<_> = outcomes.iter().filter(|outcome| outcome.is_ok()).collect();
    assert_eq!(
        succeeded.len(),
        1,
        "one refresh of one token succeeds: {outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .filter(|outcome| outcome.is_err())
            .all(|outcome| matches!(outcome, Err(SessionError::InvalidToken))),
        "losers are refused as invalid tokens: {outcomes:?}"
    );
    // Refresh racing a deletion: whichever lands second finds no row.
    let winner = succeeded[0].as_ref().map_err(|e| e.to_string())?;
    let (access, refresh) = (winner.access_token.clone(), winner.refresh_token.clone());
    let racing = Arc::clone(&store);
    let outcomes = race(2, move |index| {
        if index == 0 {
            racing.delete_session(&access).map(|()| None)
        } else {
            racing.refresh_session(&refresh, at(1100)).map(Some)
        }
    })?;
    match (&outcomes[0], &outcomes[1]) {
        // The refresh landed first: it consumed the pair, and the deletion
        // finds the rotated token gone, leaving the new pair valid.
        (Err(SessionError::InvalidToken), Ok(Some(refreshed))) => {
            assert!(
                store
                    .validate_token(&refreshed.access_token, at(1101))?
                    .is_some(),
                "the refreshed pair is valid"
            );
        }
        // The deletion landed first: the refresh finds nothing.
        (Ok(None), Err(SessionError::InvalidToken)) => {}
        _ => return Err(format!("refresh/delete race left {outcomes:?}").into()),
    }
    Ok(())
}

#[test]
fn an_account_registers_exactly_once_under_concurrency() -> TestResult {
    let (_, store) = fixture()?;
    let racing = Arc::clone(&store);
    let outcomes = race(6, move |index| {
        racing.register_credentials("did:plc:dave", &format!("password-{index}"))
    })?;
    let winners = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    assert_eq!(winners, 1, "{outcomes:?}");
    assert!(
        outcomes
            .iter()
            .filter(|outcome| outcome.is_err())
            .all(|outcome| matches!(outcome, Err(SessionError::AccountExists))),
        "losers are refused as an existing account: {outcomes:?}"
    );
    // Exactly one password authenticates, and its anchor is stable.
    let accepted: Vec<usize> = (0..6)
        .filter(|index| {
            store
                .account_anchor("did:plc:dave", &format!("password-{index}"), at(2000))
                .is_ok()
        })
        .collect();
    assert_eq!(accepted.len(), 1);
    Ok(())
}
