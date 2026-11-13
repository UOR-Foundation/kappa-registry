//! The passkey operations, independent of HTTP.
//!
//! Each takes the store and runs blocking; the routes call them inside
//! `spawn_blocking`. Order matters: a challenge is consumed before anything
//! else is checked, and nothing is written until every check has passed.

use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use kappa_core::store::KappaStore;
use kappa_core::types::NamespaceRef;
use serde::Deserialize;

use crate::config::PasskeyConfig;
use crate::error::PasskeyError;
use crate::records::{self, KeyRecord, Stored, KEY_SPEC, MAX_CHAIN, REVOCATION_SPEC};
use crate::webauthn::{self, Assertion, Created, EDDSA};

/// How long an issued challenge stays usable.
pub const CHALLENGE_TTL_MS: u64 = 120_000;
/// Outstanding challenges kept at most, so issuing cannot exhaust memory.
pub const MAX_OUTSTANDING: usize = 65_536;
/// WebAuthn credential IDs are at most 1023 bytes.
const MAX_CREDENTIAL_BYTES: usize = 1023;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Challenges the registry issued and has not yet seen come back.
#[derive(Default)]
pub struct Challenges {
    issued: DashMap<String, u64>,
}

impl Challenges {
    /// Issue a 32-byte random challenge. Returns it and its expiry.
    pub fn issue(&self, now: u64) -> Result<(String, u64), PasskeyError> {
        if self.issued.len() >= MAX_OUTSTANDING {
            self.issued.retain(|_, expires| *expires > now);
            if self.issued.len() >= MAX_OUTSTANDING {
                return Err(PasskeyError::Rate);
            }
        }
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| {
            PasskeyError::Store(kappa_core::StoreError::Io(std::io::Error::other(
                e.to_string(),
            )))
        })?;
        let challenge = webauthn::b64u(&bytes);
        let expires = now + CHALLENGE_TTL_MS;
        self.issued.insert(challenge.clone(), expires);
        Ok((challenge, expires))
    }

    /// Spend `challenge`. True only for an issued, unexpired, unused one.
    pub fn consume(&self, challenge: &str, now: u64) -> bool {
        self.issued
            .remove(challenge)
            .is_some_and(|(_, expires)| expires > now)
    }
}

#[derive(Debug, Deserialize)]
pub struct Registration {
    pub spki: String,
    pub alg: i64,
    pub credential: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    #[serde(default)]
    pub binding: Option<BindingRequest>,
}

#[derive(Debug, Deserialize)]
pub struct BindingRequest {
    pub account: String,
    #[serde(flatten)]
    pub assertion: Assertion,
}

/// A recovery key: its Ed25519 SPKI and either nothing else, to start a new
/// account with it as the first key, or an `account` and a bind assertion
/// over its key ID by a live key of that account.
#[derive(Debug, Deserialize)]
pub struct Recovery {
    #[serde(default)]
    pub account: Option<String>,
    pub spki: String,
    #[serde(default)]
    pub binding: Option<Assertion>,
}

#[derive(Debug, Deserialize)]
pub struct Revocation {
    pub account: String,
    pub key: String,
    pub assertion: Assertion,
}

/// Key and account IDs are kappas, `sha256:` and 64 lowercase hex digits,
/// or, for keys and accounts made under prism/identity/1, base64url SHA-256
/// (exactly 43 characters).
pub fn check_id(field: &str, id: &str) -> Result<(), PasskeyError> {
    let kappa = id.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    });
    let legacy = id.len() == 43 && webauthn::unb64u(field, id).is_ok_and(|b| b.len() == 32);
    if kappa || legacy {
        Ok(())
    } else {
        Err(PasskeyError::Request(format!("{field} is not a key ID")))
    }
}

/// A credential ID: base64url of 1 to 1023 bytes.
pub fn check_credential(credential: &str) -> Result<Vec<u8>, PasskeyError> {
    let bytes = webauthn::unb64u("credential", credential)?;
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(PasskeyError::Request(
            "credential must be 1 to 1023 bytes".into(),
        ));
    }
    Ok(bytes)
}

/// The live record behind `assertion`'s credential, in `account`.
fn signer(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    account: &str,
    assertion: &Assertion,
) -> Result<Option<KeyRecord>, PasskeyError> {
    let Some(Stored { record, .. }) = records::by_credential(store, ns, &assertion.credential)?
    else {
        return Ok(None);
    };
    if record.account != account {
        return Ok(None);
    }
    if records::is_revoked(store, ns, &record.key)? {
        return Err(PasskeyError::Revoked);
    }
    Ok(Some(record))
}

fn verify(
    config: &PasskeyConfig,
    record: &KeyRecord,
    message: &str,
    assertion: &Assertion,
) -> Result<(), PasskeyError> {
    let spki = webauthn::unb64u("spki", &record.spki)?;
    webauthn::check_assertion(config, record.alg, &spki, message.as_bytes(), assertion)
}

/// The live key of `account` that signed `assertion`, checked to sign
/// `prism/identity/bind/1` for `key` and to leave room in the chain.
fn binder(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    config: &PasskeyConfig,
    account: &str,
    key: &str,
    assertion: &Assertion,
) -> Result<KeyRecord, PasskeyError> {
    check_id("account", account)?;
    let binder = signer(store, ns, account, assertion)?.ok_or_else(|| {
        PasskeyError::Binding("the binding key is not a key of this account".into())
    })?;
    if records::chain_length(store, ns, &binder)? + 1 > MAX_CHAIN {
        return Err(PasskeyError::Binding(format!(
            "a binding chain may be at most {MAX_CHAIN} bindings long"
        )));
    }
    verify(
        config,
        &binder,
        &format!("prism/identity/bind/1\n{account}\n{key}"),
        assertion,
    )?;
    Ok(binder)
}

/// Register a passkey: a new account's first key, or a key bound to an
/// account by a bind assertion from one of its live keys (a passkey or a
/// recovery key).
pub fn register(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    config: &PasskeyConfig,
    challenges: &Challenges,
    request: Registration,
    now: u64,
) -> Result<KeyRecord, PasskeyError> {
    let spki = webauthn::unb64u("spki", &request.spki)?;
    let credential = check_credential(&request.credential)?;
    let client_data_json = webauthn::unb64u("clientDataJSON", &request.client_data_json)?;
    let authenticator_data = webauthn::unb64u("authenticatorData", &request.authenticator_data)?;
    let attestation_object = webauthn::unb64u("attestationObject", &request.attestation_object)?;
    let created = Created {
        spki: &spki,
        alg: request.alg,
        credential: &credential,
        client_data_json: &client_data_json,
        authenticator_data: &authenticator_data,
        attestation_object: &attestation_object,
    };
    let origin = webauthn::check_created(config, &created, |c| challenges.consume(c, now))?;
    let key = webauthn::key_id(&spki);

    let (account, binding) = match request.binding {
        None => (key.clone(), None),
        Some(BindingRequest { account, assertion }) => {
            binder(store, ns, config, &account, &key, &assertion)?;
            (account, Some(assertion))
        }
    };

    let record = KeyRecord {
        spec: KEY_SPEC.to_string(),
        key,
        account,
        credential: request.credential,
        alg: request.alg,
        spki: request.spki,
        origin,
        created: now,
        binding,
    };
    records::insert(store, ns, &record)?;
    Ok(record)
}

/// Add a recovery key. The owner keeps its private half outside every
/// device (the recovery code); with it they bind a passkey on a new device,
/// or revoke a lost one, when no device of theirs is at hand. Its credential
/// is its raw 32-byte public key in base64url, so the code alone finds its
/// record.
///
/// With no binding it starts a new account as that account's first key, so
/// an account made this way never depended on any device: the sign-in page
/// makes it, then binds the device's passkey to it with no extra prompt.
/// Nothing is proved by possession here, and nothing needs to be: the key ID
/// is the key's hash, so whoever writes the record first can only name a key
/// whose private half they may not hold, and an account no one can sign for
/// grants nothing. The first key's origin is the identity origin the browser
/// sent (`origin`), which must be one this registry accepts. With a binding,
/// it is bound like any key, by a live key of the account, and takes its
/// binder's origin.
pub fn recovery(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    config: &PasskeyConfig,
    request: Recovery,
    origin: Option<&str>,
    now: u64,
) -> Result<KeyRecord, PasskeyError> {
    let spki = webauthn::unb64u("spki", &request.spki)?;
    let public_key = webauthn::ed25519_public_key(&spki)?;
    let key = webauthn::key_id(&spki);
    let (account, origin, binding) = match (request.account, request.binding) {
        (None, None) => {
            let accepted = origin
                .and_then(|o| config.origin(o))
                .ok_or(PasskeyError::Origin)?;
            (key.clone(), accepted.origin.clone(), None)
        }
        (Some(account), Some(assertion)) => {
            let binder = binder(store, ns, config, &account, &key, &assertion)?;
            (account, binder.origin, Some(assertion))
        }
        _ => {
            return Err(PasskeyError::Request(
                "a recovery key names both an account and a binding, or neither".into(),
            ))
        }
    };
    let record = KeyRecord {
        spec: KEY_SPEC.to_string(),
        key,
        account,
        credential: webauthn::b64u(&public_key),
        alg: EDDSA,
        spki: request.spki,
        origin,
        created: now,
        binding,
    };
    records::insert(store, ns, &record)?;
    Ok(record)
}

/// Revoke `key` in `account`, on a revoke assertion by a live key of it.
/// Returns false when the key was already revoked; repeating is harmless.
pub fn revoke(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    config: &PasskeyConfig,
    request: &Revocation,
) -> Result<bool, PasskeyError> {
    check_id("account", &request.account)?;
    check_id("key", &request.key)?;
    let in_account = records::of_account(store, ns, &request.account)?
        .iter()
        .any(|r| r.key == request.key);
    if !in_account {
        return Err(PasskeyError::Key("the key is not in this account".into()));
    }
    let revoker =
        signer(store, ns, &request.account, &request.assertion)?.ok_or(PasskeyError::Signature)?;
    let message = format!(
        "prism/identity/revoke/1\n{}\n{}",
        request.account, request.key
    );
    verify(config, &revoker, &message, &request.assertion)?;
    let evidence = serde_json::json!({
        "spec": REVOCATION_SPEC,
        "account": request.account,
        "key": request.key,
        "assertion": request.assertion,
    });
    records::revoke(store, ns, &request.key, evidence.to_string().as_bytes())
}

/// The live record for `credential`: `UnknownCredential` or `Revoked` otherwise.
pub fn credential(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    credential: &str,
) -> Result<Vec<u8>, PasskeyError> {
    check_credential(credential)?;
    let stored =
        records::by_credential(store, ns, credential)?.ok_or(PasskeyError::UnknownCredential)?;
    if records::is_revoked(store, ns, &stored.record.key)? {
        return Err(PasskeyError::Revoked);
    }
    Ok(stored.bytes)
}

/// Every key record of `account` and the IDs of those revoked. Revoked
/// records stay listed: a key bound before its binder was revoked is still
/// the account's, and a reader needs the binder's record to check it.
pub fn account(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    account: &str,
) -> Result<serde_json::Value, PasskeyError> {
    check_id("account", account)?;
    let keys = records::of_account(store, ns, account)?;
    if keys.is_empty() {
        return Err(PasskeyError::UnknownAccount);
    }
    let mut revoked = Vec::new();
    for record in &keys {
        if records::is_revoked(store, ns, &record.key)? {
            revoked.push(record.key.clone());
        }
    }
    Ok(serde_json::json!({ "account": account, "keys": keys, "revoked": revoked }))
}
