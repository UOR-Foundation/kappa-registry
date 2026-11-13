//! WebAuthn checks for prism/identity/1.
//!
//! The browser hands over the raw ceremony outputs unchanged. Registration is
//! checked against a challenge the registry issued; assertions are checked
//! against a message the verifier rebuilds, with the protocol's six checks in
//! order. Signatures are verified by `p256` (ES256) and `rsa` (RS256); the
//! CBOR the authenticator wrote (attestation object, COSE key) is read by
//! `ciborium`. Nothing here trusts a field the authenticator did not sign
//! without saying why.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ciborium::Value;
use kappa_core::kappa::sha256_raw;
use serde::{Deserialize, Serialize};

use crate::config::{IdentityOrigin, PasskeyConfig};
use crate::error::PasskeyError;

/// COSE algorithm identifiers the protocol accepts.
pub const ES256: i64 = -7;
pub const RS256: i64 = -257;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const MIN_RSA_BITS: usize = 2048;

pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64u(field: &str, text: &str) -> Result<Vec<u8>, PasskeyError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| PasskeyError::Request(format!("{field} is not base64url")))
}

/// Key ID: `b64u(SHA-256(spki))`.
pub fn key_id(spki: &[u8]) -> String {
    b64u(&sha256_raw(spki))
}

/// One WebAuthn assertion, every field base64url as the protocol writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    pub credential: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

fn client_data(raw: &[u8]) -> Result<ClientData, PasskeyError> {
    serde_json::from_slice(raw)
        .map_err(|_| PasskeyError::Request("clientDataJSON is not WebAuthn client data".into()))
}

struct AuthData {
    rp_hash: [u8; 32],
    flags: u8,
    /// Attested credential ID and COSE key, present when the AT flag is set.
    attested: Option<(Vec<u8>, Value)>,
}

fn auth_data(raw: &[u8]) -> Result<AuthData, PasskeyError> {
    let short = || PasskeyError::Request("authenticatorData is truncated".into());
    let head = raw.get(..37).ok_or_else(short)?;
    let mut rp_hash = [0u8; 32];
    rp_hash.copy_from_slice(&head[..32]);
    let flags = head[32];
    if flags & FLAG_AT == 0 {
        return Ok(AuthData {
            rp_hash,
            flags,
            attested: None,
        });
    }
    // 37: AAGUID (16 bytes), then a big-endian u16 credential ID length.
    let length = raw.get(53..55).ok_or_else(short)?;
    let end = 55 + usize::from(u16::from_be_bytes([length[0], length[1]]));
    let credential = raw.get(55..end).ok_or_else(short)?.to_vec();
    let mut rest = raw.get(end..).ok_or_else(short)?;
    let cose: Value = ciborium::de::from_reader(&mut rest)
        .map_err(|_| PasskeyError::Request("the attested COSE key is not CBOR".into()))?;
    Ok(AuthData {
        rp_hash,
        flags,
        attested: Some((credential, cose)),
    })
}

/// Checks 3 to 5: an accepted origin, its rpId hash, and the UP and UV flags.
fn check_origin_rp_flags<'a>(
    config: &'a PasskeyConfig,
    origin: &str,
    auth: &AuthData,
    attested: bool,
) -> Result<&'a IdentityOrigin, PasskeyError> {
    let accepted = config.origin(origin).ok_or(PasskeyError::Origin)?;
    if auth.rp_hash != accepted.rp_hash {
        return Err(PasskeyError::Rp);
    }
    let needed = FLAG_UP | FLAG_UV | if attested { FLAG_AT } else { 0 };
    if auth.flags & needed != needed {
        return Err(PasskeyError::Flags);
    }
    Ok(accepted)
}

/// Raw registration outputs, decoded from base64url.
pub struct Created<'a> {
    pub spki: &'a [u8],
    pub alg: i64,
    pub credential: &'a [u8],
    pub client_data_json: &'a [u8],
    pub authenticator_data: &'a [u8],
    pub attestation_object: &'a [u8],
}

/// Check a `webauthn.create` result and return the identity origin it came
/// from. `consume` takes the challenge out of the issued set; it runs before
/// any other check so a challenge is spent whether or not the rest passes.
///
/// With attestation "none" nothing here is signed: the guarantee is the one
/// every WebAuthn relying party relies on, that the issued challenge came
/// back over TLS from a page on an accepted origin. Every later use of the
/// key is a signature that readers check for themselves.
pub fn check_created(
    config: &PasskeyConfig,
    created: &Created<'_>,
    consume: impl FnOnce(&str) -> bool,
) -> Result<String, PasskeyError> {
    let data = client_data(created.client_data_json)?;
    if !consume(&data.challenge) || data.kind != "webauthn.create" {
        return Err(PasskeyError::Challenge);
    }
    let attestation: Value = ciborium::de::from_reader(created.attestation_object)
        .map_err(|_| PasskeyError::Request("attestationObject is not CBOR".into()))?;
    let attested_auth = map_get(&attestation, |k| k.as_text() == Some("authData"))
        .and_then(Value::as_bytes)
        .ok_or_else(|| PasskeyError::Request("attestationObject has no authData".into()))?;
    if attested_auth.as_slice() != created.authenticator_data {
        return Err(PasskeyError::Request(
            "authenticatorData differs from the attestation object's".into(),
        ));
    }
    let auth = auth_data(created.authenticator_data)?;
    let accepted = check_origin_rp_flags(config, &data.origin, &auth, true)?;
    let (credential, cose) = auth.attested.as_ref().ok_or(PasskeyError::Flags)?;
    if credential.as_slice() != created.credential {
        return Err(PasskeyError::Credential);
    }
    cose_matches(cose, created.spki, created.alg)?;
    Ok(accepted.origin.clone())
}

/// The six assertion checks for `message`, under the key (`alg`, `spki`).
pub fn check_assertion(
    config: &PasskeyConfig,
    alg: i64,
    spki: &[u8],
    message: &[u8],
    assertion: &Assertion,
) -> Result<(), PasskeyError> {
    let client_json = unb64u("clientDataJSON", &assertion.client_data_json)?;
    let authenticator = unb64u("authenticatorData", &assertion.authenticator_data)?;
    let signature = unb64u("signature", &assertion.signature)?;
    let data = client_data(&client_json)?;
    if data.kind != "webauthn.get" || data.challenge != b64u(&sha256_raw(message)) {
        return Err(PasskeyError::Signature);
    }
    let auth = auth_data(&authenticator)?;
    check_origin_rp_flags(config, &data.origin, &auth, false)?;
    let mut signed = authenticator;
    signed.extend_from_slice(&sha256_raw(&client_json));
    verify_signature(alg, spki, &signed, &signature)
}

fn map_get(map: &Value, key: impl Fn(&Value) -> bool) -> Option<&Value> {
    map.as_map()?.iter().find(|(k, _)| key(k)).map(|(_, v)| v)
}

fn cose_get(map: &Value, label: i64) -> Option<&Value> {
    map_get(map, |k| {
        k.as_integer()
            .is_some_and(|i| i128::from(i) == i128::from(label))
    })
}

fn cose_int(map: &Value, label: i64) -> Option<i128> {
    cose_get(map, label)?.as_integer().map(i128::from)
}

fn cose_bytes(map: &Value, label: i64) -> Option<&[u8]> {
    cose_get(map, label)?.as_bytes().map(Vec::as_slice)
}

/// The attested COSE key must be the same public key as `spki`, for `alg`.
fn cose_matches(cose: &Value, spki: &[u8], alg: i64) -> Result<(), PasskeyError> {
    let mismatch = || PasskeyError::Key("the attested key is not the key in spki".into());
    if cose_int(cose, 3) != Some(i128::from(alg)) {
        return Err(PasskeyError::Key(
            "the attested algorithm is not alg".into(),
        ));
    }
    match alg {
        ES256 => {
            let (Some(2), Some(1)) = (cose_int(cose, 1), cose_int(cose, -1)) else {
                return Err(mismatch());
            };
            let (Some(x), Some(y)) = (cose_bytes(cose, -2), cose_bytes(cose, -3)) else {
                return Err(mismatch());
            };
            if x.len() != 32 || y.len() != 32 {
                return Err(mismatch());
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            let attested = p256::PublicKey::from_sec1_bytes(&point).map_err(|_| mismatch())?;
            if attested != p256_key(spki)? {
                return Err(mismatch());
            }
        }
        RS256 => {
            use rsa::traits::PublicKeyParts as _;
            let (Some(3), Some(n), Some(e)) = (
                cose_int(cose, 1),
                cose_bytes(cose, -1),
                cose_bytes(cose, -2),
            ) else {
                return Err(mismatch());
            };
            let key = rsa_key(spki)?;
            if key.n() != &rsa::BigUint::from_bytes_be(n)
                || key.e() != &rsa::BigUint::from_bytes_be(e)
            {
                return Err(mismatch());
            }
        }
        _ => return Err(unsupported()),
    }
    Ok(())
}

fn unsupported() -> PasskeyError {
    PasskeyError::Key("only ES256 (-7) and RS256 (-257) passkeys are accepted".into())
}

fn p256_key(spki: &[u8]) -> Result<p256::PublicKey, PasskeyError> {
    use p256::pkcs8::DecodePublicKey as _;
    p256::PublicKey::from_public_key_der(spki)
        .map_err(|_| PasskeyError::Key("spki is not a P-256 public key".into()))
}

fn rsa_key(spki: &[u8]) -> Result<rsa::RsaPublicKey, PasskeyError> {
    use rsa::pkcs8::DecodePublicKey as _;
    use rsa::traits::PublicKeyParts as _;
    let key = rsa::RsaPublicKey::from_public_key_der(spki)
        .map_err(|_| PasskeyError::Key("spki is not an RSA public key".into()))?;
    if key.size() * 8 < MIN_RSA_BITS {
        return Err(PasskeyError::Key(
            "RSA keys must be at least 2048 bits".into(),
        ));
    }
    Ok(key)
}

/// Check 6: the signature over `signed` under (`alg`, `spki`). ES256
/// signatures are DER, as authenticators write them; high-S is accepted
/// because P-256 ECDSA does not require low-S and authenticators do not
/// normalize.
fn verify_signature(
    alg: i64,
    spki: &[u8],
    signed: &[u8],
    signature: &[u8],
) -> Result<(), PasskeyError> {
    match alg {
        ES256 => {
            use p256::ecdsa::signature::Verifier as _;
            let key = p256::ecdsa::VerifyingKey::from(p256_key(spki)?);
            let sig =
                p256::ecdsa::Signature::from_der(signature).map_err(|_| PasskeyError::Signature)?;
            key.verify(signed, &sig)
                .map_err(|_| PasskeyError::Signature)
        }
        RS256 => {
            use rsa::signature::Verifier as _;
            let key = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(rsa_key(spki)?);
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| PasskeyError::Signature)?;
            key.verify(signed, &sig)
                .map_err(|_| PasskeyError::Signature)
        }
        _ => Err(unsupported()),
    }
}
