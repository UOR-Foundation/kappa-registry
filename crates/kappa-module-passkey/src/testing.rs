//! A software authenticator for tests: real P-256 and RSA keys producing
//! WebAuthn-shaped outputs (client data, authenticator data, attestation
//! object with fmt "none", DER and PKCS#1 signatures). Built only for tests
//! and the `testing` feature, never in a release binary.

use ciborium::Value;
use kappa_core::kappa::sha256_raw;
use serde_json::json;

use crate::webauthn::{b64u, key_id, Assertion, ES256, RS256};

pub const UP: u8 = 0x01;
pub const UV: u8 = 0x04;
pub const AT: u8 = 0x40;

enum Key {
    P256(p256::ecdsa::SigningKey),
    Rsa(Box<rsa::pkcs1v15::SigningKey<rsa::sha2::Sha256>>),
}

/// One passkey on one software authenticator.
pub struct Authenticator {
    pub alg: i64,
    pub credential: Vec<u8>,
    pub spki: Vec<u8>,
    cose: Value,
    key: Key,
}

/// The parts of one ceremony a test may change before it is signed.
pub struct Ceremony {
    pub kind: String,
    pub challenge: String,
    pub origin: String,
    pub rp_id: String,
    pub flags: u8,
    /// The credential ID written into attested credential data.
    pub attested_credential: Vec<u8>,
    /// The COSE key written into attested credential data.
    pub attested_cose: Value,
}

fn random_credential() -> Vec<u8> {
    let mut credential = vec![0u8; 16];
    getrandom::fill(&mut credential).expect("the OS random source is available in tests");
    credential
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

fn int(i: i64) -> Value {
    Value::Integer(i.into())
}

impl Authenticator {
    /// A P-256 (ES256) passkey, as every current platform authenticator makes.
    pub fn p256() -> Self {
        use p256::elliptic_curve::Generate as _;
        use p256::pkcs8::EncodePublicKey as _;
        let signing = p256::ecdsa::SigningKey::try_generate_from_rng(&mut rand_core::UnwrapErr(
            getrandom::SysRng,
        ))
        .expect("key generation from the OS random source is infallible");
        let verifying = signing.verifying_key();
        let point = verifying.to_sec1_bytes();
        let spki = verifying
            .to_public_key_der()
            .expect("a P-256 key encodes as SPKI")
            .as_bytes()
            .to_vec();
        let cose = Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(ES256)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(point[1..33].to_vec())),
            (int(-3), Value::Bytes(point[33..65].to_vec())),
        ]);
        Self {
            alg: ES256,
            credential: random_credential(),
            spki,
            cose,
            key: Key::P256(signing),
        }
    }

    /// A 2048-bit RSA (RS256) passkey, as older Windows Hello makes.
    pub fn rsa() -> Self {
        use rsa::pkcs8::EncodePublicKey as _;
        use rsa::traits::PublicKeyParts as _;
        let private = rsa::RsaPrivateKey::new(&mut rand_core_06::OsRng, 2048)
            .expect("RSA key generation from the OS random source succeeds");
        let public = private.to_public_key();
        let spki = public
            .to_public_key_der()
            .expect("an RSA key encodes as SPKI")
            .as_bytes()
            .to_vec();
        let cose = Value::Map(vec![
            (int(1), int(3)),
            (int(3), int(RS256)),
            (int(-1), Value::Bytes(public.n().to_bytes_be())),
            (int(-2), Value::Bytes(public.e().to_bytes_be())),
        ]);
        let signing = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private);
        Self {
            alg: RS256,
            credential: random_credential(),
            spki,
            cose,
            key: Key::Rsa(Box::new(signing)),
        }
    }

    pub fn key(&self) -> String {
        key_id(&self.spki)
    }

    pub fn credential_id(&self) -> String {
        b64u(&self.credential)
    }

    /// The COSE key this authenticator attests.
    pub fn cose(&self) -> Value {
        self.cose.clone()
    }

    fn ceremony(&self, kind: &str, challenge: String, origin: &str, flags: u8) -> Ceremony {
        let rp_id = origin
            .split_once("://")
            .map_or(origin, |(_, rest)| rest)
            .split(':')
            .next()
            .unwrap_or_default()
            .to_string();
        Ceremony {
            kind: kind.to_string(),
            challenge,
            origin: origin.to_string(),
            rp_id,
            flags,
            attested_credential: self.credential.clone(),
            attested_cose: self.cose.clone(),
        }
    }

    fn client_data(ceremony: &Ceremony) -> Vec<u8> {
        json!({
            "type": ceremony.kind,
            "challenge": ceremony.challenge,
            "origin": ceremony.origin,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes()
    }

    fn authenticator_data(ceremony: &Ceremony) -> Vec<u8> {
        let mut data = sha256_raw(ceremony.rp_id.as_bytes()).to_vec();
        data.push(ceremony.flags);
        data.extend_from_slice(&0u32.to_be_bytes());
        if ceremony.flags & AT != 0 {
            data.extend_from_slice(&[0u8; 16]);
            let length = u16::try_from(ceremony.attested_credential.len())
                .expect("test credentials are shorter than 64 KiB");
            data.extend_from_slice(&length.to_be_bytes());
            data.extend_from_slice(&ceremony.attested_credential);
            data.extend_from_slice(&cbor(&ceremony.attested_cose));
        }
        data
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.key {
            Key::P256(key) => {
                use p256::ecdsa::signature::Signer as _;
                let signature: p256::ecdsa::Signature = key.sign(message);
                signature.to_der().as_bytes().to_vec()
            }
            Key::Rsa(key) => {
                use rsa::signature::{SignatureEncoding as _, Signer as _};
                key.sign(message).to_vec()
            }
        }
    }

    /// A `/passkey/register` body for `challenge` from `origin`, after `edit`.
    pub fn register(
        &self,
        challenge: &str,
        origin: &str,
        edit: impl FnOnce(&mut Ceremony),
    ) -> serde_json::Value {
        let mut ceremony = self.ceremony(
            "webauthn.create",
            challenge.to_string(),
            origin,
            UP | UV | AT,
        );
        edit(&mut ceremony);
        let client_data = Self::client_data(&ceremony);
        let auth = Self::authenticator_data(&ceremony);
        let attestation = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(Vec::new())),
            (Value::Text("authData".into()), Value::Bytes(auth.clone())),
        ]);
        json!({
            "spki": b64u(&self.spki),
            "alg": self.alg,
            "credential": self.credential_id(),
            "clientDataJSON": b64u(&client_data),
            "authenticatorData": b64u(&auth),
            "attestationObject": b64u(&cbor(&attestation)),
            "transports": ["internal"],
            "binding": null,
        })
    }

    /// An assertion over `message` from `origin`, after `edit`.
    pub fn assert(
        &self,
        message: &str,
        origin: &str,
        edit: impl FnOnce(&mut Ceremony),
    ) -> Assertion {
        let challenge = b64u(&sha256_raw(message.as_bytes()));
        let mut ceremony = self.ceremony("webauthn.get", challenge, origin, UP | UV);
        edit(&mut ceremony);
        let client_data = Self::client_data(&ceremony);
        let auth = Self::authenticator_data(&ceremony);
        let mut signed = auth.clone();
        signed.extend_from_slice(&sha256_raw(&client_data));
        Assertion {
            credential: self.credential_id(),
            client_data_json: b64u(&client_data),
            authenticator_data: b64u(&auth),
            signature: b64u(&self.sign(&signed)),
        }
    }
}
