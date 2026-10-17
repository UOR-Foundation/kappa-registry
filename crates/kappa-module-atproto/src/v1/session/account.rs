//! The secret of an account credential row: the salted argon2id password
//! hash and the account's signing secret, encoded as `salt(16) ++
//! hash(32) ++ signing secret(32)`. The backend keeps it at rest under
//! its table key; it is never published as content.

use kappa_crypto::Signer;
use kappa_store::kappa::Kappa;

use super::store::SessionError;

static ARGON2_PARAMS: std::sync::LazyLock<argon2::Params> = std::sync::LazyLock::new(|| {
    argon2::Params::new(19456, 2, 1, Some(32)).expect("hardcoded argon2 params are valid")
});

pub(super) struct AccountSecret {
    salt: [u8; 16],
    hash: [u8; 32],
    signing_secret: [u8; 32],
}

const ACCOUNT_SECRET_LEN: usize = 16 + 32 + 32;

fn argon2() -> argon2::Argon2<'static> {
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        ARGON2_PARAMS.clone(),
    )
}

impl AccountSecret {
    pub(super) fn new(password: &str) -> Result<Self, SessionError> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt)
            .map_err(|e| SessionError::Internal(format!("CSPRNG failed: {e}")))?;
        let mut hash = [0u8; 32];
        argon2()
            .hash_password_into(password.as_bytes(), &salt, &mut hash)
            .map_err(|e| SessionError::Internal(format!("argon2 hash failed: {e}")))?;
        let mut signing_secret = [0u8; 32];
        getrandom::fill(&mut signing_secret)
            .map_err(|e| SessionError::Internal(format!("CSPRNG failed: {e}")))?;
        Ok(Self {
            salt,
            hash,
            signing_secret,
        })
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ACCOUNT_SECRET_LEN);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.hash);
        bytes.extend_from_slice(&self.signing_secret);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, SessionError> {
        if bytes.len() != ACCOUNT_SECRET_LEN {
            return Err(SessionError::Internal(
                "account credential secret has the wrong length".into(),
            ));
        }
        let field = |range: std::ops::Range<usize>| -> &[u8] { &bytes[range] };
        Ok(Self {
            salt: field(0..16)
                .try_into()
                .map_err(|_| SessionError::Internal("salt".into()))?,
            hash: field(16..48)
                .try_into()
                .map_err(|_| SessionError::Internal("hash".into()))?,
            signing_secret: field(48..80)
                .try_into()
                .map_err(|_| SessionError::Internal("signing secret".into()))?,
        })
    }

    pub(super) fn verify(&self, password: &str) -> bool {
        let mut computed = [0u8; 32];
        match argon2().hash_password_into(password.as_bytes(), &self.salt, &mut computed) {
            Ok(()) => {
                use subtle::ConstantTimeEq;
                self.hash.ct_eq(&computed).into()
            }
            Err(_) => false,
        }
    }

    pub(super) fn anchor(&self) -> Result<Kappa, SessionError> {
        let signer = kappa_crypto::ecdsa::P256Signer::from_bytes(&self.signing_secret)
            .map_err(|e| SessionError::Internal(e.to_string()))?;
        Kappa::from_key(signer.algorithm(), signer.public_key())
            .map_err(|e| SessionError::Internal(e.to_string()))
    }
}
