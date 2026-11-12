use rekindle_aead::BulkAead;
use rekindle_aead::aes_gcm::AesGcmKey;

/// The AEAD context of a table row: the table's context bound to the
/// row's key, so a ciphertext authenticates only under the key it was
/// written at and cannot be moved between rows of one table. Every
/// encrypted row of every table is written and read through this.
pub(crate) fn bound(context: &str, key: &[u8]) -> String {
    format!("{context}:{}", hex::encode(key))
}

/// Bytes [`bound`] allocates for a key of `key_len` bytes: the key's hex
/// encoding, then the context, separator and that encoding. What a metered
/// caller charges before it builds the context.
pub(crate) const fn bound_allocation(context: &str, key_len: usize) -> u64 {
    (context.len() + 1 + 4 * key_len) as u64
}

pub struct TableEncryptor {
    key: AesGcmKey,
    ns_key_bytes: zeroize::Zeroizing<[u8; 32]>,
}

#[derive(Debug)]
pub enum EncryptionError {
    KeyInit,
    SealFailed,
    AuthFailed,
    TruncatedValue,
    Entropy(getrandom::Error),
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyInit => write!(f, "AEAD key initialization failed"),
            Self::SealFailed => write!(f, "AEAD seal failed"),
            Self::AuthFailed => write!(f, "AEAD authentication failed"),
            Self::TruncatedValue => write!(f, "stored value too short for tag"),
            Self::Entropy(error) => write!(f, "table encryption entropy: {error}"),
        }
    }
}

impl std::error::Error for EncryptionError {}

impl TableEncryptor {
    pub fn new(ns_key: &[u8; 32]) -> Result<Self, EncryptionError> {
        let aes_key = AesGcmKey::new(ns_key).map_err(|_| EncryptionError::KeyInit)?;
        Ok(Self {
            key: aes_key,
            ns_key_bytes: zeroize::Zeroizing::new(*ns_key),
        })
    }

    pub fn hmac_key(&self, plaintext_key: &str) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.ns_key_bytes);
        hasher.update(plaintext_key.as_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }

    pub fn encrypt_value(
        &self,
        plaintext_key: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let mut nonce = vec![0u8; self.key.nonce_len()];
        getrandom::fill(&mut nonce).map_err(EncryptionError::Entropy)?;
        let mut ciphertext = vec![0u8; value.len()];
        let mut tag = [0u8; 16];
        self.key
            .seal_detached(
                &nonce,
                plaintext_key.as_bytes(),
                value,
                &mut ciphertext,
                &mut tag,
            )
            .map_err(|_| EncryptionError::SealFailed)?;
        let mut result = Vec::with_capacity(nonce.len() + 16 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&tag);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt_value(
        &self,
        plaintext_key: &str,
        stored: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let nonce_len = self.key.nonce_len();
        if stored.len() < nonce_len + 16 {
            return Err(EncryptionError::TruncatedValue);
        }
        let nonce = &stored[..nonce_len];
        let tag = &stored[nonce_len..nonce_len + 16];
        let ciphertext = &stored[nonce_len + 16..];
        let mut plaintext = vec![0u8; ciphertext.len()];
        self.key
            .open_detached(
                nonce,
                plaintext_key.as_bytes(),
                ciphertext,
                tag,
                &mut plaintext,
            )
            .map_err(|_| EncryptionError::AuthFailed)?;
        Ok(plaintext)
    }
}
