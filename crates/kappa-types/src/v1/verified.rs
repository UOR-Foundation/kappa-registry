use crate::axis::Axis;
use crate::kappa::{Kappa, KappaParseError};

/// Proof that content has been verified against its content address.
///
/// No public constructor. Obtain via `verify()` or `compute()`.
/// `BlobStore::blob_put` takes this type so unverified content
/// cannot reach the store.
///
/// The content bytes are owned by this struct. They are copied in
/// at construction time (after verification passes) and consumed
/// by the store via `into_parts()`.
pub struct VerifiedContent {
    kappa: Kappa,
    content: Vec<u8>,
    _seal: Seal,
}

/// Proof that a streaming hash computation completed successfully.
///
/// Produced by `streaming_compute_kappa` and `streaming_compute_multi`.
/// Consumed by `upload_complete`. Cannot be constructed outside this
/// crate (private `_seal` field). Move-only (no Clone).
#[derive(Debug)]
pub struct StreamingVerificationProof {
    primary: Kappa,
    additional: Vec<(Axis, Kappa)>,
    _seal: Seal,
}

/// Zero-sized private type preventing external construction.
#[derive(Debug)]
struct Seal;

impl VerifiedContent {
    /// Compute the content address of borrowed bytes under a given axis.
    /// Copies content into the seal. Use `compute_owned` when the
    /// caller can transfer ownership to avoid the copy.
    pub fn compute(axis: Axis, content: &[u8]) -> Result<Self, KappaParseError> {
        let kappa = Kappa::compute(axis, content)?;
        Ok(Self {
            kappa,
            content: content.to_vec(),
            _seal: Seal,
        })
    }

    /// Compute the content address of owned bytes. Zero copy --
    /// the Vec moves into the seal without allocation or memcpy.
    /// This is the hot path for handlers that already own the data.
    pub fn compute_owned(axis: Axis, content: Vec<u8>) -> Result<Self, KappaParseError> {
        let kappa = Kappa::compute(axis, &content)?;
        Ok(Self {
            kappa,
            content,
            _seal: Seal,
        })
    }

    /// Verify that borrowed content matches a claimed kappa.
    /// Copies content into the seal only on match.
    /// Use `verify_owned` when the caller can transfer ownership.
    pub fn verify(claimed: &Kappa, content: &[u8]) -> Result<Self, KappaParseError> {
        let computed = Kappa::compute(claimed.axis(), content)?;
        if computed != *claimed {
            return Err(KappaParseError::DigestMismatch {
                expected: claimed.to_string(),
                computed: computed.to_string(),
                axis: claimed.axis().to_string(),
            });
        }
        Ok(Self {
            kappa: computed,
            content: content.to_vec(),
            _seal: Seal,
        })
    }

    /// Verify that owned content matches a claimed kappa. Zero copy
    /// on success -- the Vec moves into the seal.
    pub fn verify_owned(claimed: &Kappa, content: Vec<u8>) -> Result<Self, KappaParseError> {
        let computed = Kappa::compute(claimed.axis(), &content)?;
        if computed != *claimed {
            return Err(KappaParseError::DigestMismatch {
                expected: claimed.to_string(),
                computed: computed.to_string(),
                axis: claimed.axis().to_string(),
            });
        }
        Ok(Self {
            kappa: computed,
            content,
            _seal: Seal,
        })
    }

    /// Verify from a wire-format kappa string. Parses first. Copies content.
    pub fn verify_str(claimed: &str, content: &[u8]) -> Result<Self, KappaParseError> {
        let kappa = Kappa::parse(claimed)?;
        Self::verify(&kappa, content)
    }

    /// The verified content address.
    pub const fn kappa(&self) -> &Kappa {
        &self.kappa
    }

    /// The verified content bytes.
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// The digest algorithm axis.
    pub const fn axis(&self) -> Axis {
        self.kappa.axis()
    }

    /// Content length in bytes.
    pub const fn len(&self) -> usize {
        self.content.len()
    }

    /// Whether the content is empty.
    pub const fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Consume the seal, returning the kappa and content separately.
    /// Used by `blob_put` implementations that need to take ownership
    /// of the content bytes for storage.
    pub fn into_parts(self) -> (Kappa, Vec<u8>) {
        (self.kappa, self.content)
    }
}

impl StreamingVerificationProof {
    /// Construct a single-axis proof. pub(crate) only.
    pub(crate) const fn single(kappa: Kappa) -> Self {
        Self {
            primary: kappa,
            additional: Vec::new(),
            _seal: Seal,
        }
    }

    /// Construct a multi-axis proof. pub(crate) only.
    pub(crate) const fn multi(primary: Kappa, additional: Vec<(Axis, Kappa)>) -> Self {
        Self {
            primary,
            additional,
            _seal: Seal,
        }
    }

    /// The primary content address.
    pub const fn kappa(&self) -> &Kappa {
        &self.primary
    }

    /// The primary digest axis.
    pub const fn axis(&self) -> Axis {
        self.primary.axis()
    }

    /// Additional axes computed during the streaming operation.
    /// Each entry is (axis, kappa) for a secondary hash.
    pub fn additional(&self) -> &[(Axis, Kappa)] {
        &self.additional
    }

    /// Consume the proof, returning primary kappa and additional kappas.
    pub fn into_parts(self) -> (Kappa, Vec<(Axis, Kappa)>) {
        (self.primary, self.additional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_produces_verified_content() -> Result<(), KappaParseError> {
        let vc = VerifiedContent::compute(Axis::Sha256, b"hello")?;
        assert_eq!(vc.content(), b"hello");
        assert_eq!(vc.axis(), Axis::Sha256);
        assert_eq!(vc.len(), 5);
        assert!(!vc.is_empty());
        Ok(())
    }

    #[test]
    fn compute_owned_zero_copy() -> Result<(), KappaParseError> {
        let data = b"owned data".to_vec();
        let expected_kappa = Kappa::sha256(&data);
        let vc = VerifiedContent::compute_owned(Axis::Sha256, data)?;
        assert_eq!(*vc.kappa(), expected_kappa);
        assert_eq!(vc.content(), b"owned data");
        Ok(())
    }

    #[test]
    fn compute_and_compute_owned_produce_same_kappa() -> Result<(), KappaParseError> {
        let data = b"consistency check";
        let borrowed = VerifiedContent::compute(Axis::Sha256, data)?;
        let owned = VerifiedContent::compute_owned(Axis::Sha256, data.to_vec())?;
        assert_eq!(*borrowed.kappa(), *owned.kappa());
        assert_eq!(borrowed.content(), owned.content());
        Ok(())
    }

    #[test]
    fn verify_accepts_correct_digest() -> Result<(), KappaParseError> {
        let kappa = Kappa::sha256(b"test data");
        let vc = VerifiedContent::verify(&kappa, b"test data")?;
        assert_eq!(*vc.kappa(), kappa);
        Ok(())
    }

    #[test]
    fn verify_rejects_wrong_digest() {
        let kappa = Kappa::sha256(b"original");
        let result = VerifiedContent::verify(&kappa, b"tampered");
        assert!(matches!(
            result,
            Err(KappaParseError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn verify_owned_accepts_correct_digest() -> Result<(), KappaParseError> {
        let data = b"owned verify".to_vec();
        let kappa = Kappa::sha256(&data);
        let vc = VerifiedContent::verify_owned(&kappa, data)?;
        assert_eq!(*vc.kappa(), kappa);
        assert_eq!(vc.content(), b"owned verify");
        Ok(())
    }

    #[test]
    fn verify_owned_rejects_wrong_digest() {
        let kappa = Kappa::sha256(b"original");
        let result = VerifiedContent::verify_owned(&kappa, b"tampered".to_vec());
        assert!(matches!(
            result,
            Err(KappaParseError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn verify_and_verify_owned_produce_same_kappa() -> Result<(), KappaParseError> {
        let data = b"consistency";
        let kappa = Kappa::sha256(data);
        let borrowed = VerifiedContent::verify(&kappa, data)?;
        let owned = VerifiedContent::verify_owned(&kappa, data.to_vec())?;
        assert_eq!(*borrowed.kappa(), *owned.kappa());
        Ok(())
    }

    #[test]
    fn verify_str_parses_and_verifies() -> Result<(), KappaParseError> {
        let kappa = Kappa::sha256(b"test");
        let wire = kappa.to_string();
        let vc = VerifiedContent::verify_str(&wire, b"test")?;
        assert_eq!(*vc.kappa(), kappa);
        Ok(())
    }

    #[test]
    fn into_parts_consumes() -> Result<(), KappaParseError> {
        let vc = VerifiedContent::compute(Axis::Sha256, b"parts test")?;
        let expected_kappa = vc.kappa().clone();
        let (k, data) = vc.into_parts();
        assert_eq!(k, expected_kappa);
        assert_eq!(data, b"parts test");
        Ok(())
    }

    #[test]
    fn empty_content_is_valid() -> Result<(), KappaParseError> {
        let vc = VerifiedContent::compute(Axis::Sha256, b"")?;
        assert!(vc.is_empty());
        assert_eq!(vc.len(), 0);
        Ok(())
    }

    #[test]
    fn streaming_proof_single() {
        let kappa = Kappa::sha256(b"streaming");
        let proof = StreamingVerificationProof::single(kappa.clone());
        assert_eq!(*proof.kappa(), kappa);
        assert!(proof.additional().is_empty());
    }

    #[test]
    fn streaming_proof_multi() {
        let primary = Kappa::sha256(b"multi");
        let secondary = Kappa::blake3(b"multi");
        let proof = StreamingVerificationProof::multi(
            primary.clone(),
            vec![(Axis::Blake3, secondary.clone())],
        );
        assert_eq!(*proof.kappa(), primary);
        assert_eq!(proof.additional().len(), 1);
        assert_eq!(proof.additional()[0].0, Axis::Blake3);
        assert_eq!(proof.additional()[0].1, secondary);
    }

    #[test]
    fn streaming_proof_into_parts() {
        let primary = Kappa::sha256(b"parts");
        let proof = StreamingVerificationProof::single(primary.clone());
        let (k, additional) = proof.into_parts();
        assert_eq!(k, primary);
        assert!(additional.is_empty());
    }
}
