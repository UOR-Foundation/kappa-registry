//! Proof-carrying content: bytes that have been verified against their
//! content address.
//!
//! `VerifiedContent` can only be constructed by computing or verifying
//! a hash. There is no public constructor. Passing unverified bytes to
//! `blob_put` becomes a compile error when the signature changes to
//! accept `VerifiedContent` instead of `(&str, &[u8])`.
//!
//! This is the same closed-constructor pattern used by `AsserterAnchor`:
//! the type proves a property (verification happened) by construction,
//! not by convention.

use crate::kappa::{compute_kappa, verify_kappa, Axis, KappaLabel, LabelError};

/// Proof that a streaming hash computation completed successfully.
///
/// Produced by `streaming_compute_kappa` and `streaming_compute_multi`.
/// Consumed by `upload_complete`. Cannot be constructed outside kappa-core
/// (private `_seal` field). Cannot be cloned (move-only -- one verification
/// per storage operation).
///
/// This is the streaming counterpart to `VerifiedContent`. Where
/// `VerifiedContent` carries verified bytes in memory, this type carries
/// verified kappa-labels without the bytes. The bytes are on disk in a
/// staging file. The proof attests that the streaming hash of those bytes
/// produced these kappa-labels.
///
/// A future developer modifying `upload_complete` cannot bypass
/// verification because the function signature requires this type,
/// and this type can only be produced by the streaming hash functions.
#[derive(Debug)]
pub struct StreamingVerificationProof {
    /// The primary verified kappa-label (client's claimed axis or server-computed).
    primary: String,
    /// Additional kappa-labels from multi-axis computation (mandatory axes).
    additional: Vec<(String, String)>,
    /// Private field preventing external construction.
    _seal: Seal,
}

impl StreamingVerificationProof {
    /// Construct from a single-axis streaming computation result.
    /// Only callable from within kappa-core (pub(crate)).
    pub(crate) fn single(kappa: String) -> Self {
        Self {
            primary: kappa,
            additional: Vec::new(),
            _seal: Seal,
        }
    }

    /// Construct from a multi-axis streaming computation result.
    /// Only callable from within kappa-core (pub(crate)).
    pub(crate) fn multi(primary: String, additional: Vec<(String, String)>) -> Self {
        Self {
            primary,
            additional,
            _seal: Seal,
        }
    }

    /// The primary verified kappa-label.
    pub fn kappa(&self) -> &str {
        &self.primary
    }

    /// The axis string of the primary kappa.
    pub fn axis(&self) -> &str {
        self.primary.split_once(':').map(|(a, _)| a).unwrap_or("sha256")
    }

    /// Additional verified kappa-labels from multi-axis computation.
    /// Each entry is (axis_str, kappa_label).
    pub fn additional(&self) -> &[(String, String)] {
        &self.additional
    }

    /// All additional kappa-label strings (without axis prefix pairs).
    pub fn additional_kappas(&self) -> Vec<String> {
        self.additional.iter().map(|(_, k)| k.clone()).collect()
    }

    /// Consume the proof into its parts: (primary_kappa, additional_kappas).
    /// This is the terminal operation -- the proof is gone after this.
    pub fn into_parts(self) -> (String, Vec<(String, String)>) {
        (self.primary, self.additional)
    }
}

/// Content that has been verified against its content address.
///
/// The only way to obtain this type is through `compute()` or `verify()`.
/// Both perform the hash computation. There is no `unsafe` escape hatch
/// and no `pub` constructor.
///
/// # Closed constructor enforcement
///
/// `VerifiedContent` has a private `_seal` field. External crates cannot
/// construct it. A trybuild compile-fail test should enforce this.
#[derive(Debug)]
pub struct VerifiedContent {
    /// The verified kappa-label (content address).
    label: KappaLabel,
    /// The verified content bytes.
    content: Vec<u8>,
    /// Private field preventing external construction.
    _seal: Seal,
}

/// Zero-sized private type that prevents external construction.
#[derive(Debug)]
struct Seal;

impl VerifiedContent {
    /// Compute the content address of bytes under a given axis.
    ///
    /// The returned `VerifiedContent` proves that `label == hash(content)`
    /// because this function computed both.
    ///
    /// For SHA-1: returns `Err(CollisionDetected)` if sha1-checked
    /// detects a collision attack. Content is never stored.
    pub fn compute(axis: Axis, content: Vec<u8>) -> Result<Self, LabelError> {
        let label = compute_kappa(axis.as_str(), &content)?;
        Ok(Self {
            label,
            content,
            _seal: Seal,
        })
    }

    /// Verify that content matches a claimed kappa-label.
    ///
    /// Re-hashes the content under the label's axis and compares.
    /// Returns `Err` if the label is malformed or the hash does not match.
    pub fn verify(claimed: &str, content: Vec<u8>) -> Result<Self, LabelError> {
        let label = KappaLabel::parse(claimed)?;
        let matches = verify_kappa(claimed, &content)?;
        if !matches {
            let axis = label.axis().to_string();
            return Err(LabelError::DigestMismatch {
                expected: claimed.to_string(),
                computed: compute_kappa(label.axis(), &content)?
                    .as_str()
                    .to_string(),
                axis,
            });
        }
        Ok(Self {
            label,
            content,
            _seal: Seal,
        })
    }

    /// The verified content address.
    pub fn label(&self) -> &KappaLabel {
        &self.label
    }

    /// The kappa-label as a string.
    pub fn kappa(&self) -> &str {
        self.label.as_str()
    }

    /// The verified content bytes.
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// Consume and return the content bytes.
    pub fn into_content(self) -> Vec<u8> {
        self.content
    }

    /// The axis (hash algorithm) used.
    pub fn axis(&self) -> Axis {
        self.label.axis_enum()
    }

    /// Content length in bytes.
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Whether the content is empty (zero bytes).
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}
