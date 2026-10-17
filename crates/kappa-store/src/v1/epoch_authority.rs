//! Epoch signing authority and its admitted succession history.
//!
//! Two distinct things live here and must not be confused:
//!
//! - **Signing authority.** Only the current [`SigningAuthority`] signs new
//!   epochs. Retiring an authority removes its signing capability from the
//!   store; this type never holds a retired signer.
//! - **Historical verification material.** The origin key and every
//!   transition's outgoing key are retained as public keys so epochs those
//!   authorities legitimately signed remain verifiable. Each historical key
//!   is valid only inside its authority window: from the moment its
//!   authority became effective until the next transition took effect. A
//!   signature by a retired key dated at or after its retirement is never
//!   admitted.
//!
//! The history is one contiguous chain from a persisted origin: every
//! transition is a dual-signed [`Succession`] re-verified against both keys
//! whenever it is admitted or restored, and the chain must start at the
//! origin and end at the current authority.
//!
//! A namespace idle across several rotations publishes its next epoch with
//! the succession path from its head's signer to the current authority,
//! checked by [`kappa_crypto::epoch_verification::check_successor`]; no
//! rotation waits for any namespace.
//!
//! Activation is governed: a transition is admitted only with its
//! [`Activation`], at least one rotation witness countersignature
//! (`kappa_types::rotation_witness`) by a party other than both rotating
//! authorities, valid at the succession's effective time and bound to the
//! exact succession record, the lineage origin and the control namespace
//! the activation is published in. The evidence is persisted with the
//! transition and re-verified whenever the transition is admitted or
//! restored, so recovery admits evidence, never a stored pointer. Standing
//! of each witness against its asserter's revocations and watermarks is
//! [`witness_standing`], which backends check under their activation fence.

use kappa_crypto::SigningAuthority;
use kappa_crypto::epoch_verification::{SuccessionPath, succession_path_bytes};
use kappa_crypto::signed_types::verify_assertion;
use kappa_types::canonical::{canonical_bytes, from_canonical};
use kappa_types::clock::ClockMs;
use kappa_types::{
    ActivationDomain, Axis, IdentityAssertion, Kappa, ROTATION_WITNESS_BASIS,
    ROTATION_WITNESS_FACET, RotationWitness, StoreError, Succession,
};

use crate::identity_ops::resolve_at;
use crate::succession_ops::VerifiedSuccession;
use crate::traits::IdentityStore;

/// Longest algorithm name an authority key may carry.
const MAX_ALGORITHM_BYTES: usize = 64;
/// Longest public key an authority may carry (ML-DSA-65 keys are 1952 bytes).
const MAX_PUBLIC_KEY_BYTES: usize = 8 * 1024;
/// Longest canonical succession record a transition may carry.
const MAX_RECORD_BYTES: usize = 64 * 1024;
/// Most witnesses one activation may carry.
const MAX_WITNESSES: usize = 16;

/// A rotation witness countersignature with the key that verifies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessEvidence {
    pub assertion: IdentityAssertion,
    pub key: AuthorityKey,
}

/// What activates one transition: the control namespace it is published
/// in and its witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activation {
    pub domain: ActivationDomain,
    pub witnesses: Vec<WitnessEvidence>,
}

/// The identity a witness's subject names: SHA-256 of the canonical,
/// dual-signed succession record.
pub fn succession_identity(succession: &Succession) -> Result<Kappa, StoreError> {
    Ok(Kappa::compute(Axis::Sha256, &canonical_bytes(succession))?)
}

/// Every witness of `activation` qualifies for `succession` in the lineage
/// from `origin`, and there is at least one.
fn verify_activation(
    succession: &Succession,
    origin: &Kappa,
    activation: &Activation,
) -> Result<(), StoreError> {
    if activation.witnesses.is_empty() {
        return Err(StoreError::Rejected(
            "authority rotation requires a rotation witness".into(),
        ));
    }
    if activation.witnesses.len() > MAX_WITNESSES {
        return Err(StoreError::Rejected(
            "authority rotation carries too many witnesses".into(),
        ));
    }
    let identity = succession_identity(succession)?;
    let effective = succession.effective_at_ms;
    for witness in &activation.witnesses {
        let assertion = &witness.assertion;
        if assertion.facet != ROTATION_WITNESS_FACET || assertion.basis != ROTATION_WITNESS_BASIS {
            return Err(StoreError::Rejected(
                "witness facet or basis is not the rotation profile".into(),
            ));
        }
        if assertion.subject != identity.to_string() {
            return Err(StoreError::Rejected(
                "witness names another succession".into(),
            ));
        }
        let value: RotationWitness = from_canonical(&assertion.value)?;
        if value.domain() != &activation.domain
            || value.origin() != origin
            || value.succession() != &identity
        {
            return Err(StoreError::Rejected(
                "witness binds another authority domain".into(),
            ));
        }
        if assertion.asserter == succession.old_anchor
            || assertion.asserter == succession.new_anchor
        {
            return Err(StoreError::Rejected(
                "a rotating authority cannot witness itself".into(),
            ));
        }
        if witness.key.anchor() != &assertion.asserter {
            return Err(StoreError::Rejected(
                "witness key does not derive its asserter".into(),
            ));
        }
        verify_assertion(assertion, witness.key.public_key())
            .map_err(|error| StoreError::Rejected(format!("witness signature: {error}")))?;
        if assertion.valid_from_ms > effective
            || assertion
                .valid_until_ms
                .is_some_and(|until| until <= effective)
        {
            return Err(StoreError::Rejected(
                "witness is not valid at the activation time".into(),
            ));
        }
    }
    Ok(())
}

/// A rotation witness countersignature by `signer` for `succession` in the
/// lineage from `origin`, activating in `domain`.
pub fn sign_witness(
    signer: &dyn kappa_crypto::Signer,
    succession: &Succession,
    origin: &Kappa,
    domain: ActivationDomain,
    valid_from_ms: i64,
    valid_until_ms: Option<i64>,
) -> Result<WitnessEvidence, StoreError> {
    let identity = succession_identity(succession)?;
    let key = AuthorityKey::new(signer.algorithm(), signer.public_key())?;
    let value = RotationWitness::new(domain, origin.clone(), identity.clone())?;
    let assertion = kappa_crypto::signed_types::sign_assertion(
        IdentityAssertion {
            asserter: key.anchor().clone(),
            subject: identity.to_string(),
            facet: ROTATION_WITNESS_FACET.to_owned(),
            value: canonical_bytes(&value),
            basis: ROTATION_WITNESS_BASIS.to_owned(),
            valid_from_ms,
            valid_until_ms,
            cose_signature: kappa_types::SignedPayload::empty(),
        },
        signer,
    )
    .map_err(|error| StoreError::Rejected(format!("witness signing: {error}")))?;
    Ok(WitnessEvidence { assertion, key })
}

/// Every witness of `activation` stands at `at_ms`: neither revoked nor
/// invalidated by a watermark of its asserter, as `identity` records them.
pub fn witness_standing(
    identity: &dyn IdentityStore,
    activation: &Activation,
    at_ms: i64,
) -> Result<(), StoreError> {
    for witness in &activation.witnesses {
        let assertion = &witness.assertion;
        let identity_of = Kappa::compute(Axis::Sha256, &canonical_bytes(assertion))?;
        let revocations = identity.revocation_list_by_asserter(&assertion.asserter)?;
        let watermarks = identity.watermark_list_by_asserter(&assertion.asserter)?;
        let resolved = resolve_at(
            &[(identity_of, assertion.clone())],
            &revocations,
            &watermarks,
            at_ms,
        );
        if resolved.valid.is_empty() {
            return Err(StoreError::Rejected(format!(
                "rotation witness of {} is revoked or invalidated",
                assertion.asserter
            )));
        }
    }
    Ok(())
}

fn activation_to_bytes(activation: &Activation) -> Result<Vec<u8>, StoreError> {
    let mut out = Vec::new();
    let mut domain = activation.domain.control.to_vec();
    domain.extend_from_slice(&activation.domain.incarnation);
    put_field(&mut out, &domain)?;
    let count = u32::try_from(activation.witnesses.len())
        .map_err(|_| StoreError::Rejected("witness count exceeds u32".into()))?;
    put_field(&mut out, &count.to_be_bytes())?;
    for witness in &activation.witnesses {
        put_field(&mut out, &canonical_bytes(&witness.assertion))?;
        put_field(&mut out, &witness.key.to_bytes()?)?;
    }
    Ok(out)
}

fn activation_from_bytes(bytes: &[u8]) -> Result<Activation, StoreError> {
    let mut fields = Fields(bytes);
    let domain = fields.next(32)?;
    let (control, incarnation) = domain
        .split_at_checked(16)
        .ok_or_else(|| StoreError::Rejected("activation domain is not 32 bytes".into()))?;
    let domain = ActivationDomain {
        control: control
            .try_into()
            .map_err(|_| StoreError::Rejected("activation control".into()))?,
        incarnation: incarnation
            .try_into()
            .map_err(|_| StoreError::Rejected("activation incarnation".into()))?,
    };
    let count: [u8; 4] = fields
        .next(4)?
        .try_into()
        .map_err(|_| StoreError::Rejected("witness count".into()))?;
    let count = usize::try_from(u32::from_be_bytes(count))
        .map_err(|_| StoreError::Rejected("witness count".into()))?;
    if count > MAX_WITNESSES {
        return Err(StoreError::Rejected(
            "activation carries too many witnesses".into(),
        ));
    }
    let mut witnesses = Vec::with_capacity(count);
    for _ in 0..count {
        let record = fields.next(MAX_RECORD_BYTES)?;
        let assertion: IdentityAssertion = from_canonical(record)?;
        if canonical_bytes(&assertion) != record {
            return Err(StoreError::Rejected(
                "witness record is not canonical".into(),
            ));
        }
        let key = AuthorityKey::from_bytes(fields.next(MAX_RECORD_BYTES)?)?;
        witnesses.push(WitnessEvidence { assertion, key });
    }
    fields.finish()?;
    Ok(Activation { domain, witnesses })
}

/// Why a backend rotation did not take effect, by what the backend knows
/// about its durable state.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityRotationError {
    /// Refused or failed before anything was committed: the outgoing
    /// authority remains the store's committed and installed authority.
    #[error("authority rotation not committed: {0}")]
    NotCommitted(#[source] StoreError),
    /// The durable commit itself failed, so whether the transition is
    /// persisted is unknown. The store refuses to seal further epochs until
    /// it is reopened and its persisted history selects the authority.
    #[error("authority rotation outcome unknown: {0}")]
    Indeterminate(#[source] StoreError),
}

/// Public verification material of one authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityKey {
    algorithm: String,
    public_key: Vec<u8>,
    anchor: Kappa,
}

impl AuthorityKey {
    pub fn new(algorithm: &str, public_key: &[u8]) -> Result<Self, StoreError> {
        if algorithm.len() > MAX_ALGORITHM_BYTES || public_key.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(StoreError::Rejected(
                "authority key exceeds its size bound".into(),
            ));
        }
        Ok(Self {
            anchor: Kappa::from_key(algorithm, public_key)?,
            algorithm: algorithm.to_owned(),
            public_key: public_key.to_vec(),
        })
    }

    fn of(authority: &SigningAuthority) -> Result<Self, StoreError> {
        let signer = authority.signer();
        Self::new(signer.algorithm(), signer.public_key())
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub const fn anchor(&self) -> &Kappa {
        &self.anchor
    }

    /// Persisted form: algorithm and key, each length-prefixed.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StoreError> {
        let mut out = Vec::new();
        put_field(&mut out, self.algorithm.as_bytes())?;
        put_field(&mut out, &self.public_key)?;
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut fields = Fields(bytes);
        let algorithm = text(fields.next(MAX_ALGORITHM_BYTES)?)?;
        let public_key = fields.next(MAX_PUBLIC_KEY_BYTES)?;
        fields.finish()?;
        Self::new(algorithm, public_key)
    }
}

/// One admitted change of epoch signer, with the activation that admitted
/// it.
#[derive(Clone, Debug)]
pub struct AuthorityTransition {
    succession: Succession,
    outgoing: AuthorityKey,
    incoming: AuthorityKey,
    activation: Activation,
}

impl AuthorityTransition {
    /// Admit a transition: both signatures verify under keys that derive
    /// the record's anchors, and its activation qualifies in the lineage
    /// from `origin`.
    fn admit(
        succession: Succession,
        outgoing: AuthorityKey,
        incoming: AuthorityKey,
        activation: Activation,
        origin: &Kappa,
    ) -> Result<Self, StoreError> {
        if succession.old_anchor == succession.new_anchor {
            return Err(StoreError::Rejected(
                "authority transition to the same anchor".into(),
            ));
        }
        let verified = VerifiedSuccession::verify(
            succession,
            &outgoing.algorithm,
            &outgoing.public_key,
            &incoming.algorithm,
            &incoming.public_key,
        )?;
        let succession = verified.into_inner();
        if canonical_bytes(&succession).len() > MAX_RECORD_BYTES {
            return Err(StoreError::Rejected(
                "succession record exceeds its size bound".into(),
            ));
        }
        verify_activation(&succession, origin, &activation)?;
        Ok(Self {
            succession,
            outgoing,
            incoming,
            activation,
        })
    }

    pub const fn activation(&self) -> &Activation {
        &self.activation
    }

    pub const fn succession(&self) -> &Succession {
        &self.succession
    }

    pub const fn outgoing(&self) -> &AuthorityKey {
        &self.outgoing
    }

    pub const fn incoming(&self) -> &AuthorityKey {
        &self.incoming
    }

    /// Persisted form: the canonical record, the outgoing and incoming
    /// keys, and the activation, each length-prefixed. Decoding re-admits
    /// the transition, so a persisted row is never trusted without its
    /// signatures and its witnesses.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StoreError> {
        let mut out = Vec::new();
        put_field(&mut out, &canonical_bytes(&self.succession))?;
        put_field(&mut out, &self.outgoing.to_bytes()?)?;
        put_field(&mut out, &self.incoming.to_bytes()?)?;
        put_field(&mut out, &activation_to_bytes(&self.activation)?)?;
        Ok(out)
    }

    /// Decode and re-admit a persisted transition of the lineage from
    /// `origin`.
    pub fn from_bytes(bytes: &[u8], origin: &Kappa) -> Result<Self, StoreError> {
        let mut fields = Fields(bytes);
        let record = fields.next(MAX_RECORD_BYTES)?;
        let outgoing = AuthorityKey::from_bytes(fields.next(MAX_RECORD_BYTES)?)?;
        let incoming = AuthorityKey::from_bytes(fields.next(MAX_RECORD_BYTES)?)?;
        let activation = activation_from_bytes(
            fields.next(MAX_RECORD_BYTES.saturating_mul(2 * MAX_WITNESSES + 1))?,
        )?;
        fields.finish()?;
        let succession: Succession = from_canonical(record)?;
        if canonical_bytes(&succession) != record {
            return Err(StoreError::Rejected(
                "authority transition record is not canonical".into(),
            ));
        }
        Self::admit(succession, outgoing, incoming, activation, origin)
    }
}

/// The current signing authority with the verified chain of transitions
/// that led to it from the store's origin authority.
#[derive(Clone)]
pub struct EpochAuthority {
    origin: AuthorityKey,
    transitions: Vec<AuthorityTransition>,
    current: SigningAuthority,
}

impl EpochAuthority {
    /// A store whose first authority is `current`.
    pub fn new(current: SigningAuthority) -> Result<Self, StoreError> {
        Ok(Self {
            origin: AuthorityKey::of(&current)?,
            transitions: Vec::new(),
            current,
        })
    }

    /// Restore a persisted history. The chain must start at `origin`, be
    /// contiguous with non-decreasing effective times and consistent keys,
    /// and end at `current`, whose signer must hold the last incoming key.
    pub fn restore(
        origin: AuthorityKey,
        transitions: Vec<AuthorityTransition>,
        current: SigningAuthority,
    ) -> Result<Self, StoreError> {
        let mut head = &origin;
        let mut effective = i64::MIN;
        let mut seen = std::collections::HashSet::from([origin.anchor().key_bytes()]);
        for transition in &transitions {
            if transition.outgoing != *head
                || &transition.succession.old_anchor != head.anchor()
                || transition.succession.effective_at_ms < effective
                || !seen.insert(transition.incoming.anchor().key_bytes())
            {
                return Err(StoreError::Rejected(
                    "persisted authority history is not one chain from its origin".into(),
                ));
            }
            verify_activation(
                &transition.succession,
                origin.anchor(),
                &transition.activation,
            )?;
            head = &transition.incoming;
            effective = transition.succession.effective_at_ms;
        }
        if *head != AuthorityKey::of(&current)? {
            return Err(StoreError::AuthorityMismatch {
                offered: Box::new(current.anchor().clone()),
                current: Box::new(head.anchor().clone()),
            });
        }
        Ok(Self {
            origin,
            transitions,
            current,
        })
    }

    pub const fn origin(&self) -> &AuthorityKey {
        &self.origin
    }

    pub fn transitions(&self) -> &[AuthorityTransition] {
        &self.transitions
    }

    /// The only signer this store signs new epochs with.
    pub const fn current(&self) -> &SigningAuthority {
        &self.current
    }

    pub fn anchor(&self) -> &Kappa {
        self.current.anchor()
    }

    /// The authority after `succession` hands signing from the current
    /// authority to `next`, with the admitted transition to persist.
    ///
    /// The succession must lead from the current anchor to `next`'s, carry
    /// both signatures, use the current signer's key as its outgoing key,
    /// and take effect no earlier than the last transition and no later
    /// than `now`: activation happens at this boundary, so the authority a
    /// publication signs with is always effective at its timestamp.
    /// Backends additionally require it to take effect no earlier than any
    /// published epoch, so no epoch already signed falls outside its
    /// signer's authority window.
    ///
    /// `activation` must qualify (see the module documentation); standing
    /// of its witnesses against revocations is the backend's to check with
    /// [`witness_standing`] under its activation fence.
    pub fn rotate(
        &self,
        next: SigningAuthority,
        succession: VerifiedSuccession,
        activation: Activation,
        now: ClockMs,
    ) -> Result<(Self, AuthorityTransition), StoreError> {
        let record = succession.inner();
        if &record.old_anchor != self.current.anchor() || &record.new_anchor != next.anchor() {
            return Err(StoreError::Conflict(
                "succession does not lead from the current authority to the next".into(),
            ));
        }
        if succession.old_public_key() != self.current.signer().public_key() {
            return Err(StoreError::Conflict(
                "succession outgoing key is not the current signer's".into(),
            ));
        }
        if record.effective_at_ms > now.as_i64() {
            return Err(StoreError::Rejected(
                "authority transition is not yet effective; rotate at its effective time".into(),
            ));
        }
        if self.resolve(next.anchor()).is_some() {
            return Err(StoreError::Rejected(
                "authority anchor already served this store".into(),
            ));
        }
        if self
            .transitions
            .last()
            .is_some_and(|last| record.effective_at_ms < last.succession.effective_at_ms)
        {
            return Err(StoreError::Rejected(
                "authority transition regresses effective time".into(),
            ));
        }
        let transition = AuthorityTransition::admit(
            succession.into_inner(),
            AuthorityKey::of(&self.current)?,
            AuthorityKey::of(&next)?,
            activation,
            self.origin.anchor(),
        )?;
        let mut transitions = self.transitions.clone();
        transitions.push(transition.clone());
        Ok((
            Self {
                origin: self.origin.clone(),
                transitions,
                current: next,
            },
            transition,
        ))
    }

    /// Verification key of `anchor` for an epoch dated `timestamp_ms`:
    /// present only if `anchor` is an authority of this store whose window
    /// contains that time. Windows run from the authority's own effective
    /// time (the origin's from the beginning) up to, excluding, the
    /// effective time of the transition that retired it.
    pub fn verification_key(&self, anchor: &Kappa, timestamp_ms: i64) -> Option<&AuthorityKey> {
        let mut key = &self.origin;
        let mut start = i64::MIN;
        for transition in &self.transitions {
            let end = transition.succession.effective_at_ms;
            if key.anchor() == anchor && start <= timestamp_ms && timestamp_ms < end {
                return Some(key);
            }
            key = &transition.incoming;
            start = end;
        }
        (key.anchor() == anchor && start <= timestamp_ms).then_some(key)
    }

    /// The transitions from `from` to the current authority, in order:
    /// empty when `from` is current, absent when `from` is not an authority
    /// of this store.
    pub fn path_from(&self, from: &Kappa) -> Option<&[AuthorityTransition]> {
        if from == self.current.anchor() {
            return Some(&[]);
        }
        let start = self
            .transitions
            .iter()
            .position(|transition| &transition.succession.old_anchor == from)?;
        Some(&self.transitions[start..])
    }

    /// Key resolution for [`crate::replay::replay_authenticated`] over this
    /// store's own history. Replay proves each key's position; this only
    /// supplies material.
    pub fn resolve(&self, anchor: &Kappa) -> Option<(String, Vec<u8>)> {
        std::iter::once(&self.origin)
            .chain(
                self.transitions
                    .iter()
                    .map(|transition| &transition.incoming),
            )
            .find(|key| key.anchor() == anchor)
            .map(|key| (key.algorithm.clone(), key.public_key.clone()))
    }

    /// Every anchor this store's history retired, oldest first: each
    /// transition's outgoing authority. These keep historical verification
    /// windows and nothing else; no current capability may name them.
    pub fn retired(&self) -> impl Iterator<Item = &Kappa> {
        self.transitions
            .iter()
            .map(|transition| transition.outgoing.anchor())
    }
}

/// Succession evidence for an epoch moving from one authority to another
/// through `transitions`: its records and their canonical path content.
pub struct PathEvidence<'a> {
    links: Vec<Succession>,
    outgoing: Vec<(&'a str, &'a [u8])>,
}

impl<'a> PathEvidence<'a> {
    pub fn new(transitions: &'a [AuthorityTransition]) -> Self {
        Self {
            links: transitions
                .iter()
                .map(|transition| transition.succession.clone())
                .collect(),
            outgoing: transitions
                .iter()
                .map(|transition| {
                    (
                        transition.outgoing.algorithm(),
                        transition.outgoing.public_key(),
                    )
                })
                .collect(),
        }
    }

    pub fn path(&self) -> SuccessionPath<'_> {
        SuccessionPath {
            links: &self.links,
            outgoing: &self.outgoing,
        }
    }

    pub fn content(&self) -> Vec<u8> {
        succession_path_bytes(&self.links)
    }
}

fn put_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), StoreError> {
    let length = u32::try_from(field.len())
        .map_err(|_| StoreError::Rejected("authority record field exceeds u32".into()))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn next(&mut self, maximum: usize) -> Result<&'a [u8], StoreError> {
        let (length, tail) = self
            .0
            .split_first_chunk::<4>()
            .ok_or_else(|| StoreError::Rejected("truncated authority record".into()))?;
        let length = usize::try_from(u32::from_be_bytes(*length))
            .map_err(|_| StoreError::Rejected("authority record field length".into()))?;
        if length > maximum || tail.len() < length {
            return Err(StoreError::Rejected(
                "authority record field out of bounds".into(),
            ));
        }
        let (value, tail) = tail.split_at(length);
        self.0 = tail;
        Ok(value)
    }

    fn finish(self) -> Result<(), StoreError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(StoreError::Rejected(
                "trailing bytes after authority record".into(),
            ))
        }
    }
}

fn text(bytes: &[u8]) -> Result<&str, StoreError> {
    std::str::from_utf8(bytes)
        .map_err(|_| StoreError::Rejected("authority algorithm is not UTF-8".into()))
}

#[cfg(test)]
#[path = "epoch_authority_tests.rs"]
mod tests;
