use std::sync::{PoisonError, RwLock};

use kappa_types::identity::{DegradeReason, ProbeResult, TrustPosition};
use kappa_types::kappa::Kappa;

use crate::keystore::{NodeKeys, Settlement, Staged};
use crate::{CryptoError, Signer, SigningAuthority};

/// A registry node's cryptographic identity: the owner of the node's live
/// signing authority, bound to the key store that holds its key.
///
/// - **Acquisition.** An identity is built only from a key store
///   [`Settlement`], the authority that store settled to from the backend's
///   committed history, and records which store that was. A change installs
///   only a [`Successor`] taken from the same store's [`Staged`] or
///   [`Settlement`], and runs only under that store's lifecycle guard;
///   anything else is refused with `CustodyMismatch`.
/// - **Use.** Signing goes through [`NodeIdentity::sign`] or
///   [`NodeIdentity::with_authority`], which lend an [`AuthorityView`] for
///   one operation; the view's signer is a borrow, so nothing obtained
///   from the identity retains a signing capability past it.
///   [`NodeIdentity::transition`] returns the installed anchor, not the
///   installed signer.
/// - **Unavailability.** A change whose backend outcome is unknown leaves
///   the identity unresolved; a live authority found to differ from the
///   committed one leaves it diverged; a change that panicked leaves it
///   interrupted. In each, no authority signs or names the node,
///   [`NodeIdentity::status`] reports which, and only a restart, whose
///   persisted backend history selects the authority, restores signing.
///
/// The key store guard itself holds the private keys: its holder can read
/// them, which is why custody, not this type, is the boundary that admits
/// changes.
pub struct NodeIdentity {
    state: RwLock<State>,
    position: RwLock<TrustPosition>,
    /// [`crate::keystore::KeyStore`] holding the live authority's key.
    custodian: u64,
    /// Operations that have reached shared acquisition of the authority,
    /// so a test can establish that one is waiting behind a transition.
    #[cfg(test)]
    acquiring: std::sync::atomic::AtomicUsize,
}

enum State {
    Active(SigningAuthority),
    Unresolved { last: Kappa },
    Diverged { live: Kappa, committed: Kappa },
}

/// The live authority, lent for one operation.
#[derive(Clone, Copy)]
pub struct AuthorityView<'a> {
    authority: &'a SigningAuthority,
}

impl<'a> AuthorityView<'a> {
    /// The anchor the node signs under.
    pub fn anchor(&self) -> &'a Kappa {
        self.authority.anchor()
    }

    /// The signer, borrowed for this operation only.
    pub fn signer(&self) -> &'a dyn Signer {
        self.authority.signer()
    }
}

/// An authority a transition may install: one a key store holds, with
/// that store's identity.
pub struct Successor {
    authority: SigningAuthority,
    custodian: u64,
}

impl Successor {
    /// A view of the incoming authority, for publication under it inside
    /// the transition, before the identity installs it.
    pub const fn view(&self) -> AuthorityView<'_> {
        AuthorityView {
            authority: &self.authority,
        }
    }

    pub fn anchor(&self) -> &Kappa {
        self.authority.anchor()
    }

    /// The incoming authority, for a backend that seals under it.
    pub fn authority(&self) -> &SigningAuthority {
        &self.authority
    }
}

impl From<&Staged> for Successor {
    fn from(staged: &Staged) -> Self {
        Self {
            authority: staged.authority.clone(),
            custodian: staged.custodian,
        }
    }
}

impl From<&Settlement> for Successor {
    fn from(settled: &Settlement) -> Self {
        Self {
            authority: settled.authority.clone(),
            custodian: settled.custodian,
        }
    }
}

/// What a transition step established.
pub enum TransitionOutcome<T, E> {
    /// The change committed; install the next authority. `T` is the step's
    /// report of the committed change.
    Installed(Successor, T),
    /// Nothing changed; the current authority stays live.
    Unchanged(E),
    /// Whether the change committed is unknown; refuse all signing until a
    /// restart resolves it.
    Unresolved(E),
    /// The live authority is not the backend's committed one; refuse all
    /// signing until a restart selects the committed one.
    Diverged { committed: Kappa, error: E },
}

/// Whether the node may sign, and under which anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Availability {
    /// The node signs under this anchor.
    Active(Kappa),
    /// A rotation from `last` ended with an unknown backend outcome.
    Unresolved { last: Kappa },
    /// The live authority `live` differs from the backend's `committed`.
    Diverged { live: Kappa, committed: Kappa },
    /// A transition panicked; whether its backend change committed is
    /// unknown.
    Interrupted,
}

/// The authority lock was poisoned by a transition that panicked: whether
/// the backend committed that transition is unknown.
fn interrupted<T>(_: PoisonError<T>) -> CryptoError {
    CryptoError::AuthorityInterrupted
}

fn unavailable(state: &State) -> Option<CryptoError> {
    match state {
        State::Active(_) => None,
        State::Unresolved { last } => Some(CryptoError::AuthorityUnresolved {
            last: Box::new(last.clone()),
        }),
        State::Diverged { live, committed } => Some(CryptoError::AuthorityDiverged {
            live: Box::new(live.clone()),
            committed: Box::new(committed.clone()),
        }),
    }
}

impl NodeIdentity {
    /// An identity holding the authority `settled` selected, bound to the
    /// key store that settled it.
    pub fn new(settled: &Settlement) -> Self {
        Self {
            state: RwLock::new(State::Active(settled.authority.clone())),
            position: RwLock::new(TrustPosition::Unprobed),
            custodian: settled.custodian,
            #[cfg(test)]
            acquiring: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Run `operation` with the live authority held shared, so a record that
    /// names the node's anchor and carries its signature is produced under
    /// one authority that no transition can replace meanwhile.
    ///
    /// # Errors
    ///
    /// `AuthorityUnresolved`, `AuthorityDiverged` or `AuthorityInterrupted`
    /// when the authority is unavailable.
    pub fn with_authority<T>(
        &self,
        operation: impl FnOnce(AuthorityView<'_>) -> T,
    ) -> Result<T, CryptoError> {
        #[cfg(test)]
        self.acquiring
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let state = self.state.read().map_err(interrupted)?;
        match &*state {
            State::Active(authority) => Ok(operation(AuthorityView { authority })),
            other => Err(unavailable(other).unwrap_or(CryptoError::AuthorityInterrupted)),
        }
    }

    /// The anchor the node currently signs under.
    ///
    /// # Errors
    ///
    /// As [`NodeIdentity::with_authority`].
    pub fn anchor(&self) -> Result<Kappa, CryptoError> {
        self.with_authority(|view| view.anchor().clone())
    }

    /// # Errors
    ///
    /// As [`NodeIdentity::with_authority`].
    pub fn algorithm(&self) -> Result<&'static str, CryptoError> {
        self.with_authority(|view| view.signer().algorithm())
    }

    /// # Errors
    ///
    /// As [`NodeIdentity::with_authority`].
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.with_authority(|view| view.signer().public_key().to_vec())
    }

    /// Sign with the live authority, holding it for the signature.
    ///
    /// # Errors
    ///
    /// `SigningFailed` from the signer; as [`NodeIdentity::with_authority`]
    /// otherwise.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.with_authority(|view| view.signer().sign(message))?
    }

    /// Change the node's authority. `custody` must be the lifecycle guard of
    /// the key store holding the live authority, held across the whole
    /// change; `step` receives the live authority, performs every durable
    /// effect of the change, including publication under the incoming
    /// authority (through [`Successor::view`]), and reports what it
    /// established. The authority is held exclusively throughout, so signing
    /// waits for the change and then uses the authority it installed, or
    /// fails if the identity became unavailable.
    ///
    /// Returns the installed anchor and the step's report.
    ///
    /// # Errors
    ///
    /// `CustodyMismatch`, converted, when `custody` belongs to another key
    /// store (the step never runs), or when the step installs a successor
    /// another key store holds (the identity becomes unresolved, since the
    /// step may have committed it). `AuthorityUnresolved`,
    /// `AuthorityDiverged` or `AuthorityInterrupted`, converted, when the
    /// identity is already unavailable (the step never runs). Otherwise the
    /// step's error for an unchanged, unresolved or diverged outcome.
    pub fn transition<T, E: From<CryptoError>>(
        &self,
        custody: &NodeKeys<'_>,
        step: impl FnOnce(&NodeKeys<'_>, AuthorityView<'_>) -> TransitionOutcome<T, E>,
    ) -> Result<(Kappa, T), E> {
        if custody.custodian() != self.custodian {
            return Err(CryptoError::CustodyMismatch.into());
        }
        let mut state = self.state.write().map_err(interrupted)?;
        let (outcome, last) = match &*state {
            State::Active(authority) => (
                step(custody, AuthorityView { authority }),
                authority.anchor().clone(),
            ),
            other => {
                return Err(unavailable(other)
                    .unwrap_or(CryptoError::AuthorityInterrupted)
                    .into());
            }
        };
        match outcome {
            TransitionOutcome::Installed(next, report) if next.custodian == self.custodian => {
                let anchor = next.authority.anchor().clone();
                *state = State::Active(next.authority);
                drop(state);
                Ok((anchor, report))
            }
            TransitionOutcome::Installed(..) => {
                *state = State::Unresolved { last };
                drop(state);
                Err(CryptoError::CustodyMismatch.into())
            }
            TransitionOutcome::Unchanged(error) => Err(error),
            TransitionOutcome::Unresolved(error) => {
                *state = State::Unresolved { last };
                drop(state);
                Err(error)
            }
            TransitionOutcome::Diverged { committed, error } => {
                *state = State::Diverged {
                    live: last,
                    committed,
                };
                drop(state);
                Err(error)
            }
        }
    }

    /// Whether the node may sign, and under which anchor. A poisoned
    /// authority lock reports [`Availability::Interrupted`], the same state
    /// in which signing refuses.
    pub fn status(&self) -> Availability {
        match self.state.read() {
            Err(_) => Availability::Interrupted,
            Ok(state) => match &*state {
                State::Active(authority) => Availability::Active(authority.anchor().clone()),
                State::Unresolved { last } => Availability::Unresolved { last: last.clone() },
                State::Diverged { live, committed } => Availability::Diverged {
                    live: live.clone(),
                    committed: committed.clone(),
                },
            },
        }
    }

    /// Whether signing is refused: unresolved, diverged or interrupted.
    pub fn is_unresolved(&self) -> bool {
        !matches!(self.status(), Availability::Active(_))
    }

    /// The current trust position. A position is a plain value replaced
    /// whole, so one left by a panicking writer is still a complete
    /// position and is returned rather than propagated as a panic.
    pub fn position(&self) -> TrustPosition {
        self.position
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set_position(&self, position: TrustPosition) {
        *self
            .position
            .write()
            .unwrap_or_else(PoisonError::into_inner) = position;
    }

    /// Update trust position from a batch of probe results.
    ///
    /// Any equivocation or invalid signature degrades the position.
    /// All verified with no faults produces Federated.
    /// All unreachable produces Standalone (absence is not failure).
    pub fn update_from_probes(&self, results: &[ProbeResult]) {
        if results.is_empty() {
            return;
        }
        let mut verified = 0u64;
        let mut reachable = 0u64;
        let mut fault = None;

        for result in results {
            match result {
                ProbeResult::Verified(_) => {
                    verified += 1;
                    reachable += 1;
                }
                ProbeResult::Unreachable(_) => {}
                ProbeResult::SignatureInvalid(_) => {
                    reachable += 1;
                    fault.get_or_insert(DegradeReason::SignatureInvalid);
                }
                ProbeResult::Equivocation { .. } => {
                    reachable += 1;
                    fault.get_or_insert(DegradeReason::Equivocation);
                }
            }
        }

        let new_position = match fault {
            Some(reason) => TrustPosition::Degraded {
                reason,
                reachable,
                verified,
            },
            None if verified > 0 => TrustPosition::Federated {
                verified_peers: verified,
            },
            None => TrustPosition::Standalone,
        };

        self.set_position(new_position);
    }
}

#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;
