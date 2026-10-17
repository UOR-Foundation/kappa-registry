//! Exclusive keys: names and rows only one namespace may hold at a time.
//!
//! A namespace alias, a session, a credential, the trust position, a
//! handle, an anchor's locator record and an anchor's revocation
//! commitment each have one owning namespace. An execution reserves the
//! key when it writes it; the reservation conflicts immediately with any
//! other namespace's hold, so two executions never both believe they
//! acquired one key. The claim follows the publication:
//!
//! - publication commits it (`Reserved` becomes `Committed`);
//! - abort releases it;
//! - an execution that removes a key it owns marks it `Releasing`, which
//!   still excludes every other namespace; publication removes it, abort
//!   restores it.
//!
//! A claim is exclusion, never evidence: whatever its state, a reader
//! takes its owner as a candidate and confirms the row against that
//! owner's published view. A reservation whose publication stored its view
//! but has not committed the claim yet therefore still finds the row; an
//! aborted reservation contributes nothing, because no view holds its row.
//!
//! Each shard carries a version advanced by every transition in it, read
//! under the shard lock together with the claim, so an observation that
//! found the key unowned can tell whether that still holds. Versions never
//! wrap: an exhausted shard reports every observation of it as changed.

use std::collections::BTreeMap;
use std::hash::{BuildHasher, Hash};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kappa_store::traits::namespace::validate_alias_admission;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::ProtocolId;

use super::view::NamespaceId;

/// Shards of the claim table. Many, so that an absence observation is
/// invalidated by an unrelated key only rarely; the observation is
/// conservative either way.
const SHARDS: usize = 4096;
const SHARDS_U64: u64 = 4096;
const EXHAUSTED: u64 = u64::MAX;

/// A key one namespace holds exclusively.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimKey {
    /// A namespace alias: the name, then the protocol scoping it (empty
    /// for a global alias). Every alias of one name shares a shard and
    /// orders together, so the admission rule over all of them is decided
    /// under one lock.
    Alias {
        name: String,
        protocol: String,
    },
    Session(String),
    Credential(String),
    Trust,
    /// `protocol:handle`.
    Handle(String),
    Locator(Kappa),
    Commitment(Kappa),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Reserved { attempt: u64 },
    Committed,
    Releasing { attempt: u64 },
}

#[derive(Clone, Copy, Debug)]
struct Claim {
    owner: NamespaceId,
    incarnation: u64,
    state: State,
}

impl Claim {
    /// The holder this claim names.
    const fn holder(&self) -> Holder {
        Holder {
            namespace: self.owner,
            incarnation: self.incarnation,
        }
    }

    /// Whether `holder`, exactly this namespace incarnation, owns the claim.
    fn held_by(&self, holder: Holder) -> bool {
        self.holder() == holder
    }
}

#[derive(Default)]
struct Shard {
    claims: BTreeMap<ClaimKey, Claim>,
    version: u64,
}

impl Shard {
    fn advance(&mut self) {
        self.version = self.version.checked_add(1).unwrap_or(EXHAUSTED);
    }
}

/// The namespace that may hold a key's row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holder {
    pub namespace: NamespaceId,
    pub incarnation: u64,
}

/// A shard version read with a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardVersion {
    shard: usize,
    version: u64,
}

/// A key's candidate holder and the shard version, read together.
#[derive(Clone, Copy, Debug)]
pub struct Observation {
    pub holder: Option<Holder>,
    pub at: ShardVersion,
}

pub struct Claims {
    shards: Box<[Mutex<Shard>]>,
    hasher: std::hash::RandomState,
}

impl Default for Claims {
    fn default() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(Shard::default())).collect(),
            hasher: std::hash::RandomState::new(),
        }
    }
}

fn conflict(key: &ClaimKey) -> StoreError {
    StoreError::Conflict(format!("{key:?} is held by another namespace"))
}

impl Claims {
    fn shard_of(&self, key: &ClaimKey) -> usize {
        let hash = match key {
            ClaimKey::Alias { name, .. } => self.hasher.hash_one(("alias", name)),
            other => self.hasher.hash_one(other),
        };
        // The remainder is below `SHARDS`, which fits usize.
        usize::try_from(hash % SHARDS_U64).unwrap_or(0)
    }

    /// Reserve the alias `name` in `protocol` (empty for global) under the
    /// alias admission rule (`validate_alias_admission`): the exact alias
    /// must be free, a scoped alias needs the global name free, and a
    /// global alias needs every scoped alias of the name free. A release of
    /// one of these by this attempt does not count against it. Every alias
    /// of the name is in one shard, so the rule and the reservation are
    /// decided under one lock.
    pub fn reserve_alias(
        &self,
        name: &str,
        protocol: &str,
        holder: Holder,
        attempt: u64,
    ) -> Result<(), StoreError> {
        let key = ClaimKey::Alias {
            name: name.to_owned(),
            protocol: protocol.to_owned(),
        };
        let mut shard = self.lock(self.shard_of(&key));
        let held = |claim: &Claim| {
            !(claim.held_by(holder) && claim.state == (State::Releasing { attempt }))
        };
        let lower = ClaimKey::Alias {
            name: name.to_owned(),
            protocol: String::new(),
        };
        let mut exact = false;
        let mut global = false;
        let mut scoped = false;
        for (candidate, claim) in shard.claims.range(lower..) {
            let ClaimKey::Alias {
                name: candidate_name,
                protocol: candidate_protocol,
            } = candidate
            else {
                break;
            };
            if candidate_name != name {
                break;
            }
            if !held(claim) {
                continue;
            }
            exact |= candidate_protocol == protocol;
            global |= candidate_protocol.is_empty();
            scoped |= !candidate_protocol.is_empty();
        }
        // The shared rule over the facts this shard holds.
        let scope = (!protocol.is_empty())
            .then(|| ProtocolId::new(protocol))
            .transpose()
            .map_err(|error| StoreError::Rejected(error.to_string()))?;
        validate_alias_admission(name, scope.as_ref(), exact, global, scoped)?;
        match shard.claims.get(&key).copied() {
            // This attempt released the alias and claims it again.
            Some(claim) if !held(&claim) => {
                if let Some(claim) = shard.claims.get_mut(&key) {
                    claim.state = State::Committed;
                }
            }
            Some(_) => return Err(conflict(&key)),
            None => {
                shard.claims.insert(
                    key,
                    Claim {
                        owner: holder.namespace,
                        incarnation: holder.incarnation,
                        state: State::Reserved { attempt },
                    },
                );
            }
        }
        shard.advance();
        drop(shard);
        Ok(())
    }

    // Shard state is consistent after every statement, so a lock a
    // panicking thread poisoned is still usable.
    fn lock(&self, shard: usize) -> MutexGuard<'_, Shard> {
        self.shards[shard]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserve `key` for `holder`'s execution `attempt`. Holding the key
    /// already (committed, or reserved by this attempt) succeeds without a
    /// transition; another holder, another incarnation of this namespace,
    /// or another attempt's reservation conflicts. Returns whether a
    /// reservation was taken.
    pub fn reserve(
        &self,
        key: &ClaimKey,
        holder: Holder,
        attempt: u64,
    ) -> Result<bool, StoreError> {
        let mut shard = self.lock(self.shard_of(key));
        let Some(claim) = shard.claims.get(key).copied() else {
            shard.claims.insert(
                key.clone(),
                Claim {
                    owner: holder.namespace,
                    incarnation: holder.incarnation,
                    state: State::Reserved { attempt },
                },
            );
            shard.advance();
            return Ok(true);
        };
        if !claim.held_by(holder) {
            return Err(conflict(key));
        }
        match claim.state {
            State::Committed => Ok(false),
            State::Reserved { attempt: held } if held == attempt => Ok(false),
            State::Releasing { attempt: held } if held == attempt => {
                // The attempt removed the key and writes it again: it keeps
                // owning it.
                if let Some(claim) = shard.claims.get_mut(key) {
                    claim.state = State::Committed;
                }
                shard.advance();
                drop(shard);
                Ok(false)
            }
            State::Reserved { .. } | State::Releasing { .. } => Err(conflict(key)),
        }
    }

    /// Mark `key`, which `holder` owns, as released by `attempt`. Returns
    /// whether a transition was recorded; a key the holder does not hold
    /// records nothing.
    pub fn release(&self, key: &ClaimKey, holder: Holder, attempt: u64) -> bool {
        let mut shard = self.lock(self.shard_of(key));
        let Some(claim) = shard.claims.get(key).copied() else {
            return false;
        };
        if !claim.held_by(holder) {
            return false;
        }
        match claim.state {
            State::Committed => {
                if let Some(claim) = shard.claims.get_mut(key) {
                    claim.state = State::Releasing { attempt };
                }
            }
            State::Reserved { attempt: held } if held == attempt => {
                shard.claims.remove(key);
            }
            State::Reserved { .. } | State::Releasing { .. } => return false,
        }
        shard.advance();
        true
    }

    /// Settle `attempt`'s claims: on publication its reservations become
    /// ownership and its releases take effect; on abort its reservations
    /// are released and its releases undone.
    pub fn settle(&self, keys: &[ClaimKey], holder: Holder, attempt: u64, published: bool) {
        for key in keys {
            let mut shard = self.lock(self.shard_of(key));
            let Some(claim) = shard.claims.get(key).copied() else {
                continue;
            };
            if !claim.held_by(holder) {
                continue;
            }
            let remove = match (claim.state, published) {
                (State::Reserved { attempt: held }, true) if held == attempt => false,
                (State::Releasing { attempt: held }, true) if held == attempt => true,
                (State::Reserved { attempt: held }, false) if held == attempt => true,
                (State::Releasing { attempt: held }, false) if held == attempt => false,
                _ => continue,
            };
            if remove {
                shard.claims.remove(key);
            } else if let Some(claim) = shard.claims.get_mut(key) {
                claim.state = State::Committed;
            }
            shard.advance();
        }
    }

    /// The candidate holder of `key`, whatever the claim's state, with the
    /// shard version read under the same lock.
    pub fn observe(&self, key: &ClaimKey) -> Observation {
        let index = self.shard_of(key);
        let shard = self.lock(index);
        Observation {
            holder: shard.claims.get(key).map(Claim::holder),
            at: ShardVersion {
                shard: index,
                version: shard.version,
            },
        }
    }

    /// Whether the shard of `at` changed since it was read.
    pub fn unchanged(&self, at: ShardVersion) -> bool {
        at.version != EXHAUSTED && self.lock(at.shard).version == at.version
    }
}

#[cfg(test)]
#[path = "claims_tests.rs"]
mod tests;
