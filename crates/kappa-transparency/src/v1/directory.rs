//! The directory service: publication, recovery and proof service over
//! the store's execution contract.
//!
//! Every method runs blocking store work and must be called from a
//! blocking worker. One mutex serializes publication and proof service,
//! so a proof is always built from the state its binding commits to.
//! A publication whose outcome disagrees with the directory's expectation
//! marks the directory unavailable until `recover` rebuilds it from the
//! committed state; it never serves a proof from state it cannot bind.

use std::sync::{Arc, Mutex, PoisonError};

use kappa_store::time::Clock;
use kappa_store::traits::KappaStore;
use kappa_types::axis::Axis;
use kappa_types::canonical::{canonical_bytes, from_canonical};
use kappa_types::epoch::{EpochMutation, MutationOp};
use kappa_types::epoch_root::{EpochRoot, mutations_merkle_root};
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::merkle_index;
use kappa_types::namespace::NamespaceRef;
use kappa_types::tag::TagUpdate;
use kappa_types::verified::VerifiedContent;

use crate::audit;
use crate::error::DirectoryError;
use crate::history;
use crate::proof::{AuditProof, EpochBinding, HistoryProof, path_bytes};
use crate::record::{Commitment, LogRecord, MapRecord};
use crate::state::DirectoryState;

/// The system namespace the directory publishes in.
pub const DIRECTORY_NAMESPACE: &str = "_identity/directory";
/// Tag naming the current commitment record; its `TagSet` mutation is the
/// epoch binding every proof carries.
pub const COMMITMENT_TAG: &str = "_directory/commitment";
/// Tag naming the current map record.
pub const MAP_TAG: &str = "_directory/map";
/// Tag naming the current log record.
pub const LOG_TAG: &str = "_directory/log";

/// One requested change: set `label` to `value`, or retract it (`None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub label: Vec<u8>,
    pub value: Option<Kappa>,
}

/// The committed state the directory serves from.
struct Committed {
    state: DirectoryState,
    binding: EpochBinding,
    commitment_kappa: Kappa,
}

pub struct Directory {
    store: Arc<dyn KappaStore>,
    clock: Arc<dyn Clock>,
    namespace: NamespaceRef,
    /// `None` while the directory is unavailable (see module doc).
    committed: Mutex<Option<Committed>>,
}

fn poisoned<T>(error: PoisonError<T>) -> T {
    error.into_inner()
}

/// The `TagSet` mutation of `tag` in `ledger`, with its index.
fn tag_mutation<'a>(ledger: &'a [EpochMutation], tag: &str) -> Option<(usize, &'a EpochMutation)> {
    ledger.iter().enumerate().find(|(_, mutation)| {
        mutation.op == MutationOp::TagSet && mutation.context.as_deref() == Some(tag)
    })
}

/// The binding of `commitment` to `root`, whose ledger is `ledger`.
fn binding_for(
    root: &EpochRoot,
    ledger: &[EpochMutation],
    commitment: Commitment,
) -> Result<EpochBinding, DirectoryError> {
    if mutations_merkle_root(ledger).as_slice() != root.mutations_root() {
        return Err(DirectoryError::Verification(
            "ledger does not hash to the epoch's mutations root".into(),
        ));
    }
    let commitment_kappa = Kappa::sha256(&canonical_bytes(&commitment));
    let (index, mutation) = tag_mutation(ledger, COMMITMENT_TAG).ok_or_else(|| {
        DirectoryError::Rejected(format!(
            "epoch {} holds no directory commitment",
            root.epoch_number()
        ))
    })?;
    if mutation.kappa != commitment_kappa {
        return Err(DirectoryError::Verification(
            "commitment tag names another record than the commitment read".into(),
        ));
    }
    let leaves: Vec<Vec<u8>> = ledger.iter().map(canonical_bytes).collect();
    let refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
    let path = merkle_index::inclusion_proof(&refs, index)
        .ok_or_else(|| DirectoryError::Verification("no ledger inclusion proof".into()))?;
    Ok(EpochBinding {
        epoch_root: dcbor::ByteString::from(root.to_bytes()),
        mutation: mutation.clone(),
        mutation_index: index as u64,
        mutation_count: ledger.len() as u64,
        mutation_path: path_bytes(&path),
        commitment,
    })
}

impl Directory {
    /// Open the directory over `store`: recover the committed state, or
    /// publish the empty genesis commitment when the namespace holds
    /// none, so every later query is provable.
    pub fn open(store: Arc<dyn KappaStore>, clock: Arc<dyn Clock>) -> Result<Self, DirectoryError> {
        let namespace = store.namespace_resolve(DIRECTORY_NAMESPACE, None)?;
        let directory = Self {
            store,
            clock,
            namespace,
            committed: Mutex::new(None),
        };
        match directory
            .store
            .tag_get(&directory.namespace, COMMITMENT_TAG)
        {
            Ok(_) => directory.recover()?,
            Err(StoreError::NotFound(_)) => {
                directory.serialized(|committed| {
                    directory.publish_state(committed, DirectoryState::default(), None)
                })?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(directory)
    }

    pub const fn namespace(&self) -> &NamespaceRef {
        &self.namespace
    }

    /// Run `serve` holding the one mutex that serializes publication,
    /// recovery and proof service (see module doc). The lock is held for
    /// the whole of `serve`, so a proof is built from the state its
    /// binding commits to and a publication is bound before anything else
    /// observes the directory.
    fn serialized<T>(
        &self,
        serve: impl FnOnce(&mut Option<Committed>) -> Result<T, DirectoryError>,
    ) -> Result<T, DirectoryError> {
        serve(&mut self.committed.lock().unwrap_or_else(poisoned))
    }

    /// Rebuild the served state from the committed records: the map and
    /// log the tags name, verified against their identities, replayed
    /// (`DirectoryState::from_records`), recommitted and checked against
    /// the commitment the epoch binds.
    pub fn recover(&self) -> Result<(), DirectoryError> {
        self.serialized(|committed| self.recover_into(committed))
    }

    /// `recover` under the held lock: unavailable from the start, served
    /// again only once the rebuilt state is bound.
    fn recover_into(&self, committed: &mut Option<Committed>) -> Result<(), DirectoryError> {
        *committed = None;
        let ns = &self.namespace;
        let read = |tag: &str| -> Result<(Kappa, Vec<u8>), DirectoryError> {
            let entry = self.store.tag_get(ns, tag)?;
            let bytes = self.store.blob_get_in(ns, &entry.kappa)?;
            VerifiedContent::verify(&entry.kappa, &bytes)?;
            Ok((entry.kappa, bytes))
        };
        let (commitment_kappa, commitment_bytes) = read(COMMITMENT_TAG)?;
        let (_, map_bytes) = read(MAP_TAG)?;
        let (_, log_bytes) = read(LOG_TAG)?;
        let commitment: Commitment = from_canonical(&commitment_bytes)?;
        let map: MapRecord = from_canonical(&map_bytes)?;
        let log: LogRecord = from_canonical(&log_bytes)?;
        let state = DirectoryState::from_records(&map, &log)?;
        if state.commitment(commitment.epoch, commitment.previous.clone()) != commitment {
            return Err(DirectoryError::Verification(
                "recovered records do not reproduce the committed roots".into(),
            ));
        }
        let (number, head) = self.store.epoch_current(ns)?;
        if number != commitment.epoch {
            return Err(DirectoryError::Verification(format!(
                "commitment is of epoch {} but the namespace head is {number}",
                commitment.epoch
            )));
        }
        let binding = self.bind(&head, commitment)?;
        *committed = Some(Committed {
            state,
            binding,
            commitment_kappa,
        });
        Ok(())
    }

    /// The binding of `commitment` under the admitted root `root_kappa`.
    fn bind(
        &self,
        root_kappa: &Kappa,
        commitment: Commitment,
    ) -> Result<EpochBinding, DirectoryError> {
        let root = self.store.epoch_get(root_kappa)?;
        let ledger_bytes = self
            .store
            .blob_get_in(&self.namespace, root.ledger_root())?;
        VerifiedContent::verify(root.ledger_root(), &ledger_bytes)?;
        let ledger: Vec<EpochMutation> = from_canonical(&ledger_bytes)?;
        let binding = binding_for(&root, ledger.as_slice(), commitment)?;
        crate::verify::binding_structure(&binding, self.namespace.id())?;
        Ok(binding)
    }

    /// Publish `state` as the next epoch of the directory namespace and
    /// make it the served state. `previous` is the commitment it extends.
    fn publish_state(
        &self,
        committed: &mut Option<Committed>,
        state: DirectoryState,
        previous: Option<Kappa>,
    ) -> Result<u64, DirectoryError> {
        let ns = &self.namespace;
        let epoch = self
            .store
            .epoch_current(ns)?
            .0
            .checked_add(1)
            .ok_or_else(|| DirectoryError::Rejected("directory epoch number exhausted".into()))?;
        let commitment = state.commitment(epoch, previous);
        let records = [
            (COMMITMENT_TAG, canonical_bytes(&commitment)),
            (MAP_TAG, canonical_bytes(&state.map_record())),
            (LOG_TAG, canonical_bytes(&state.log_record())),
        ];
        let mut execution = self.store.begin_execution(ns, &*self.clock)?;
        let mut commitment_kappa = None;
        for (tag, bytes) in &records {
            let content = VerifiedContent::compute(Axis::Sha256, bytes)?;
            execution.blob_put(&content)?;
            execution.tag_put(
                tag,
                &TagUpdate::Set {
                    kappa: content.kappa().clone(),
                },
            )?;
            if *tag == COMMITMENT_TAG {
                commitment_kappa = Some(content.kappa().clone());
            }
        }
        let published = execution.publish()?;
        // From here the publication is committed; any failure to bind it
        // leaves the directory unavailable until recovery.
        *committed = None;
        if published.epoch_number != epoch {
            tracing::error!(
                expected = epoch,
                published = published.epoch_number,
                "directory epoch committed out of sequence; another publisher wrote the directory namespace"
            );
            return Err(DirectoryError::Unavailable);
        }
        let commitment_kappa = commitment_kappa.ok_or_else(|| {
            DirectoryError::Verification("commitment record not published".into())
        })?;
        let binding = self.bind(&published.root, commitment)?;
        *committed = Some(Committed {
            state,
            binding,
            commitment_kappa,
        });
        Ok(epoch)
    }

    /// Apply `requests` as one directory epoch. Requests the map already
    /// reflects publish nothing; the current epoch is returned.
    pub fn publish(&self, requests: &[Request]) -> Result<u64, DirectoryError> {
        self.serialized(|committed| {
            let current = committed.as_ref().ok_or(DirectoryError::Unavailable)?;
            let epoch = current
                .binding
                .commitment
                .epoch
                .checked_add(1)
                .ok_or_else(|| {
                    DirectoryError::Rejected("directory epoch number exhausted".into())
                })?;
            let mut next = current.state.clone();
            let mut changed = false;
            for request in requests {
                if let Some(transition) =
                    next.derive(&request.label, request.value.as_ref(), epoch)?
                {
                    next.admit(&transition)?;
                    changed = true;
                }
            }
            if !changed {
                return Ok(current.binding.commitment.epoch);
            }
            let previous = Some(current.commitment_kappa.clone());
            self.publish_state(committed, next, previous)
        })
    }

    /// Retract `label` if it is active and currently names `value`: the
    /// retraction of one assertion must not retract a later assertion
    /// that replaced it. Returns the current epoch either way.
    pub fn retract(&self, label: &[u8], value: &Kappa) -> Result<u64, DirectoryError> {
        self.serialized(|committed| {
            let current = committed.as_ref().ok_or(DirectoryError::Unavailable)?;
            let names_value = current
                .state
                .entry(label)
                .is_some_and(|entry| entry.is_active() && &entry.value == value);
            if !names_value {
                return Ok(current.binding.commitment.epoch);
            }
            let epoch = current
                .binding
                .commitment
                .epoch
                .checked_add(1)
                .ok_or_else(|| {
                    DirectoryError::Rejected("directory epoch number exhausted".into())
                })?;
            let mut next = current.state.clone();
            let transition = next.derive(label, None, epoch)?.ok_or_else(|| {
                DirectoryError::Verification("active entry derived no retraction".into())
            })?;
            next.admit(&transition)?;
            let previous = Some(current.commitment_kappa.clone());
            self.publish_state(committed, next, previous)
        })
    }

    /// The three-state history proof of `label` at the current epoch.
    pub fn history(&self, label: &[u8]) -> Result<HistoryProof, DirectoryError> {
        self.serialized(|committed| {
            let current = committed.as_ref().ok_or(DirectoryError::Unavailable)?;
            let proof = history::build(&current.state, current.binding.clone(), label)?;
            crate::verify::history_structure(&proof, self.namespace.id())?;
            Ok(proof)
        })
    }

    /// The current directory epoch and its commitment identity.
    pub fn current(&self) -> Result<(u64, Kappa), DirectoryError> {
        self.serialized(|committed| {
            let current = committed.as_ref().ok_or(DirectoryError::Unavailable)?;
            Ok((
                current.binding.commitment.epoch,
                current.commitment_kappa.clone(),
            ))
        })
    }

    /// The commitment of directory epoch `number` and the log it commits,
    /// read from the namespace's admitted history.
    fn committed_epoch(&self, number: u64) -> Result<(EpochBinding, LogRecord), DirectoryError> {
        let ns = &self.namespace;
        let root_kappa = self.store.epoch_get_by_number(ns, number)?;
        let root = self.store.epoch_get(&root_kappa)?;
        let ledger_bytes = self.store.blob_get_in(ns, root.ledger_root())?;
        VerifiedContent::verify(root.ledger_root(), &ledger_bytes)?;
        let ledger: Vec<EpochMutation> = from_canonical(&ledger_bytes)?;
        let read = |tag: &str| -> Result<Vec<u8>, DirectoryError> {
            let (_, mutation) = tag_mutation(&ledger, tag).ok_or_else(|| {
                DirectoryError::Rejected(format!("epoch {number} holds no directory {tag}"))
            })?;
            let bytes = self.store.blob_get_in(ns, &mutation.kappa)?;
            VerifiedContent::verify(&mutation.kappa, &bytes)?;
            Ok(bytes)
        };
        let commitment: Commitment = from_canonical(&read(COMMITMENT_TAG)?)?;
        let log: LogRecord = from_canonical(&read(LOG_TAG)?)?;
        let binding = binding_for(&root, &ledger, commitment)?;
        crate::verify::binding_structure(&binding, ns.id())?;
        Ok((binding, log))
    }

    /// Append-only audit from directory epoch `from` to `to` (the current
    /// epoch when `None`), one page from `offset` (the earlier log's end
    /// when `None`).
    pub fn audit(
        &self,
        from: u64,
        to: Option<u64>,
        offset: Option<u64>,
    ) -> Result<AuditProof, DirectoryError> {
        self.serialized(|committed| {
            let current = committed.as_ref().ok_or(DirectoryError::Unavailable)?;
            let (to_binding, log) = match to {
                Some(to) if to != current.binding.commitment.epoch => self.committed_epoch(to)?,
                _ => (current.binding.clone(), current.state.log_record()),
            };
            let (from_binding, _) = if from == to_binding.commitment.epoch {
                (
                    to_binding.clone(),
                    LogRecord {
                        transitions: Vec::new(),
                    },
                )
            } else {
                self.committed_epoch(from)?
            };
            let offset = offset.unwrap_or(from_binding.commitment.log_size);
            let proof = audit::build(from_binding, to_binding, &log.transitions, offset)?;
            crate::verify::audit_structure(&proof, self.namespace.id())?;
            Ok(proof)
        })
    }
}
