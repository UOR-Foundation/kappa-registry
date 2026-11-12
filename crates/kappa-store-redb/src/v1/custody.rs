//! Durable custody of a publication whose signing coordinate is consumed.
//!
//! A redb publication is assembled inside one namespace write transaction,
//! which nothing outlives but its commit. Its signing coordinate, however,
//! is consumed before the signer is invoked and can never be signed for
//! another root. The custody record is what outlives the transaction: the
//! instance and coordinate, the predecessor and the identity of the
//! unsigned root, the execution's time, the activation it governs if any,
//! every applied transition in ledger order (its canonical mutation, its
//! evidence bytes and its private payload, with the physical bytes of any
//! allocation it installs), the authorization rows it read, the work spent
//! on it so far, and how far signing progressed, down to the exact bytes
//! the signer returned.
//!
//! This module is the record's codec and persistence only. Signing
//! progress is the shared state machine's (`epoch_publication`), recorded
//! here as it reports it; when the record may be discharged is decided by
//! its caller from the committed root, which [`PersistentStore::discharge_custody`]
//! checks names exactly the custodied candidate.
//!
//! Every write is made under the instance's writer gate, whose token the
//! write takes: the gate is the exclusion that makes the record store
//! (`instance_record::Kind::store`) atomic. The record is encrypted under
//! the table key bound to the instance, and its loads are bounded by
//! `custody_record_bytes` and charged to the caller's meter before they
//! read. A loaded record must name the instance it was loaded for,
//! incarnation included.
//!
//! Resolution (`custody_resolve`) rebuilds the transaction from the record
//! through the shared transition boundary and [`TxnWriter::apply`]; while a
//! record is held, reclamation protects every allocation it names
//! (`content_reclaim`), and admission refuses new executions of the
//! instance.

use dcbor::prelude::*;

use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::epoch_publication::RecordedSigning;
use kappa_store::transition::PrivatePayload;
use kappa_store::work::{Dimension, Meter, Work};
use kappa_store::{
    EpochRoot, Kappa, PublicationPhase, RecoveryDisposition, RetainedPublication, StoreError,
    VerifiedContent,
};

use crate::PersistentStore;
use crate::content_install::PreparedContent;
use crate::encrypted::bound;
use crate::identity_local::{AuthorizationRead, AuthorizationTable};
use crate::instance_record::Kind;
use crate::representation::{AllocationId, Representation};
use crate::representation_codec;
use crate::storage::WriterToken;
use crate::storage_instance::{Incarnation, StorageInstance};
use crate::tables::{ID_CREDENTIAL_GRACE, ID_CREDENTIALS, ID_SESSIONS, ID_TRUST};
use crate::transition_apply::RedbPayload;

/// The only version of the record.
const CUSTODY_VERSION: u64 = 1;

/// The private payload of one custodied transition: what its evidence does
/// not carry and its application needs.
#[derive(Clone, Debug, PartialEq, Eq, CBORCodable)]
pub(crate) enum CustodyPayload {
    #[cbor(n = 0)]
    None,
    #[cbor(n = 1)]
    Session {
        #[cbor(n = 0)]
        metadata: Vec<u8>,
    },
    #[cbor(n = 2)]
    Credential {
        #[cbor(n = 0)]
        secret_hash: Vec<u8>,
        #[cbor(n = 1)]
        grace_secret_hash: Option<Vec<u8>>,
    },
    /// Prepared content: its identity, aliases and representation, and the
    /// physical bytes its allocation occupies, which the unsettled budget
    /// charges once it is pinned again.
    #[cbor(n = 3)]
    Content {
        #[cbor(n = 0)]
        identity: Kappa,
        #[cbor(n = 1)]
        aliases: Vec<Kappa>,
        #[cbor(n = 2)]
        record: Vec<u8>,
        #[cbor(n = 3)]
        allocated_bytes: u64,
    },
    #[cbor(n = 4)]
    Record {
        #[cbor(n = 0)]
        identity: Kappa,
        #[cbor(n = 1)]
        bytes: Vec<u8>,
    },
}

impl CustodyPayload {
    /// Bytes held while cloning and decoding the private payload during
    /// reconstruction. Fixed object and identity slots are included.
    pub(crate) fn reconstruction_bound(&self) -> u64 {
        let bytes = match self {
            Self::None => 0,
            Self::Session { metadata } => metadata.len() as u64,
            Self::Credential {
                secret_hash,
                grace_secret_hash,
            } => (secret_hash.len() as u64).saturating_add(
                grace_secret_hash
                    .as_ref()
                    .map_or(0, |bytes| bytes.len() as u64),
            ),
            Self::Content {
                aliases, record, ..
            } => (record.len() as u64).saturating_add((aliases.len() as u64).saturating_mul(256)),
            Self::Record { bytes, .. } => bytes.len() as u64,
        };
        bytes.saturating_add(512).saturating_mul(4)
    }

    /// The custody form of `payload`.
    pub(crate) fn of(payload: &RedbPayload) -> Self {
        match payload {
            PrivatePayload::NoResources => Self::None,
            PrivatePayload::SessionMetadata(metadata) => Self::Session {
                metadata: metadata.clone(),
            },
            PrivatePayload::CredentialSecrets {
                secret_hash,
                grace_secret_hash,
            } => Self::Credential {
                secret_hash: secret_hash.clone(),
                grace_secret_hash: grace_secret_hash.clone(),
            },
            PrivatePayload::PreparedContent(prepared) => Self::Content {
                identity: prepared.identity().clone(),
                aliases: prepared.aliases().to_vec(),
                record: representation_codec::encode(prepared.record()),
                allocated_bytes: prepared.allocated_bytes(),
            },
            PrivatePayload::ExplicitRecord(content) => Self::Record {
                identity: content.kappa().clone(),
                bytes: content.content().to_vec(),
            },
        }
    }

    /// The allocation this payload's prepared content installs, if any.
    pub(crate) fn allocation(&self) -> Result<Option<AllocationId>, StoreError> {
        let Self::Content { record, .. } = self else {
            return Ok(None);
        };
        Ok(
            match representation_codec::decode(record)?.representation() {
                Representation::External { allocation, .. } => Some(*allocation),
                _ => None,
            },
        )
    }

    /// The payload again, owned by `store`: prepared content is pinned
    /// again on its allocation, carrying the physical bytes the preparation
    /// measured, and owned by the store's protection; an explicit record is
    /// verified against its identity.
    pub(crate) fn restore(self, store: &PersistentStore) -> Result<RedbPayload, StoreError> {
        Ok(match self {
            Self::None => PrivatePayload::NoResources,
            Self::Session { metadata } => PrivatePayload::SessionMetadata(metadata),
            Self::Credential {
                secret_hash,
                grace_secret_hash,
            } => PrivatePayload::CredentialSecrets {
                secret_hash,
                grace_secret_hash,
            },
            Self::Content {
                identity,
                aliases,
                record,
                allocated_bytes,
            } => {
                let record = representation_codec::decode(&record)?;
                let prepared = match record.representation() {
                    Representation::External { allocation, .. } => {
                        let pin = store
                            .protection
                            .pin(*allocation)?
                            .with_bytes(allocated_bytes);
                        PreparedContent::allocated(identity, record, pin)?
                    }
                    _ => PreparedContent::unallocated(identity, record)?,
                };
                PrivatePayload::PreparedContent(Box::new(
                    prepared.with_aliases(aliases).owned_by(&store.protection),
                ))
            }
            Self::Record { identity, bytes } => {
                PrivatePayload::ExplicitRecord(VerifiedContent::verify_owned(&identity, bytes)?)
            }
        })
    }
}

/// One transition in custody, in ledger order.
#[derive(Clone, Debug, PartialEq, Eq, CBORCodable)]
pub(crate) struct CustodyTransition {
    /// The canonical `EpochMutation` the transition's ledger entry is.
    #[cbor(n = 0)]
    pub(crate) mutation: Vec<u8>,
    /// The canonical evidence the mutation names.
    #[cbor(n = 1)]
    pub(crate) evidence: Vec<u8>,
    #[cbor(n = 2)]
    pub(crate) payload: CustodyPayload,
}

/// One authorization row the execution read, as it observed it.
#[derive(Clone, Debug, PartialEq, Eq, CBORCodable)]
pub(crate) struct CustodyRead {
    #[cbor(n = 0)]
    table: String,
    #[cbor(n = 1)]
    key: String,
    #[cbor(n = 2)]
    observed: Option<Vec<u8>>,
}

/// The authorization tables an execution reads.
const AUTHORIZATION_TABLES: [AuthorizationTable; 4] =
    [ID_SESSIONS, ID_CREDENTIALS, ID_CREDENTIAL_GRACE, ID_TRUST];

impl CustodyRead {
    pub(crate) fn held_bytes(&self) -> u64 {
        (self.table.len() as u64)
            .saturating_add(self.key.len() as u64)
            .saturating_add(self.observed.as_ref().map_or(0, |bytes| bytes.len() as u64))
            .saturating_add(size_of::<Self>() as u64)
    }

    pub(crate) fn of(read: &AuthorizationRead) -> Self {
        Self {
            table: redb::TableHandle::name(&read.table).to_owned(),
            key: read.key.clone(),
            observed: read.observed.clone(),
        }
    }

    pub(crate) fn restore(self) -> Result<AuthorizationRead, StoreError> {
        let table = AUTHORIZATION_TABLES
            .into_iter()
            .find(|table| redb::TableHandle::name(table) == self.table)
            .ok_or_else(|| {
                StoreError::Internal(format!(
                    "custody names authorization table {}, which executions do not read",
                    self.table
                ))
            })?;
        Ok(AuthorizationRead {
            table,
            key: self.key,
            observed: self.observed,
        })
    }
}

/// The activation a custodied epoch governs: its history position, the
/// identity of its transition record, and the outgoing authority it
/// succeeds.
#[derive(Clone, Debug, PartialEq, Eq, CBORCodable)]
pub(crate) struct CustodyActivation {
    #[cbor(n = 0)]
    pub(crate) position: u64,
    #[cbor(n = 1)]
    pub(crate) record: Kappa,
    #[cbor(n = 2)]
    pub(crate) outgoing: Kappa,
}

/// How far signing progressed, as the shared state machine reported it.
#[derive(Clone, Debug, PartialEq, Eq, CBORCodable)]
pub(crate) enum CustodySigning {
    #[cbor(n = 0)]
    Prepared,
    #[cbor(n = 1)]
    Invoked,
    #[cbor(n = 2)]
    Returned {
        #[cbor(n = 0)]
        signature: Vec<u8>,
    },
}

impl CustodySigning {
    pub(crate) fn recorded(self) -> RecordedSigning {
        match self {
            Self::Prepared => RecordedSigning::Prepared,
            Self::Invoked => RecordedSigning::Invoked,
            Self::Returned { signature } => RecordedSigning::Returned(signature),
        }
    }
}

/// A retained publication in custody (see the module documentation).
#[derive(Clone, Debug, PartialEq, Eq, CBORCodable)]
pub(crate) struct CustodyRecord {
    #[cbor(n = 0)]
    version: u64,
    #[cbor(n = 1)]
    namespace: Vec<u8>,
    #[cbor(n = 2)]
    incarnation: Vec<u8>,
    #[cbor(n = 3)]
    pub(crate) epoch_number: u64,
    #[cbor(n = 4)]
    pub(crate) predecessor: Option<Kappa>,
    #[cbor(n = 5)]
    pub(crate) unsigned: Kappa,
    #[cbor(n = 6)]
    pub(crate) now_ms: i64,
    #[cbor(n = 7)]
    pub(crate) activation: Option<CustodyActivation>,
    #[cbor(n = 8)]
    pub(crate) transitions: Vec<CustodyTransition>,
    #[cbor(n = 9)]
    pub(crate) reads: Vec<CustodyRead>,
    #[cbor(n = 10)]
    pub(crate) signing: CustodySigning,
    /// Why the publication is retained, as last observed.
    #[cbor(n = 11)]
    pub(crate) cause: String,
    /// All the work spent on the publication, per dimension in
    /// `Dimension::ALL` order: its execution's and every resolution's.
    #[cbor(n = 12)]
    work: Vec<u64>,
    /// A conclusive publication refusal, preserved independently of signing progress.
    #[cbor(n = 13)]
    terminal: Option<String>,
}

/// What a custody record is made of, at the seal.
pub(crate) struct CustodyParts {
    pub(crate) namespace: [u8; 16],
    pub(crate) incarnation: [u8; 16],
    pub(crate) epoch_number: u64,
    pub(crate) predecessor: Option<Kappa>,
    pub(crate) unsigned: Kappa,
    pub(crate) now_ms: i64,
    pub(crate) activation: Option<CustodyActivation>,
    pub(crate) transitions: Vec<CustodyTransition>,
    pub(crate) reads: Vec<CustodyRead>,
    pub(crate) work: Work,
}

impl CustodyRecord {
    /// The record of a publication about to consume its coordinate.
    pub(crate) fn new(parts: CustodyParts) -> Self {
        let mut record = Self {
            version: CUSTODY_VERSION,
            namespace: parts.namespace.to_vec(),
            incarnation: parts.incarnation.to_vec(),
            epoch_number: parts.epoch_number,
            predecessor: parts.predecessor,
            unsigned: parts.unsigned,
            now_ms: parts.now_ms,
            activation: parts.activation,
            transitions: parts.transitions,
            reads: parts.reads,
            signing: CustodySigning::Prepared,
            cause: "the publication's coordinate is consumed and it has not committed".into(),
            work: Vec::new(),
            terminal: None,
        };
        record.set_work(&parts.work);
        record
    }

    /// What a caller observes of this retained publication: its
    /// coordinate, candidate, signing phase and disposition, and cause. A
    /// signed root is formed only by resolution, so none is reported here.
    pub(crate) fn retained(&self) -> Result<RetainedPublication, StoreError> {
        let (phase, disposition) = match &self.signing {
            CustodySigning::Prepared => {
                (PublicationPhase::Prepared, RecoveryDisposition::Resumable)
            }
            CustodySigning::Invoked => (
                PublicationPhase::SignerInvoked,
                RecoveryDisposition::Terminal,
            ),
            CustodySigning::Returned { .. } => (
                PublicationPhase::SignatureReturned,
                RecoveryDisposition::Resumable,
            ),
        };
        Ok(RetainedPublication {
            namespace: self.namespace()?,
            incarnation: self.incarnation()?,
            epoch_number: self.epoch_number,
            candidate: self.unsigned.clone(),
            signed_root: None,
            phase,
            disposition: self
                .terminal
                .as_ref()
                .map_or(disposition, |_| RecoveryDisposition::Terminal),
            cause: self.terminal.as_ref().unwrap_or(&self.cause).clone(),
        })
    }

    pub(crate) fn namespace(&self) -> Result<[u8; 16], StoreError> {
        self.namespace
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Internal("custody namespace is not 16 bytes".into()))
    }

    pub(crate) fn incarnation(&self) -> Result<[u8; 16], StoreError> {
        self.incarnation
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Internal("custody incarnation is not 16 bytes".into()))
    }

    /// All the work spent on the publication.
    pub(crate) fn work(&self) -> Result<Work, StoreError> {
        if self.work.len() != Dimension::ALL.len() {
            return Err(StoreError::Internal(format!(
                "custody work names {} dimensions, not {}",
                self.work.len(),
                Dimension::ALL.len()
            )));
        }
        Ok(Dimension::ALL
            .into_iter()
            .zip(&self.work)
            .fold(Work::default(), |work, (dimension, amount)| {
                work.with(dimension, *amount)
            }))
    }

    pub(crate) fn set_work(&mut self, work: &Work) {
        self.work = Dimension::ALL
            .into_iter()
            .map(|dimension| work.get(dimension))
            .collect();
    }

    pub(crate) fn make_terminal(&mut self, cause: &StoreError) {
        self.terminal.get_or_insert_with(|| cause.to_string());
    }

    /// Match authenticated committed evidence before allowing cleanup. A
    /// signature over the same unsigned candidate is not interchangeable with
    /// the exact signature this invocation returned.
    pub(crate) fn check_committed(
        &self,
        instance: &StorageInstance,
        committed: &EpochRoot,
        work: &mut dyn Meter,
        storage: &std::sync::Arc<kappa_store::capacity::CapacityPool>,
    ) -> Result<(), StoreError> {
        let signature_matches = match &self.signing {
            CustodySigning::Returned { signature } => {
                // The borrowed matcher examines each encoded head and compares
                // disjoint signature chunks. It allocates no decoded envelope.
                let length = committed.cose_signature().len() as u64;
                work.charge_all(&[(Dimension::Entries, length), (Dimension::BytesRead, length)])?;
                kappa_crypto::cose::contains_signature(committed.cose_signature(), signature)
                    .map_err(crate::error::crypto)?
            }
            _ => false,
        };
        if self.namespace()? != *instance.namespace()
            || instance.incarnation() != Incarnation::Known(self.incarnation()?)
            || committed.namespace_id() != self.namespace()?.as_slice()
            || committed.epoch_number() != self.epoch_number
            || committed.prev_identifier() != self.predecessor.as_ref()
            || committed.bounded_unsigned_identity(work, storage)? != self.unsigned
            || !signature_matches
        {
            return Err(StoreError::Conflict(format!(
                "committed epoch {} of {instance} is not the retained signed candidate {}",
                committed.kappa(),
                self.unsigned,
            )));
        }
        Ok(())
    }
}

#[path = "custody_persistence.rs"]
mod persistence;
