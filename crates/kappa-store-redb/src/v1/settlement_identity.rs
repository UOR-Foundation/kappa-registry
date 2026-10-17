//! Collection of identity evidence for the registry's cross-namespace
//! identity projections.
//!
//! An execution writes identity rows into its namespace database and
//! records their ledger evidence (`AssertionPublish`, `RevocationPublish`,
//! `AnchorOrigin` with an `AnchorScope`). Settlement reads, for each such
//! mutation, the row the scope names from the snapshot of the namespace
//! database its epoch cursor holds (`collect`): the row at that snapshot,
//! present or gone. The transition records the ledger names are verified
//! against the scope; the row itself is current state at the snapshot, not
//! a reconstruction of what the epoch alone admitted. Settlement stages the
//! effect as versions of its projection families (`settlement_apply`),
//! completed with the epoch; settlement of an instance is sequential, so a
//! projection is never replaced by one from an older snapshot.

use redb::ReadableTable;

use kappa_store::authorization::{CredentialTransition, SessionTransition};
use kappa_store::canonical::from_canonical;
use kappa_store::epoch::{EpochMutation, MutationOp};
use kappa_store::identity::{Revocation, Succession, TrustPosition, Watermark};
use kappa_store::identity_scope::AnchorScope;
use kappa_store::{Kappa, NamespaceRef, StoreError};

use crate::content_read::ReadView;
use crate::identity_local::{AuthorizationTable, TRUST_KEY};
use crate::identity_write::binding_key;
use crate::tables;
use crate::unsettled_index::DiscoveryKey;

/// An anchor-keyed identity table, as a settlement target.
#[derive(Clone, Copy, Debug)]
pub enum AnchorTable {
    Device,
    Prekey,
    Locator,
    Commitment,
}

impl AnchorTable {
    const fn definition(self) -> redb::TableDefinition<'static, &'static [u8], &'static [u8]> {
        match self {
            Self::Device => tables::ID_DEVICE_BINDINGS,
            Self::Prekey => tables::ID_PREKEY_BINDINGS,
            Self::Locator => tables::ID_LOCATOR_RECORDS,
            Self::Commitment => tables::ID_REVOCATION_COMMITMENTS,
        }
    }
}

/// One identity row at the state the namespace holds, to project.
pub enum IdentityEffect {
    Assertion {
        kappa: Kappa,
        bytes: Vec<u8>,
    },
    Revocation {
        kappa: Kappa,
        bytes: Vec<u8>,
    },
    Watermark {
        kappa: Kappa,
        bytes: Vec<u8>,
    },
    /// Boxed: a succession record is several times the size of every other
    /// effect, and settlement holds an epoch's effects in one vector.
    Succession {
        record: Box<Succession>,
    },
    Binding {
        key: Vec<u8>,
        source: String,
        bytes: Option<Vec<u8>>,
    },
    Handle {
        key: String,
        bytes: Option<Vec<u8>>,
    },
    AnchorRow {
        table: AnchorTable,
        anchor_key: Vec<u8>,
        bytes: Option<Vec<u8>>,
    },
    /// A row of one of the string-keyed authorization tables (sessions,
    /// credentials, grace, trust): projected as a locator
    /// `[ns_uuid:16] ++ ciphertext`, removed when the namespace row is gone.
    Authorization {
        table: AuthorizationTable,
        key: String,
        bytes: Option<Vec<u8>>,
    },
}

/// The borrowed value of a row, copied only once its length is within
/// `limit`: a row beyond the settlement record limit is refused without
/// being copied or decoded.
fn bounded(value: &[u8], limit: u64) -> Result<Vec<u8>, StoreError> {
    let length = value.len() as u64;
    if length > limit {
        return Err(StoreError::CapacityExceeded(format!(
            "identity row of {length} bytes exceeds the settlement record limit {limit}"
        )));
    }
    Ok(value.to_vec())
}

fn string_row(
    txn: &redb::ReadTransaction,
    table: redb::TableDefinition<'static, &'static str, &'static [u8]>,
    key: &str,
    limit: u64,
) -> Result<Option<Vec<u8>>, StoreError> {
    txn.open_table(table)
        .map_err(crate::error::redb)?
        .get(key)
        .map_err(crate::error::redb)?
        .map(|value| bounded(value.value(), limit))
        .transpose()
}

fn row(
    txn: &redb::ReadTransaction,
    table: redb::TableDefinition<'static, &'static [u8], &'static [u8]>,
    key: &[u8],
    limit: u64,
) -> Result<Option<Vec<u8>>, StoreError> {
    txn.open_table(table)
        .map_err(crate::error::redb)?
        .get(key)
        .map_err(crate::error::redb)?
        .map(|value| bounded(value.value(), limit))
        .transpose()
}

fn required_row(
    txn: &redb::ReadTransaction,
    table: redb::TableDefinition<'static, &'static [u8], &'static [u8]>,
    kappa: &Kappa,
    kind: &str,
    limit: u64,
) -> Result<Vec<u8>, StoreError> {
    row(txn, table, kappa.key_bytes().as_slice(), limit)?.ok_or_else(|| {
        StoreError::Internal(format!("{kind} {kappa} is in the ledger but has no row"))
    })
}

impl IdentityEffect {
    /// Bytes of namespace rows this effect holds for projection, each
    /// already checked against the record limit when it was copied.
    fn held_bytes(&self) -> u64 {
        let held = match self {
            Self::Assertion { bytes, .. }
            | Self::Revocation { bytes, .. }
            | Self::Watermark { bytes, .. } => bytes.len(),
            Self::Succession { .. } => 0,
            Self::Binding { bytes, .. }
            | Self::Handle { bytes, .. }
            | Self::AnchorRow { bytes, .. }
            | Self::Authorization { bytes, .. } => bytes.as_ref().map_or(0, Vec::len),
        };
        held as u64
    }

    /// The predicate this effect's row answers before it is projected: a
    /// revocation or watermark is discoverable by its asserter.
    pub fn discovery_key(&self) -> Result<Option<DiscoveryKey>, StoreError> {
        Ok(match self {
            Self::Revocation { bytes, .. } => {
                let revocation: Revocation = from_canonical(bytes)?;
                Some(DiscoveryKey::RevocationsBy(revocation.asserter))
            }
            Self::Watermark { bytes, .. } => {
                let watermark: Watermark = from_canonical(bytes)?;
                Some(DiscoveryKey::WatermarksBy(watermark.asserter))
            }
            Self::Assertion { .. }
            | Self::Succession { .. }
            | Self::Binding { .. }
            | Self::Handle { .. }
            | Self::AnchorRow { .. }
            | Self::Authorization { .. } => None,
        })
    }

    /// `self` with the total bytes read for it: `records` read beside the
    /// rows it holds.
    fn sized(self, records: u64) -> Result<(Self, u64), StoreError> {
        let total = records
            .checked_add(self.held_bytes())
            .ok_or_else(|| StoreError::Internal("identity settlement read exceeds u64".into()))?;
        Ok((self, total))
    }
}

/// Read the row `mutation` names from the namespace snapshot `txn`. Every
/// record read is refused before it is read when larger than `limit`, every
/// row held after it is read; returns the effect and the bytes read.
pub fn collect(
    view: &ReadView,
    txn: &redb::ReadTransaction,
    index: &impl ReadableTable<&'static [u8], &'static [u8]>,
    ns: &NamespaceRef,
    mutation: &EpochMutation,
    limit: u64,
) -> Result<(IdentityEffect, u64), StoreError> {
    let kappa = mutation.kappa.clone();
    let mut records = 0u64;
    let mut record = |identity: &Kappa| -> Result<Vec<u8>, StoreError> {
        let bytes = view.epoch_content_from_index(index, identity, Some(limit))?;
        records = records
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| StoreError::Internal("identity settlement read exceeds u64".into()))?;
        Ok(bytes)
    };
    let effect = match mutation.op {
        MutationOp::AssertionPublish => IdentityEffect::Assertion {
            bytes: required_row(txn, tables::ID_ASSERTIONS, &kappa, "assertion", limit)?,
            kappa,
        },
        MutationOp::RevocationPublish => IdentityEffect::Revocation {
            bytes: required_row(txn, tables::ID_REVOCATIONS, &kappa, "revocation", limit)?,
            kappa,
        },
        MutationOp::AnchorOrigin => match AnchorScope::parse(mutation.context.as_deref())? {
            AnchorScope::Watermark => IdentityEffect::Watermark {
                bytes: required_row(txn, tables::ID_WATERMARKS, &kappa, "watermark", limit)?,
                kappa,
            },
            AnchorScope::Succession => {
                let bytes = record(&kappa)?;
                IdentityEffect::Succession {
                    record: Box::new(from_canonical(&bytes)?),
                }
            }
            AnchorScope::Binding { source } => {
                let key = binding_key(ns, &source);
                IdentityEffect::Binding {
                    bytes: row(txn, tables::ID_BINDINGS, key.as_slice(), limit)?,
                    key,
                    source,
                }
            }
            AnchorScope::Handle { key } => IdentityEffect::Handle {
                bytes: string_row(txn, tables::ID_HANDLES, &key, limit)?,
                key,
            },
            AnchorScope::Device => anchor_row(txn, AnchorTable::Device, &kappa, limit)?,
            AnchorScope::Prekey => anchor_row(txn, AnchorTable::Prekey, &kappa, limit)?,
            AnchorScope::Locator => anchor_row(txn, AnchorTable::Locator, &kappa, limit)?,
            AnchorScope::Commitment => anchor_row(txn, AnchorTable::Commitment, &kappa, limit)?,
            // The transition record the ledger names is the evidence of
            // what this epoch admitted; it is read back from the epoch's
            // content and checked to name the scoped row before the row's
            // current state is projected.
            AnchorScope::Session { id } => {
                let bytes = record(&kappa)?;
                let transition: SessionTransition = from_canonical(&bytes)?;
                if transition.id != id {
                    return Err(StoreError::Rejected(format!(
                        "session transition {kappa} names {} but the ledger scope names {id}",
                        transition.id
                    )));
                }
                IdentityEffect::Authorization {
                    table: tables::ID_SESSIONS,
                    bytes: string_row(txn, tables::ID_SESSIONS, &id, limit)?,
                    key: id,
                }
            }
            // A credential settles its row and its grace row as two
            // effects; the grace is the second (`collect_grace`).
            AnchorScope::Credential { id } => {
                let bytes = record(&kappa)?;
                let transition: CredentialTransition = from_canonical(&bytes)?;
                if transition.id != id {
                    return Err(StoreError::Rejected(format!(
                        "credential transition {kappa} names {} but the ledger scope names {id}",
                        transition.id
                    )));
                }
                IdentityEffect::Authorization {
                    table: tables::ID_CREDENTIALS,
                    bytes: string_row(txn, tables::ID_CREDENTIALS, &id, limit)?,
                    key: id,
                }
            }
            AnchorScope::Trust => {
                let bytes = record(&kappa)?;
                let _: TrustPosition = from_canonical(&bytes)?;
                IdentityEffect::Authorization {
                    table: tables::ID_TRUST,
                    bytes: string_row(txn, tables::ID_TRUST, TRUST_KEY, limit)?,
                    key: TRUST_KEY.to_owned(),
                }
            }
        },
        other => {
            return Err(StoreError::Internal(format!(
                "{other:?} is not identity evidence"
            )));
        }
    };
    effect.sized(records)
}

/// The grace row that accompanies a credential transition: `Some` for a
/// `Credential` scope, `None` for every other mutation; with the bytes
/// read, the row refused when larger than `limit`.
pub fn collect_grace(
    txn: &redb::ReadTransaction,
    mutation: &EpochMutation,
    limit: u64,
) -> Result<Option<(IdentityEffect, u64)>, StoreError> {
    if mutation.op != MutationOp::AnchorOrigin {
        return Ok(None);
    }
    match AnchorScope::parse(mutation.context.as_deref())? {
        AnchorScope::Credential { id } => IdentityEffect::Authorization {
            table: tables::ID_CREDENTIAL_GRACE,
            bytes: string_row(txn, tables::ID_CREDENTIAL_GRACE, &id, limit)?,
            key: id,
        }
        .sized(0)
        .map(Some),
        _ => Ok(None),
    }
}

fn anchor_row(
    txn: &redb::ReadTransaction,
    table: AnchorTable,
    anchor: &Kappa,
    limit: u64,
) -> Result<IdentityEffect, StoreError> {
    let anchor_key = anchor.key_bytes();
    Ok(IdentityEffect::AnchorRow {
        table,
        bytes: row(txn, table.definition(), anchor_key.as_slice(), limit)?,
        anchor_key,
    })
}
