//! Published identity claims: bindings, assertions, revocations, watermarks,
//! and the cross-namespace subject index, read from the registry's
//! completed projection (`projection`). Every read is one
//! [`ProjectionRead`] on the one meter of the operation that asked for it;
//! writes are `EpochExecution` methods over `identity_write.rs` into the
//! namespace database, projected by settlement. The answers a decision
//! depends on (an asserter's revocations and watermarks) are complete:
//! settled state plus every unsettled instance registered under the
//! predicate (`issued_by`).

use std::collections::{BTreeMap, BTreeSet};

use redb::ReadableDatabase;

use kappa_store::axis::Axis;
use kappa_store::canonical::from_canonical;
use kappa_store::error::StoreError;
use kappa_store::identity::{IdentityAssertion, IdentityBinding, Revocation, Watermark};
use kappa_store::kappa::Kappa;
use kappa_store::page::{Page, PageRequest};
use kappa_store::work::{Dimension, Meter, reserve_charged};

use crate::PersistentStore;
use crate::projection::{Family, ProjectionRead};
use crate::tables;
use crate::unsettled_index::DiscoveryKey;

/// Subject index members are `[asserter key bytes][assertion key bytes]`.
fn decode_subject_idx_value(bytes: &[u8]) -> Result<(Vec<u8>, Kappa), StoreError> {
    if bytes.is_empty() {
        return Err(StoreError::Internal("empty subject index value".into()));
    }
    let asserter_axis = Axis::from_discriminant(bytes[0])
        .ok_or_else(|| StoreError::Internal("invalid asserter axis in subject index".into()))?;
    let asserter_len = 1 + asserter_axis.digest_len();
    if bytes.len() <= asserter_len {
        return Err(StoreError::Internal("truncated subject index value".into()));
    }
    let asserter_kb = bytes[..asserter_len].to_vec();
    let assertion_kappa = Kappa::from_key_bytes(&bytes[asserter_len..])
        .map_err(|e| StoreError::Internal(format!("assertion kappa decode: {e}")))?;
    Ok((asserter_kb, assertion_kappa))
}

/// Entries written by the former asserter-less index carry an all-zero
/// asserter; they are admitted without a trust decision because their
/// asserter is unknown to the index.
fn is_zero_asserter(asserter_kb: &[u8]) -> bool {
    asserter_kb.iter().all(|&b| b == 0)
}

fn asserter_hash_128(asserter_kb: &[u8]) -> [u8; 16] {
    let hash = blake3::hash(asserter_kb);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_bytes()[..16]);
    out
}

/// The completed record of content-keyed `family` at `identity`, read on
/// `work`. Records are content-addressed: every instance holding one holds
/// the same bytes.
fn completed<T>(
    read: &ProjectionRead,
    family: Family,
    identity: &Kappa,
    kind: &str,
    work: &mut dyn Meter,
) -> Result<Option<T>, StoreError>
where
    T: TryFrom<dcbor::CBOR, Error = dcbor::Error>,
{
    read.get(family, &identity.key_bytes(), work)?
        .into_iter()
        .next()
        .map(|visible| {
            from_canonical(&visible.value)
                .map_err(|e| StoreError::Internal(format!("{kind} decode: {e}")))
        })
        .transpose()
}

/// Completed records listed by an asserter-keyed membership family, each
/// confirmed by its completed record, all on `work`.
fn settled_by_asserter<T>(
    read: &ProjectionRead,
    index: Family,
    records: Family,
    asserter: &Kappa,
    kind: &str,
    work: &mut dyn Meter,
) -> Result<Vec<(Kappa, T)>, StoreError>
where
    T: TryFrom<dcbor::CBOR, Error = dcbor::Error>,
{
    let mut identities = BTreeSet::new();
    for (member, _) in read.members(index, &asserter.key_bytes(), work)? {
        identities.insert(Kappa::from_key_bytes(&member)?);
    }
    let mut results = Vec::with_capacity(identities.len());
    for identity in identities {
        if let Some(record) = completed(read, records, &identity, kind, work)? {
            results.push((identity, record));
        }
    }
    Ok(results)
}

/// Records listed by an asserter-keyed multimap index of a namespace's own
/// tables, read in `rtxn` on `work`: the asserter's key and its lookup,
/// each index member examined, and each record looked up, read, decoded
/// and held, every one charged before it is done, the result buffer as it
/// grows. Each member is confirmed as it is read; no list of keys is built.
fn namespace_by_asserter<T>(
    rtxn: &redb::ReadTransaction,
    index: redb::MultimapTableDefinition<&'static [u8], &'static [u8]>,
    records: redb::TableDefinition<&'static [u8], &'static [u8]>,
    asserter: &Kappa,
    kind: &str,
    work: &mut dyn Meter,
) -> Result<Vec<(Kappa, T)>, StoreError>
where
    T: TryFrom<dcbor::CBOR, Error = dcbor::Error>,
{
    let idx = rtxn
        .open_multimap_table(index)
        .map_err(crate::error::redb)?;
    let table = rtxn.open_table(records).map_err(crate::error::redb)?;
    work.charge_all(&[
        (Dimension::BytesAllocated, asserter.key_len() as u64),
        (Dimension::Entries, 1),
    ])?;
    let mut members = idx
        .get(asserter.key_bytes().as_slice())
        .map_err(crate::error::redb)?;
    let mut results = Vec::new();
    loop {
        work.charge(Dimension::Entries, 1)?;
        let Some(item) = members.next() else {
            break;
        };
        let item = item.map_err(crate::error::redb)?;
        let key = item.value();
        work.charge(Dimension::Entries, 1)?;
        let Some(value) = table.get(key).map_err(crate::error::redb)? else {
            continue;
        };
        let length = value.value().len() as u64;
        work.charge_all(&[
            (Dimension::BytesAllocated, key.len() as u64),
            (Dimension::BytesRead, length),
            (Dimension::BytesDecoded, length),
            (Dimension::BytesAllocated, length),
        ])?;
        let identity = Kappa::from_key_bytes(key)
            .map_err(|e| StoreError::Internal(format!("kappa decode: {e}")))?;
        let record = from_canonical(value.value())
            .map_err(|e| StoreError::Internal(format!("{kind} decode: {e}")))?;
        reserve_charged(work, &mut results)?;
        results.push((identity, record));
    }
    Ok(results)
}

/// The asserter-keyed families of one kind of signed record, in the
/// registry's projection and in a namespace's own tables.
struct Issued {
    key: fn(Kappa) -> DiscoveryKey,
    index: Family,
    records: Family,
    namespace_index: redb::MultimapTableDefinition<'static, &'static [u8], &'static [u8]>,
    namespace_records: redb::TableDefinition<'static, &'static [u8], &'static [u8]>,
    kind: &'static str,
}

const REVOCATIONS: Issued = Issued {
    key: DiscoveryKey::RevocationsBy,
    index: Family::RevocationByAsserter,
    records: Family::Revocation,
    namespace_index: tables::ID_REVOCATION_ASSERTER_IDX,
    namespace_records: tables::ID_REVOCATIONS,
    kind: "revocation",
};

const WATERMARKS: Issued = Issued {
    key: DiscoveryKey::WatermarksBy,
    index: Family::WatermarkByAsserter,
    records: Family::Watermark,
    namespace_index: tables::ID_WATERMARK_ASSERTER_IDX,
    namespace_records: tables::ID_WATERMARKS,
    kind: "watermark",
};

impl PersistentStore {
    pub(crate) fn read_bindings(
        &self,
        source: &str,
        work: &mut dyn Meter,
    ) -> Result<Vec<IdentityBinding>, StoreError> {
        let read = self.projection()?;
        let mut namespaces = BTreeSet::new();
        for (member, _) in read.members(Family::BindingBySource, source.as_bytes(), work)? {
            if member.len() == 16 {
                namespaces.insert(member);
            }
        }
        let mut results = Vec::new();
        for namespace in namespaces {
            let mut key = Vec::with_capacity(16 + source.len());
            key.extend_from_slice(&namespace);
            key.extend_from_slice(source.as_bytes());
            let Some(visible) = read
                .get(Family::Binding, &key, work)?
                .into_iter()
                .max_by_key(|visible| visible.completion)
            else {
                continue;
            };
            let bindings: Vec<IdentityBinding> = from_canonical(&visible.value)
                .map_err(|e| StoreError::Internal(format!("binding decode: {e}")))?;
            results.extend(bindings);
        }
        Ok(results)
    }

    pub(crate) fn read_bindings_by_target(
        &self,
        target: &Kappa,
        page: &PageRequest,
        work: &mut dyn Meter,
    ) -> Result<Page<IdentityBinding>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let read = self.projection()?;
        let mut results = BTreeMap::new();
        for (key, visible) in read.scan(Family::Binding, &[], work)? {
            let namespace: [u8; 16] = key
                .get(..16)
                .ok_or_else(|| StoreError::Internal("truncated binding key".into()))?
                .try_into()
                .map_err(|_| StoreError::Internal("invalid binding namespace".into()))?;
            let namespace = uuid::Uuid::from_bytes(namespace);
            let bindings: Vec<IdentityBinding> = from_canonical(&visible.value)
                .map_err(|e| StoreError::Internal(format!("binding decode: {e}")))?;
            for b in bindings {
                if b.target == *target {
                    let cursor = format!("{namespace}:{}", b.source);
                    if page.after.as_ref().is_some_and(|after| cursor <= *after) {
                        continue;
                    }
                    results.insert(cursor, b);
                    if results.len() > page.limit.saturating_add(1) {
                        results.pop_last();
                    }
                }
            }
        }
        let entries =
            Page::from_oversized(results.into_iter().collect(), page.limit, |(cursor, _)| {
                cursor.clone()
            });
        Ok(Page {
            items: entries
                .items
                .into_iter()
                .map(|(_, binding)| binding)
                .collect(),
            next_after: entries.next_after,
        })
    }

    pub(crate) fn read_assertion(
        &self,
        kappa: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<IdentityAssertion, StoreError> {
        completed(
            &self.projection()?,
            Family::Assertion,
            kappa,
            "assertion",
            work,
        )?
        .ok_or_else(|| StoreError::NotFound(format!("assertion {kappa}")))
    }

    pub(crate) fn read_assertions_by_asserter(
        &self,
        asserter: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Vec<(Kappa, IdentityAssertion)>, StoreError> {
        settled_by_asserter(
            &self.projection()?,
            Family::AssertionByAsserter,
            Family::Assertion,
            asserter,
            "assertion",
            work,
        )
    }

    pub(crate) fn read_assertions_by_subject(
        &self,
        subject: &str,
        trust_filter: &dyn Fn(&[u8; 16]) -> bool,
        page: &PageRequest,
        work: &mut dyn Meter,
    ) -> Result<Page<(Kappa, IdentityAssertion)>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let after = page.after.as_deref().map(Kappa::parse).transpose()?;
        let prefix = format!("{subject}\x00");
        let read = self.projection()?;
        let mut selected = BTreeSet::new();
        for (_, member, _) in
            read.member_scan(Family::AssertionBySubject, prefix.as_bytes(), work)?
        {
            let (asserter_kb, assertion_kappa) = decode_subject_idx_value(&member)?;
            if !is_zero_asserter(&asserter_kb) && !trust_filter(&asserter_hash_128(&asserter_kb)) {
                continue;
            }
            if after
                .as_ref()
                .is_some_and(|after| assertion_kappa <= *after)
            {
                continue;
            }
            selected.insert(assertion_kappa);
            if selected.len() > page.limit.saturating_add(1) {
                selected.pop_last();
            }
        }
        let mut results = Vec::with_capacity(selected.len());
        for kappa in selected {
            let record = completed(&read, Family::Assertion, &kappa, "assertion", work)?
                .ok_or_else(|| {
                    StoreError::Internal("assertion index references missing record".into())
                })?;
            results.push((kappa, record));
        }
        Ok(Page::from_oversized(results, page.limit, |(kappa, _)| {
            kappa.to_string()
        }))
    }

    pub(crate) fn read_assertion_index(
        &self,
        subject: &str,
        work: &mut dyn Meter,
    ) -> Result<Vec<Kappa>, StoreError> {
        let prefix = format!("{subject}\x00");
        let mut results = Vec::new();
        let mut seen = BTreeSet::new();
        for (_, member, _) in
            self.projection()?
                .member_scan(Family::AssertionBySubject, prefix.as_bytes(), work)?
        {
            let (_asserter_kb, assertion_kappa) = decode_subject_idx_value(&member)?;
            if seen.insert(assertion_kappa.key_bytes()) {
                results.push(assertion_kappa);
            }
        }
        Ok(results)
    }

    pub(crate) fn read_revocation(
        &self,
        kappa: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Revocation, StoreError> {
        completed(
            &self.projection()?,
            Family::Revocation,
            kappa,
            "revocation",
            work,
        )?
        .ok_or_else(|| StoreError::NotFound(format!("revocation {kappa}")))
    }

    /// Every revocation `asserter` issued: complete or `Unavailable`
    /// (`issued_by`). A decision that an assertion stands depends on it.
    pub(crate) fn read_revocations_by_asserter(
        &self,
        asserter: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Vec<Revocation>, StoreError> {
        self.issued_by(asserter, &REVOCATIONS, work)
    }

    pub(crate) fn read_watermark(
        &self,
        kappa: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Watermark, StoreError> {
        completed(
            &self.projection()?,
            Family::Watermark,
            kappa,
            "watermark",
            work,
        )?
        .ok_or_else(|| StoreError::NotFound(format!("watermark {kappa}")))
    }

    /// Every watermark `asserter` issued: complete or `Unavailable`
    /// (`issued_by`).
    pub(crate) fn read_watermarks_by_asserter(
        &self,
        asserter: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Vec<Watermark>, StoreError> {
        self.issued_by(asserter, &WATERMARKS, work)
    }

    /// Every record of `issued`'s kind `asserter` issued, complete: the
    /// completed projection, every unsettled instance registered under the
    /// predicate read and confirmed in its own storage, and the completed
    /// projection again, which holds whatever completed (its registration
    /// dropped) between the first two reads. `Unavailable` when discovery is
    /// incomplete or a candidate cannot be read, and refused when `work`
    /// refuses, never a shorter list. Each record once, in identity order.
    ///
    /// A record committed before the call is in one of the three reads; one
    /// committing during it may or may not be. A caller that must exclude
    /// later commits orders them against its own action: authority
    /// activation holds the activation gate exclusively across this check
    /// and its commit, which every publication takes shared to sign and
    /// commit (`rotate_authority`).
    fn issued_by<T>(
        &self,
        asserter: &Kappa,
        issued: &Issued,
        work: &mut dyn Meter,
    ) -> Result<Vec<T>, StoreError>
    where
        T: TryFrom<dcbor::CBOR, Error = dcbor::Error>,
    {
        let subject = format!("{}s issued by {asserter}", issued.kind);
        let settled =
            |found: &mut BTreeMap<Kappa, T>, work: &mut dyn Meter| -> Result<(), StoreError> {
                found.extend(settled_by_asserter(
                    &self.projection()?,
                    issued.index,
                    issued.records,
                    asserter,
                    issued.kind,
                    work,
                )?);
                Ok(())
            };
        let mut found: BTreeMap<Kappa, T> = BTreeMap::new();
        settled(&mut found, work)?;
        let unsettled = self.every_unsettled_holder(
            &(issued.key)(asserter.clone()),
            &subject,
            work,
            |view: &crate::content_read::ReadView, work: &mut dyn Meter| {
                let rtxn = view.db.begin_read().map_err(crate::error::redb)?;
                namespace_by_asserter::<T>(
                    &rtxn,
                    issued.namespace_index,
                    issued.namespace_records,
                    asserter,
                    issued.kind,
                    work,
                )
            },
        )?;
        for listed in unsettled {
            found.extend(listed);
        }
        settled(&mut found, work)?;
        Ok(found.into_values().collect())
    }
}
