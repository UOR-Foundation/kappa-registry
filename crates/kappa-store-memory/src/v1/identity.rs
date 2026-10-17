//! The `IdentityStore` contract over namespace views.
//!
//! Every record is a row of the view of the namespace that published it.
//! Registry-wide reads find namespaces through the identity projections
//! and decide from their published views (`locate`); exclusive rows
//! (handles, locator records, revocation commitments, authorization rows)
//! are read from the view of their claim holder; succession links are read
//! from the succession graph, which admitted them against every namespace.
//!
//! Assertions, revocations and watermarks are immutable evidence keyed by
//! their full content identity: a record published by several namespaces
//! is one record, listed once.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::ops::Bound::{self, Excluded, Included, Unbounded};
use std::sync::Arc;

use imbl::{OrdMap, OrdSet};
use kappa_store::traits::identity::{CredentialLookup, IdentityStore, asserter_filter_key};
use kappa_types::clock::ClockMs;
use kappa_types::error::StoreError;
use kappa_types::identity::{
    DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord, PrekeyBinding,
    Revocation, RevocationCommitment, Succession, TrustPosition, Watermark,
};
use kappa_types::kappa::Kappa;
use kappa_types::namespace::ProtocolId;
use kappa_types::page::{Page, PageRequest};

use super::InMemoryStore;
use super::claims::ClaimKey;
use super::identity_write::handle_key;
use super::locate::{CANDIDATE_BOUND, CANDIDATE_PAGE, Holders, LISTING_FACTOR, incomplete};
use super::locator::Locator;
use super::view::{IdentityRows, NamespaceView};

/// A binding listing cursor: `{namespace uuid}:{source}`.
fn binding_cursor(namespace: &[u8; 16], source: &str) -> String {
    format!("{}:{source}", uuid::Uuid::from_bytes(*namespace))
}

fn parse_binding_cursor(cursor: &str) -> Result<([u8; 16], String), StoreError> {
    let (namespace, source) = cursor.split_once(':').ok_or_else(|| {
        StoreError::Rejected(format!("binding cursor {cursor:?} names no source"))
    })?;
    let namespace = uuid::Uuid::parse_str(namespace)
        .map_err(|error| StoreError::Rejected(format!("binding cursor namespace: {error}")))?;
    Ok((namespace.into_bytes(), source.to_owned()))
}

/// One subject facet's assertions in one namespace's published view.
struct Stream {
    view: Arc<NamespaceView>,
    facet: String,
}

impl InMemoryStore {
    /// Records `index` lists under `asserter` across every namespace,
    /// once each, in identity key order.
    fn by_asserter<T: Clone>(
        &self,
        locator: &Locator<Kappa>,
        asserter: &Kappa,
        index: impl Fn(&IdentityRows) -> &OrdMap<Kappa, OrdSet<Kappa>>,
        records: impl Fn(&IdentityRows) -> &OrdMap<Kappa, T>,
        kind: &str,
    ) -> Result<Vec<(Kappa, T)>, StoreError> {
        let mut found: BTreeMap<Vec<u8>, (Kappa, T)> = BTreeMap::new();
        let complete = self.located(locator, asserter, |_, view| {
            let rows = &view.identity;
            for identity in index(rows).get(asserter).into_iter().flatten() {
                if let Some(record) = records(rows).get(identity) {
                    found
                        .entry(identity.key_bytes())
                        .or_insert_with(|| (identity.clone(), record.clone()));
                }
            }
            false
        });
        if !complete {
            return Err(incomplete(&format_args!("{kind}s of {asserter}")));
        }
        Ok(found.into_values().collect())
    }

    /// Every (namespace view, facet key) holding assertions about
    /// `subject`, examining at most `CANDIDATE_BOUND` candidates.
    fn subject_streams(&self, subject: &str) -> Result<Vec<Stream>, StoreError> {
        let prefix = format!("{subject}\x00");
        let locator = &self.projections.assertion_subjects;
        let mut streams = Vec::new();
        let mut examined = 0usize;
        let mut last: Option<String> = None;
        loop {
            let lower = last.as_ref().map_or(Included(&prefix), Excluded);
            let keys = locator.range(lower, CANDIDATE_PAGE, CANDIDATE_PAGE);
            let exhausted = keys.len() < CANDIDATE_PAGE;
            for (facet, candidates, more) in keys {
                if !facet.starts_with(&prefix) {
                    return Ok(streams);
                }
                let mut admit = |view: &Arc<NamespaceView>| {
                    if view.identity.assertion_subjects.contains_key(&facet) {
                        streams.push(Stream {
                            view: Arc::clone(view),
                            facet: facet.clone(),
                        });
                    }
                };
                for candidate in candidates {
                    examined += 1;
                    if examined > CANDIDATE_BOUND {
                        return Err(incomplete(&format_args!("assertions about {subject}")));
                    }
                    if let Some(view) = self.confirm(candidate) {
                        admit(&view);
                    }
                }
                if let Some(next) = more
                    && !self.located_from(locator, &facet, Excluded(next), |_, view| {
                        admit(view);
                        false
                    })
                {
                    return Err(incomplete(&format_args!("assertions about {subject}")));
                }
                last = Some(facet);
            }
            if exhausted {
                return Ok(streams);
            }
        }
    }

    /// The assertions about `subject` after `after`, in identity order,
    /// each once, offered to `visit` with its record until it returns
    /// false.
    fn subject_merge(
        &self,
        subject: &str,
        after: Option<&Kappa>,
        mut visit: impl FnMut(&Kappa, &IdentityAssertion) -> Result<bool, StoreError>,
    ) -> Result<(), StoreError> {
        let streams = self.subject_streams(subject)?;
        let lower: Bound<&Kappa> = after.map_or(Unbounded, Excluded);
        let mut cursors: Vec<_> = streams
            .iter()
            .map(|stream| {
                stream
                    .view
                    .identity
                    .assertion_subjects
                    .get(&stream.facet)
                    .map(|set| set.range::<_, Kappa>((lower, Unbounded)))
            })
            .collect();
        let mut heap = BinaryHeap::new();
        for (index, cursor) in cursors.iter_mut().enumerate() {
            if let Some(next) = cursor.as_mut().and_then(Iterator::next) {
                heap.push(Reverse((next, index)));
            }
        }
        let mut previous: Option<&Kappa> = None;
        while let Some(Reverse((identity, index))) = heap.pop() {
            if let Some(next) = cursors[index].as_mut().and_then(Iterator::next) {
                heap.push(Reverse((next, index)));
            }
            if previous == Some(identity) {
                continue;
            }
            previous = Some(identity);
            let record = streams[index]
                .view
                .identity
                .assertions
                .get(identity)
                .ok_or_else(|| {
                    StoreError::Internal("assertion index references missing record".into())
                })?;
            if !visit(identity, record)? {
                return Ok(());
            }
        }
        Ok(())
    }
}

impl IdentityStore for InMemoryStore {
    fn binding_get(&self, source: &str) -> Result<Vec<IdentityBinding>, StoreError> {
        let key = source.to_owned();
        self.gather(
            &self.projections.binding_sources,
            &key,
            |_, view, out| {
                out.extend(
                    view.identity
                        .bindings
                        .get(source)
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
            },
            &format_args!("bindings of {source}"),
        )
    }

    fn binding_list_by_target(
        &self,
        target: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<IdentityBinding>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let after = page
            .after
            .as_deref()
            .map(parse_binding_cursor)
            .transpose()?;
        let from = after
            .as_ref()
            .map_or(Unbounded, |(namespace, _)| Included(*namespace));
        let take = page.limit.saturating_add(1);
        let mut items: Vec<(String, IdentityBinding)> = Vec::new();
        let complete = self.located_from(
            &self.projections.binding_targets,
            target,
            from,
            |namespace, view| {
                let lower = match &after {
                    Some((at, source)) if *at == namespace => Excluded(source.as_str()),
                    _ => Unbounded,
                };
                let rows = &view.identity;
                for source in rows
                    .binding_targets
                    .get(target)
                    .into_iter()
                    .flat_map(|sources| sources.range::<_, str>((lower, Unbounded)))
                {
                    let bound = rows
                        .bindings
                        .get(source)
                        .into_iter()
                        .flatten()
                        .filter(|binding| binding.target == *target);
                    for binding in bound {
                        items.push((binding_cursor(&namespace, source), binding.clone()));
                        if items.len() >= take {
                            return true;
                        }
                    }
                }
                false
            },
        );
        if !complete {
            return Err(incomplete(&format_args!("bindings of {target}")));
        }
        let entries = Page::from_oversized(items, page.limit, |(cursor, _)| cursor.clone());
        Ok(Page {
            items: entries
                .items
                .into_iter()
                .map(|(_, binding)| binding)
                .collect(),
            next_after: entries.next_after,
        })
    }

    fn assertion_get(&self, kappa: &Kappa) -> Result<IdentityAssertion, StoreError> {
        self.find(
            &self.projections.assertions,
            kappa,
            |view| view.identity.assertions.get(kappa).cloned(),
            &format_args!("assertion {kappa}"),
        )
    }

    fn assertion_list_by_asserter(
        &self,
        asserter: &Kappa,
    ) -> Result<Vec<(Kappa, IdentityAssertion)>, StoreError> {
        self.by_asserter(
            &self.projections.assertion_asserters,
            asserter,
            |rows| &rows.assertion_asserters,
            |rows| &rows.assertions,
            "assertion",
        )
    }

    fn assertion_list_by_subject(
        &self,
        subject: &str,
        page: &PageRequest,
    ) -> Result<Page<(Kappa, IdentityAssertion)>, StoreError> {
        self.assertion_list_by_subject_filtered(subject, &|_| true, page)
    }

    /// Assertions the filter refuses count against the examination budget;
    /// a page that did not fill within it continues after the last
    /// assertion examined.
    fn assertion_list_by_subject_filtered(
        &self,
        subject: &str,
        trust_filter: &dyn Fn(&[u8; 16]) -> bool,
        page: &PageRequest,
    ) -> Result<Page<(Kappa, IdentityAssertion)>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let after = page.after.as_deref().map(Kappa::parse).transpose()?;
        let budget = page
            .limit
            .saturating_mul(LISTING_FACTOR)
            .max(page.limit.saturating_add(1));
        let mut items = Vec::new();
        let mut examined = 0usize;
        let mut last_examined = None;
        let mut exhausted_budget = false;
        self.subject_merge(subject, after.as_ref(), |identity, record| {
            if examined == budget {
                exhausted_budget = true;
                return Ok(false);
            }
            examined += 1;
            last_examined = Some(identity.clone());
            if trust_filter(&asserter_filter_key(&record.asserter)) {
                items.push((identity.clone(), record.clone()));
            }
            Ok(items.len() <= page.limit)
        })?;
        if items.len() > page.limit {
            return Ok(Page::from_oversized(items, page.limit, |(kappa, _)| {
                kappa.to_string()
            }));
        }
        Ok(Page {
            items,
            next_after: if exhausted_budget {
                last_examined.map(|kappa| kappa.to_string())
            } else {
                None
            },
        })
    }

    fn revocation_get(&self, kappa: &Kappa) -> Result<Revocation, StoreError> {
        self.find(
            &self.projections.revocations,
            kappa,
            |view| view.identity.revocations.get(kappa).cloned(),
            &format_args!("revocation {kappa}"),
        )
    }

    fn revocation_list_by_asserter(&self, asserter: &Kappa) -> Result<Vec<Revocation>, StoreError> {
        Ok(self
            .by_asserter(
                &self.projections.revocation_asserters,
                asserter,
                |rows| &rows.revocation_asserters,
                |rows| &rows.revocations,
                "revocation",
            )?
            .into_iter()
            .map(|(_, record)| record)
            .collect())
    }

    fn succession_get(&self, old_anchor: &Kappa) -> Result<Kappa, StoreError> {
        self.successions
            .successor(old_anchor)
            .map(|record| record.new_anchor)
            .ok_or_else(|| StoreError::NotFound(format!("successor of {old_anchor}")))
    }

    fn watermark_get(&self, kappa: &Kappa) -> Result<Watermark, StoreError> {
        self.find(
            &self.projections.watermarks,
            kappa,
            |view| view.identity.watermarks.get(kappa).cloned(),
            &format_args!("watermark {kappa}"),
        )
    }

    fn watermark_list_by_asserter(&self, asserter: &Kappa) -> Result<Vec<Watermark>, StoreError> {
        Ok(self
            .by_asserter(
                &self.projections.watermark_asserters,
                asserter,
                |rows| &rows.watermark_asserters,
                |rows| &rows.watermarks,
                "watermark",
            )?
            .into_iter()
            .map(|(_, record)| record)
            .collect())
    }

    fn handle_get(&self, protocol: ProtocolId, handle: &str) -> Result<HandleRecord, StoreError> {
        self.handle_published(&protocol, handle).ok_or_else(|| {
            StoreError::NotFound(format!("handle {}", handle_key(&protocol, handle)))
        })
    }

    fn handle_list(&self, page: &PageRequest) -> Result<Page<HandleRecord>, StoreError> {
        self.listing(
            &self.projections.handles,
            page.after.as_ref(),
            page.limit,
            Holders::First,
            |key, view, out| out.extend(view.identity.handles.get(key).cloned()),
            Clone::clone,
        )
    }

    fn handle_list_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<HandleRecord>, StoreError> {
        self.handles_by_anchor(anchor, page, None)
    }

    fn session_get(&self, token: &str, now: ClockMs) -> Result<(Kappa, Vec<u8>), StoreError> {
        self.read_session(token, now)
    }

    fn session_evict(&self, now: ClockMs) -> Result<u64, StoreError> {
        self.evict_sessions(now)
    }

    fn credential_get(
        &self,
        credential_id: &str,
        now: ClockMs,
    ) -> Result<CredentialLookup, StoreError> {
        self.read_credential(credential_id, now)
    }

    fn trust_position_get(&self) -> Result<TrustPosition, StoreError> {
        Ok(self.read_trust_position())
    }

    fn device_binding_list(&self, anchor: &Kappa) -> Result<Vec<DeviceBinding>, StoreError> {
        self.gather(
            &self.projections.devices,
            anchor,
            |_, view, out| {
                out.extend(
                    view.identity
                        .devices
                        .get(anchor)
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
            },
            &format_args!("device bindings of {anchor}"),
        )
    }

    fn prekey_binding_list(&self, anchor: &Kappa) -> Result<Vec<PrekeyBinding>, StoreError> {
        self.gather(
            &self.projections.prekeys,
            anchor,
            |_, view, out| {
                out.extend(
                    view.identity
                        .prekeys
                        .get(anchor)
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
            },
            &format_args!("prekey bindings of {anchor}"),
        )
    }

    fn locator_get(&self, anchor: &Kappa) -> Result<Option<LocatorRecord>, StoreError> {
        Ok(self
            .claimed(&ClaimKey::Locator(anchor.clone()))
            .and_then(|view| view.identity.locators.get(anchor).cloned()))
    }

    fn succession_chain_get(&self, anchor: &Kappa) -> Result<Vec<Succession>, StoreError> {
        self.successions.chain(anchor)
    }

    fn revocation_commitment_get(
        &self,
        anchor: &Kappa,
    ) -> Result<Option<RevocationCommitment>, StoreError> {
        Ok(self
            .claimed(&ClaimKey::Commitment(anchor.clone()))
            .and_then(|view| view.identity.commitments.get(anchor).cloned()))
    }

    fn assertion_index_query(&self, subject: &str) -> Result<Vec<Kappa>, StoreError> {
        let mut identities = Vec::new();
        self.subject_merge(subject, None, |identity, _| {
            identities.push(identity.clone());
            Ok(true)
        })?;
        Ok(identities)
    }
}
