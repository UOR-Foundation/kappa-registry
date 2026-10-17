use crate::{
    PersistentStore,
    tables::{EDGE_ASR, EDGE_FWD, EDGE_REL, EDGE_REV, EDGES},
};
use kappa_store::EdgeStore;
use kappa_types::canonical::{canonical_bytes, from_canonical};
use kappa_types::edge::{Direction, Edge, EdgeInput, EdgeQuery, EdgeRelation};
use kappa_types::page::{Page, PageRequest};
use kappa_types::{Kappa, NamespaceRef, StoreError, VerifiedContent};
use redb::{
    MultimapTableDefinition, ReadableMultimapTable, ReadableTable, TableDefinition, TableError,
};

fn ns_key(ns: &NamespaceRef, payload: &[u8]) -> Vec<u8> {
    let mut key = ns.id().to_vec();
    key.extend_from_slice(payload);
    key
}

fn next_directional_key<'a>(
    left: &mut std::iter::Peekable<
        impl Iterator<Item = Result<redb::AccessGuard<'a, &'static [u8]>, redb::StorageError>>,
    >,
    right: &mut std::iter::Peekable<
        impl Iterator<Item = Result<redb::AccessGuard<'a, &'static [u8]>, redb::StorageError>>,
    >,
    direction: Direction,
) -> Result<Option<Vec<u8>>, StoreError> {
    if direction != Direction::Inbound && left.peek().is_some_and(Result::is_err) {
        left.next().transpose().map_err(crate::error::redb)?;
    }
    if direction != Direction::Outbound && right.peek().is_some_and(Result::is_err) {
        right.next().transpose().map_err(crate::error::redb)?;
    }
    let l = if direction == Direction::Inbound {
        None
    } else {
        left.peek()
            .and_then(|value| value.as_ref().ok())
            .map(|value| value.value().to_vec())
    };
    let r = if direction == Direction::Outbound {
        None
    } else {
        right
            .peek()
            .and_then(|value| value.as_ref().ok())
            .map(|value| value.value().to_vec())
    };
    let key = match (l, r) {
        (None, None) => return Ok(None),
        (Some(l), None) => {
            left.next().transpose().map_err(crate::error::redb)?;
            l
        }
        (Some(l), Some(r)) if l == r => {
            left.next().transpose().map_err(crate::error::redb)?;
            right.next().transpose().map_err(crate::error::redb)?;
            l
        }
        (Some(l), Some(r)) if l < r => {
            left.next().transpose().map_err(crate::error::redb)?;
            l
        }
        (_, Some(r)) => {
            right.next().transpose().map_err(crate::error::redb)?;
            r
        }
    };
    Ok(Some(key))
}

fn index_contains<'a>(
    values: &mut std::iter::Peekable<
        impl Iterator<Item = Result<redb::AccessGuard<'a, &'static [u8]>, redb::StorageError>>,
    >,
    key: &[u8],
) -> Result<bool, StoreError> {
    loop {
        match values.peek() {
            Some(Ok(value)) if value.value() < key => {
                values.next().transpose().map_err(crate::error::redb)?;
            }
            Some(Ok(value)) => return Ok(value.value() == key),
            Some(Err(_)) => {
                values.next().transpose().map_err(crate::error::redb)?;
            }
            None => return Ok(false),
        }
    }
}

/// An edge index table's definition.
type IndexDefinition = MultimapTableDefinition<'static, &'static [u8], &'static [u8]>;
/// The edge record table's definition.
type RecordDefinition = TableDefinition<'static, &'static [u8], &'static [u8]>;

/// The edge tables of one view: a read snapshot, or an execution's write
/// transaction so its own puts and deletes are visible.
struct EdgeTables<I, E> {
    forward: I,
    reverse: I,
    relations: I,
    asserters: I,
    records: E,
}

impl<I, E> EdgeTables<I, E> {
    /// The edge tables of one transaction, opened by its `index` and
    /// `records` openers: the one place the set of edge tables is named.
    fn open(
        index: impl Fn(IndexDefinition) -> Result<I, TableError>,
        records: impl FnOnce(RecordDefinition) -> Result<E, TableError>,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            forward: index(EDGE_FWD).map_err(crate::error::redb)?,
            reverse: index(EDGE_REV).map_err(crate::error::redb)?,
            relations: index(EDGE_REL).map_err(crate::error::redb)?,
            asserters: index(EDGE_ASR).map_err(crate::error::redb)?,
            records: records(EDGES).map_err(crate::error::redb)?,
        })
    }
}

impl PersistentStore {
    /// One page of `query` over `tables`.
    fn edge_query_in<I, E>(
        &self,
        tables: &EdgeTables<I, E>,
        ns: &NamespaceRef,
        query: &EdgeQuery,
        page: &PageRequest,
    ) -> Result<Page<Edge>, StoreError>
    where
        I: ReadableMultimapTable<&'static [u8], &'static [u8]>,
        E: ReadableTable<&'static [u8], &'static [u8]>,
    {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let after = page
            .after
            .as_deref()
            .map(Kappa::parse)
            .transpose()?
            .map(|key| key.key_bytes());
        let anchor = ns_key(ns, &query.anchor.key_bytes());
        let mut left = tables
            .forward
            .get(anchor.as_slice())
            .map_err(crate::error::redb)?
            .peekable();
        let mut right = tables
            .reverse
            .get(anchor.as_slice())
            .map_err(crate::error::redb)?
            .peekable();
        let relation = query
            .relation
            .as_ref()
            .map(|relation| ns_key(ns, &canonical_bytes(relation)));
        let asserter = query
            .asserter
            .as_ref()
            .map(|asserter| ns_key(ns, &asserter.key_bytes()));
        let mut relation_values = relation
            .as_ref()
            .map(|key| tables.relations.get(key.as_slice()))
            .transpose()
            .map_err(crate::error::redb)?
            .map(Iterator::peekable);
        let mut asserter_values = asserter
            .as_ref()
            .map(|key| tables.asserters.get(key.as_slice()))
            .transpose()
            .map_err(crate::error::redb)?
            .map(Iterator::peekable);
        let mut results = Vec::with_capacity(page.limit.min(1000));
        while let Some(raw) = next_directional_key(&mut left, &mut right, query.direction)? {
            if after.as_ref().is_some_and(|after| raw <= *after) {
                continue;
            }
            let mut selected = true;
            for values in [&mut relation_values, &mut asserter_values]
                .into_iter()
                .flatten()
            {
                selected &= index_contains(values, &raw)?;
            }
            if !selected {
                continue;
            }
            let key = ns_key(ns, &raw);
            let value = tables
                .records
                .get(key.as_slice())
                .map_err(crate::error::redb)?
                .ok_or_else(|| {
                    StoreError::Internal("edge index references missing record".into())
                })?;
            let input: EdgeInput = from_canonical(
                &self.decrypt_bytes(&crate::encrypted::bound("edge", &key), value.value())?,
            )?;
            let identity = Kappa::from_key_bytes(&raw)?;
            VerifiedContent::verify(&identity, &canonical_bytes(&input))?;
            results.push(Edge {
                kappa: identity,
                input,
            });
            if results.len() > page.limit {
                break;
            }
        }
        Ok(Page::from_oversized(results, page.limit, |edge| {
            edge.kappa.to_string()
        }))
    }

    /// `edge_query_in` over an execution's write transaction.
    pub(crate) fn edge_query_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        query: &EdgeQuery,
        page: &PageRequest,
    ) -> Result<Page<Edge>, StoreError> {
        let tables = EdgeTables::open(
            |index| txn.open_multimap_table(index),
            |records| txn.open_table(records),
        )?;
        self.edge_query_in(&tables, ns, query, page)
    }
}

// Edge writes are `EpochExecution::edge_put`, `edge_put_batch`, and
// `edge_delete`, which call `edge_mutation_put_in_txn` / `edge_delete_in_txn`
// inside the execution's writer and publish with its epoch.
impl EdgeStore for PersistentStore {
    fn edge_query(
        &self,
        ns: &NamespaceRef,
        query: &EdgeQuery,
        page: &PageRequest,
    ) -> Result<Page<Edge>, StoreError> {
        let snapshot = self.namespace_snapshot(ns)?;
        let txn = snapshot.transaction();
        let tables = EdgeTables::open(
            |index| txn.open_multimap_table(index),
            |records| txn.open_table(records),
        )?;
        self.edge_query_in(&tables, ns, query, page)
    }

    fn edge_cursor(
        &self,
        ns: &NamespaceRef,
        query: &EdgeQuery,
    ) -> Result<Box<dyn kappa_cursor::KappaCursor + '_>, StoreError> {
        let mut page = PageRequest::first(1024);
        let mut keys = Vec::new();
        loop {
            let result = self.edge_query(ns, query, &page)?;
            keys.extend(result.items.into_iter().map(|edge| edge.kappa.key_bytes()));
            match result.next_after {
                Some(after) => page.after = Some(after),
                None => break,
            }
        }
        Ok(Box::new(kappa_cursor::SliceCursor::from_owned(keys)))
    }

    fn edge_diff(
        &self,
        ns: &NamespaceRef,
        have: &[Kappa],
        want: &[Kappa],
        relations: &[EdgeRelation],
    ) -> Result<Vec<Kappa>, StoreError> {
        kappa_store::graph::edge_difference(self, ns, have, want, relations)
    }
}
