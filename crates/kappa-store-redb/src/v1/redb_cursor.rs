//! Native redb traversal: the borrowed range over any byte-keyed table
//! within a shared interval ([`rows`]), and the retained reader that owns
//! its read root across calls ([`RedbCursor`]).

use kappa_cursor::FallibleCursor;
use kappa_cursor::interval::Interval;
use kappa_store::work::{Dimension, Meter};
use kappa_types::StoreError;
use redb::{AccessGuard, ReadOnlyTable, ReadableTable, ReadableTableMetadata};

/// The rows of one table within an interval, borrowed from the table: no
/// mutation of the table is possible while the range or a row it yielded
/// is held, so a mutating caller copies what it needs and drops both
/// first. An exhausted interval holds no native range at all.
pub(crate) enum Rows<'t, V: redb::Value + 'static> {
    Exhausted,
    Native(redb::Range<'t, &'static [u8], V>),
}

/// One row of [`Rows`], as redb's guards over its page.
pub(crate) type Row<'t, V> = (AccessGuard<'t, &'static [u8]>, AccessGuard<'t, V>);

impl<'t, V: redb::Value + 'static> Iterator for Rows<'t, V> {
    type Item = Result<Row<'t, V>, StoreError>;

    /// The next row in key order. A native failure stays a failure on every
    /// later call (redb latches it), never exhaustion.
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Exhausted => None,
            Self::Native(range) => range.next().map(|row| row.map_err(crate::error::redb)),
        }
    }
}

impl<V: redb::Value + 'static> DoubleEndedIterator for Rows<'_, V> {
    /// The last remaining row in key order.
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Exhausted => None,
            Self::Native(range) => range.next_back().map(|row| row.map_err(crate::error::redb)),
        }
    }
}

/// The rows of `table` within `interval`, in key order. The bytes redb
/// copies to encode the interval's bounds (`Interval::bound_bytes`) are
/// accounted on `unit`, the admitted unit (`Meter::admit`) whose bound
/// includes them; an exhausted interval builds no native range and copies
/// nothing. Examining each row, copying it and decoding it are the
/// caller's, admitted before the row is read.
pub(crate) fn rows<'t, V: redb::Value + 'static>(
    table: &'t impl ReadableTable<&'static [u8], V>,
    interval: &Interval,
    unit: &mut dyn Meter,
) -> Result<Rows<'t, V>, StoreError> {
    let Some(bounds) = interval.bounds() else {
        return Ok(Rows::Exhausted);
    };
    let copied = interval
        .bound_bytes()
        .ok_or_else(|| StoreError::Internal("native range bounds exceed u64".into()))?;
    unit.account(Dimension::BytesAllocated, copied)?;
    table
        .range::<&[u8]>(bounds)
        .map(Rows::Native)
        .map_err(crate::error::redb)
}

/// Native range over one retained redb read root.
///
/// Only the current key is copied. `ReadOnlyTable` and `Range` retain redb's transaction guard; dropping
/// the originating read transaction does not retire this reader's pages.
pub struct RedbCursor {
    table: ReadOnlyTable<&'static [u8], &'static [u8]>,
    range: redb::Range<'static, &'static [u8], &'static [u8]>,
    head: Option<Vec<u8>>,
    failure: Option<std::sync::Arc<StoreError>>,
    remaining: u64,
}

impl RedbCursor {
    pub fn new(table: ReadOnlyTable<&'static [u8], &'static [u8]>) -> Result<Self, StoreError> {
        let remaining = table.len().map_err(crate::error::redb)?;
        let range = table.range::<&[u8]>(..).map_err(crate::error::redb)?;
        let mut cursor = Self {
            table,
            range,
            head: None,
            failure: None,
            remaining,
        };
        cursor.load_next()?;
        Ok(cursor)
    }

    fn load_next(&mut self) -> Result<(), StoreError> {
        match self.range.next() {
            Some(Ok((key, _))) => self.head = Some(key.value().to_vec()),
            Some(Err(error)) => {
                return Err(self.fail(crate::error::redb(error)));
            }
            None => {
                self.head = None;
                self.remaining = 0;
            }
        }
        Ok(())
    }

    fn ensure_valid(&self) -> Result<(), StoreError> {
        self.failure
            .as_ref()
            .map_or_else(|| Ok(()), |error| Err(Self::retained_error(error)))
    }

    fn fail(&mut self, error: StoreError) -> StoreError {
        self.head = None;
        let error = std::sync::Arc::new(error);
        let result = Self::retained_error(&error);
        self.failure = Some(error);
        result
    }

    /// A fresh error carrying the retained failure's kind and OS error, so a
    /// latched I/O failure stays distinguishable from internal corruption on
    /// every later call.
    pub(crate) fn retained_error(error: &std::sync::Arc<StoreError>) -> StoreError {
        match error.as_ref() {
            StoreError::Io(io) => StoreError::Io(io.raw_os_error().map_or_else(
                || std::io::Error::new(io.kind(), std::sync::Arc::clone(error)),
                std::io::Error::from_raw_os_error,
            )),
            StoreError::Internal(message) => StoreError::Internal(message.clone()),
            // A traversal whose operation's allowance refused stays refused,
            // never relabelled a storage failure.
            StoreError::WorkRefused(refused) => StoreError::WorkRefused(*refused),
            // redb navigation converts only I/O and corruption errors here.
            other => StoreError::Internal(other.to_string()),
        }
    }
}

impl FallibleCursor for RedbCursor {
    type Error = StoreError;

    fn key(&self) -> Result<Option<&[u8]>, StoreError> {
        self.ensure_valid()?;
        Ok(self.head.as_deref())
    }

    fn advance(&mut self) -> Result<Option<&[u8]>, StoreError> {
        self.ensure_valid()?;
        if self.head.is_some() {
            self.remaining = self.remaining.saturating_sub(1);
            self.load_next()?;
        }
        self.key()
    }

    fn seek(&mut self, target: &[u8]) -> Result<Option<&[u8]>, StoreError> {
        self.ensure_valid()?;
        if self.head.as_deref().is_some_and(|head| head < target) {
            match self.table.range::<&[u8]>(target..) {
                Ok(range) => self.range = range,
                Err(error) => {
                    return Err(self.fail(crate::error::redb(error)));
                }
            }
            // Re-ranging skips an unknown number of keys. Preserve the old
            // upper bound rather than inventing an exact remaining count.
            self.load_next()?;
        }
        self.key()
    }

    fn size_hint(&self) -> u64 {
        self.remaining
    }
    fn cost(&self) -> u64 {
        // Native range traversal loads pages; this conservative linear unit
        // estimate is not a measured latency or an invented I/O multiplier.
        self.remaining
    }
}
