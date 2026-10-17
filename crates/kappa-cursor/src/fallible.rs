/// Ordered traversal of a source whose navigation can fail.
///
/// Construction positions on the first key. Successful exhaustion returns
/// None; failure returns Err and must remain distinguishable from exhaustion
/// on every subsequent call. Seek never moves backward or revives exhaustion.
/// Implementations retain the resources establishing their read view.
/// This contract knows neither storage error types nor protocol semantics.
pub trait FallibleCursor: Send {
    type Error;

    fn key(&self) -> Result<Option<&[u8]>, Self::Error>;
    fn advance(&mut self) -> Result<Option<&[u8]>, Self::Error>;
    fn seek(&mut self, target: &[u8]) -> Result<Option<&[u8]>, Self::Error>;
    /// Conservative remaining cardinality upper bound, not an I/O estimate.
    fn size_hint(&self) -> u64;
    /// Source-specific execution estimate, distinct from cardinality.
    fn cost(&self) -> u64;
}

/// Lift an infallible source without changing its navigation or ownership.
pub struct InfallibleCursor<C, E> {
    source: C,
    error: std::marker::PhantomData<fn() -> E>,
}

impl<C, E> InfallibleCursor<C, E> {
    pub const fn new(source: C) -> Self {
        Self {
            source,
            error: std::marker::PhantomData,
        }
    }
}

impl<C: crate::KappaCursor, E> FallibleCursor for InfallibleCursor<C, E> {
    type Error = E;
    fn key(&self) -> Result<Option<&[u8]>, E> {
        let key = self.source.key();
        Ok((key != crate::TERMINATED).then_some(key))
    }
    fn advance(&mut self) -> Result<Option<&[u8]>, E> {
        self.source.advance();
        self.key()
    }
    fn seek(&mut self, target: &[u8]) -> Result<Option<&[u8]>, E> {
        self.source.seek(target);
        self.key()
    }
    fn size_hint(&self) -> u64 {
        self.source.size_hint()
    }
    fn cost(&self) -> u64 {
        self.source.cost()
    }
}

impl<C: FallibleCursor + ?Sized> FallibleCursor for Box<C> {
    type Error = C::Error;
    fn key(&self) -> Result<Option<&[u8]>, Self::Error> {
        (**self).key()
    }
    fn advance(&mut self) -> Result<Option<&[u8]>, Self::Error> {
        (**self).advance()
    }
    fn seek(&mut self, target: &[u8]) -> Result<Option<&[u8]>, Self::Error> {
        (**self).seek(target)
    }
    fn size_hint(&self) -> u64 {
        (**self).size_hint()
    }
    fn cost(&self) -> u64 {
        (**self).cost()
    }
}
