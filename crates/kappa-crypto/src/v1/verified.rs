//! Signature evidence owned by the cryptographic verification boundary.

/// A record whose signatures have been checked by this crate.
/// Signature validity does not imply authorization, freshness, or chain admission.
///
/// ```compile_fail
/// use kappa_crypto::Verified;
/// let forged = Verified::from_verified(42_u64);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }

    pub(crate) fn from_verified(inner: T) -> Self {
        Self(inner)
    }
}
