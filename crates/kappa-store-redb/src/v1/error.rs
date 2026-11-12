//! Backend-owned conversion into the protocol-neutral storage error boundary.
use kappa_types::StoreError;

pub fn redb(error: impl Into<redb::Error>) -> StoreError {
    match error.into() {
        redb::Error::Io(error) => StoreError::Io(error),
        redb::Error::DatabaseAlreadyOpen => StoreError::Conflict("database already open".into()),
        redb::Error::TableDoesNotExist(name) => StoreError::NotFound(format!("redb table: {name}")),
        redb::Error::Corrupted(message) => {
            StoreError::Internal(format!("redb corrupted: {message}"))
        }
        error => StoreError::Internal(format!("redb: {error}")),
    }
}

/// Why a write transaction did not commit, classified by what is known of
/// its durability. Every redb commit, of a namespace or of the registry, is
/// classified by [`classify_commit`]; what an unknown outcome obliges
/// (fencing, retained custody, an unresolved lifecycle) is decided by the
/// owner of the write, never by converting this into a plain error.
#[derive(Debug)]
pub(crate) enum CommitFailure {
    /// The transaction did not commit; nothing of it persists.
    Known(StoreError),
    /// Whether the transaction persisted is unknown.
    Unknown(StoreError),
}

impl std::fmt::Display for CommitFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Known(error) => write!(formatter, "commit known not to have happened: {error}"),
            Self::Unknown(error) => write!(formatter, "commit outcome unknown: {error}"),
        }
    }
}

impl std::error::Error for CommitFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Known(error) | Self::Unknown(error) => Some(error),
        }
    }
}

/// Classify a redb commit by redb's contract
/// (`redb::WriteTransaction::commit`): a poisoned transaction is rolled back
/// and commits nothing; any other failure may already be durable.
pub(crate) fn classify_commit(result: Result<(), redb::CommitError>) -> Result<(), CommitFailure> {
    match result {
        Ok(()) => Ok(()),
        Err(error @ redb::CommitError::TransactionPoisoned) => {
            Err(CommitFailure::Known(redb(error)))
        }
        Err(error) => Err(CommitFailure::Unknown(redb(error))),
    }
}

pub fn crypto(error: kappa_crypto::CryptoError) -> StoreError {
    match error {
        kappa_crypto::CryptoError::Io(error) => StoreError::Io(error),
        error => StoreError::Internal(format!("crypto: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// redb's commit contract, classified: a poisoned transaction was
    /// rolled back (known); any storage failure may have persisted it.
    #[test]
    fn a_poisoned_commit_is_known_and_a_storage_failure_unknown() {
        assert!(classify_commit(Ok(())).is_ok());
        assert!(matches!(
            classify_commit(Err(redb::CommitError::TransactionPoisoned)),
            Err(CommitFailure::Known(_))
        ));
        assert!(matches!(
            classify_commit(Err(redb::CommitError::Storage(redb::StorageError::Io(
                std::io::Error::other("write failed")
            )))),
            Err(CommitFailure::Unknown(StoreError::Io(_)))
        ));
    }

    #[test]
    fn io_identity_and_actionable_categories_survive_conversion() {
        let io = std::io::Error::from_raw_os_error(28);
        match redb(redb::StorageError::Io(io)) {
            StoreError::Io(error) => assert_eq!(error.raw_os_error(), Some(28)),
            other => panic!("lost I/O error identity: {other}"),
        }
        assert!(matches!(
            redb(redb::DatabaseError::DatabaseAlreadyOpen),
            StoreError::Conflict(_)
        ));
        assert!(
            matches!(redb(redb::TableError::TableDoesNotExist("missing".into())), StoreError::NotFound(message) if message.contains("missing"))
        );
        assert!(
            matches!(redb(redb::StorageError::Corrupted("damaged".into())), StoreError::Internal(message) if message.contains("damaged"))
        );
    }
}
