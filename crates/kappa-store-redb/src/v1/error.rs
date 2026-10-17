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

pub fn crypto(error: kappa_crypto::CryptoError) -> StoreError {
    match error {
        kappa_crypto::CryptoError::Io(error) => StoreError::Io(error),
        error => StoreError::Internal(format!("crypto: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
