//! Operation paths: hierarchical dotted names with `+` composition.
//!
//! An operation names the work measured. `a+b` names two operations measured
//! as one inseparable unit; operands are sorted and deduplicated so the
//! canonical form is unique. Every operand must be registered: the registry
//! is the vocabulary the dependency graph, validation rules and roofline
//! classes are written against, so an unregistered operation could never be
//! gated, validated or graded.

use std::fmt;

/// A parsed operation path, possibly `+`-composed.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct OperationPath {
    /// Sorted, deduplicated operands. A single operation has one operand.
    operands: Vec<String>,
}

/// Why an operation path was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperationError {
    #[error("empty operation path")]
    Empty,
    #[error("operation '{0}' is not dotted labels of [a-z][a-z0-9_]*")]
    Syntax(String),
    #[error("operation '{0}' is not registered")]
    Unregistered(String),
}

impl OperationPath {
    /// Parse and validate against the registry.
    pub fn parse(path: &str) -> Result<Self, OperationError> {
        if path.is_empty() {
            return Err(OperationError::Empty);
        }
        let mut operands = Vec::new();
        for operand in path.split('+') {
            if !is_valid_syntax(operand) {
                return Err(OperationError::Syntax(operand.to_owned()));
            }
            if !SEEDED_OPERATIONS.contains(&operand) {
                return Err(OperationError::Unregistered(operand.to_owned()));
            }
            operands.push(operand.to_owned());
        }
        operands.sort();
        operands.dedup();
        Ok(Self { operands })
    }

    /// Canonical form: sorted operands joined by `+`.
    pub fn canonical(&self) -> String {
        self.operands.join("+")
    }

    pub fn operands(&self) -> &[String] {
        &self.operands
    }

    pub const fn is_composed(&self) -> bool {
        self.operands.len() > 1
    }

    /// Every distinct domain (first dotted label) across the operands.
    pub fn domains(&self) -> Vec<&str> {
        let mut domains: Vec<&str> = self
            .operands
            .iter()
            .filter_map(|operand| operand.split('.').next())
            .collect();
        domains.sort_unstable();
        domains.dedup();
        domains
    }
}

impl fmt::Display for OperationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

/// One or more labels of `[a-z][a-z0-9_]*` joined by `.`. Input is not
/// case-folded: the canonical vocabulary is lowercase and anything else is a
/// different, unregistered name.
fn is_valid_syntax(path: &str) -> bool {
    !path.is_empty()
        && path.split('.').all(|label| {
            let mut chars = label.chars();
            chars.next().is_some_and(|c| c.is_ascii_lowercase())
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// The registered operation vocabulary.
pub const SEEDED_OPERATIONS: &[&str] = &[
    // Memory hierarchy floors (PERF-CAL-010/011/012/014/023)
    "mem.read",
    "mem.write",
    "mem.copy",
    "mem.chase",
    "mem.alloc",
    "mem.zero",
    // Device floors: the persistent datapath (PERF-CAL-015/016/017)
    "device.seq_read",
    "device.seq_write",
    "device.rand_read",
    "device.rand_write",
    "device.fsync",
    "device.fdatasync",
    // Kernel and synchronization floors (PERF-CAL-021)
    "sys.getpid",
    "sys.futex",
    "sync.atomic",
    "sync.mutex",
    "sync.channel",
    "sync.wake",
    "sched.spawn_blocking",
    // Digest axes (PERF-CAL-018, PERF-HSH-010/011)
    "hash.sha256",
    "hash.sha512",
    "hash.blake3",
    "hash.sha1",
    "hash.sha3_256",
    "hash.keccak256",
    "hash.multi",
    // Signatures and typed boundaries (PERF-CAL-020, PERF-CRY-012)
    "crypto.sign.ed25519",
    "crypto.verify.ed25519",
    "crypto.sign.p256",
    "crypto.verify.p256",
    "crypto.sign.k256",
    "crypto.verify.k256",
    "crypto.cose.sign",
    "crypto.cose.verify",
    "crypto.admit.assertion",
    "crypto.admit.revocation",
    "crypto.admit.succession",
    "crypto.aead.seal",
    "crypto.aead.open",
    // Commitments (PERF-EPO-021/022)
    "merkle.root",
    "merkle.proof",
    "merkle.verify",
    "digest.insert",
    "digest.merge",
    "canonical.encode",
    "canonical.decode",
    // Generation publication primitives (PERF-STO-028)
    "arcswap.load",
    "arcswap.store",
    "imbl.insert",
    // Store workloads (PERF-STO-020..031)
    "store.tag_put",
    "store.tag_get",
    "store.publish",
    "store.blob_put",
    "store.blob_get",
    "store.blob_get_verified",
    "store.blob_get_range",
    "store.ingest",
    "store.epoch_get",
    "store.operation_replay",
    "store.edge_query",
    "store.multipart_complete",
    "redb.commit",
    "redb.read",
    // Epoch authority (PERF-EPO-020/023)
    "epoch.sign",
    "epoch.verify",
    "replay.ledger",
    "gc.sweep",
    // Staging transactions (PERF-STO-007)
    "txn.put",
    "txn.promote",
    // Succinct index (PERF-SUC-030..041)
    "index.seek",
    "index.advance",
    "index.rebuild",
    "index.insert",
    // Requests through the assembled server, end to end over TCP
    "http.blob_get",
    "http.blob_put",
    "http.manifest_get",
];

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn simple_path() -> TestResult {
        let op = OperationPath::parse("store.publish")?;
        assert_eq!(op.canonical(), "store.publish");
        assert!(!op.is_composed());
        assert_eq!(op.domains(), vec!["store"]);
        Ok(())
    }

    #[test]
    fn composition_sorts_and_deduplicates() -> TestResult {
        let op = OperationPath::parse("store.tag_put+crypto.sign.ed25519+store.tag_put")?;
        assert_eq!(op.canonical(), "crypto.sign.ed25519+store.tag_put");
        assert!(op.is_composed());
        assert_eq!(op.domains(), vec!["crypto", "store"]);
        Ok(())
    }

    #[test]
    fn rejects_syntax_and_unregistered() {
        assert_eq!(OperationPath::parse(""), Err(OperationError::Empty));
        for bad in [
            "Store.publish",
            "store..publish",
            ".store",
            "store.",
            "9store.x",
        ] {
            assert!(
                matches!(OperationPath::parse(bad), Err(OperationError::Syntax(_))),
                "{bad} must be a syntax error"
            );
        }
        assert_eq!(
            OperationPath::parse("store.nonexistent"),
            Err(OperationError::Unregistered("store.nonexistent".into()))
        );
        assert!(matches!(
            OperationPath::parse("store.publish+mem.bogus"),
            Err(OperationError::Unregistered(_))
        ));
    }

    #[test]
    fn registry_is_valid_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for op in SEEDED_OPERATIONS {
            assert!(is_valid_syntax(op), "{op} has invalid syntax");
            assert!(seen.insert(*op), "{op} registered twice");
        }
    }
}
