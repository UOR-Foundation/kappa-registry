//! Accumulative dependency graph over operations.
//!
//! A composite measurement is meaningful only when the floors it decomposes
//! into were measured on the same host: `store.blob_put` is bounded by the
//! digest it computes and the device it writes, `redb.commit` by `fsync`.
//! The graph names those constituents. A session skips a measurement whose
//! transitive dependencies are not established, and reports which are
//! missing. Dependencies are quantity-agnostic: `bw/device.seq_write`
//! satisfies a dependency on `device.seq_write` for a `lat` subject.

use std::collections::{BTreeMap, BTreeSet};

use super::operation::OperationPath;

/// Operation -> operations it directly depends on.
pub struct DependencyGraph {
    edges: BTreeMap<&'static str, &'static [&'static str]>,
}

impl DependencyGraph {
    pub fn seeded() -> Self {
        Self {
            edges: SEEDED_DEPS.iter().copied().collect(),
        }
    }

    pub fn direct_deps(&self, operation: &str) -> &'static [&'static str] {
        self.edges.get(operation).copied().unwrap_or(&[])
    }

    /// Transitive closure of an operation's dependencies.
    pub fn transitive_deps(&self, operation: &str) -> BTreeSet<&'static str> {
        let mut closure = BTreeSet::new();
        let mut stack = self.direct_deps(operation).to_vec();
        while let Some(dep) = stack.pop() {
            if closure.insert(dep) {
                stack.extend_from_slice(self.direct_deps(dep));
            }
        }
        closure
    }

    /// Dependencies of a possibly composed operation: the union over its
    /// operands, minus the operands themselves (a composite is measured as
    /// one unit and never requires its own parts separately).
    pub fn deps_of(&self, operation: &OperationPath) -> BTreeSet<&'static str> {
        let mut deps = BTreeSet::new();
        for operand in operation.operands() {
            deps.extend(self.transitive_deps(operand));
        }
        for operand in operation.operands() {
            deps.remove(operand.as_str());
        }
        deps
    }

    /// Accumulative execution order: every operation after its dependencies.
    pub fn topo_order(&self) -> Vec<&'static str> {
        fn visit(
            graph: &DependencyGraph,
            op: &'static str,
            done: &mut BTreeSet<&'static str>,
            order: &mut Vec<&'static str>,
        ) {
            if done.insert(op) {
                for dep in graph.direct_deps(op) {
                    visit(graph, dep, done, order);
                }
                order.push(op);
            }
        }
        let mut done = BTreeSet::new();
        let mut order = Vec::with_capacity(self.edges.len());
        for op in self.edges.keys() {
            visit(self, op, &mut done, &mut order);
        }
        order
    }

    pub fn operations(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.edges.keys().copied()
    }
}

/// Seeded declarations. Every registered operation has exactly one entry.
const SEEDED_DEPS: &[(&str, &[&str])] = &[
    ("mem.read", &[]),
    ("mem.write", &[]),
    ("mem.copy", &[]),
    ("mem.chase", &[]),
    ("mem.alloc", &[]),
    ("mem.zero", &[]),
    ("device.seq_read", &[]),
    ("device.seq_write", &[]),
    ("device.rand_read", &[]),
    ("device.rand_write", &[]),
    ("device.fsync", &["device.seq_write"]),
    ("device.fdatasync", &["device.seq_write"]),
    ("sys.getpid", &[]),
    ("sys.futex", &[]),
    ("sync.atomic", &[]),
    ("sync.mutex", &["sync.atomic"]),
    ("sync.wake", &["sys.futex"]),
    ("sync.channel", &["sync.atomic", "sync.wake"]),
    ("sched.spawn_blocking", &["sync.channel"]),
    ("hash.sha256", &["mem.read"]),
    ("hash.sha512", &["mem.read"]),
    ("hash.blake3", &["mem.read"]),
    ("hash.sha1", &["mem.read"]),
    ("hash.sha3_256", &["mem.read"]),
    ("hash.keccak256", &["mem.read"]),
    ("hash.multi", &["hash.sha256", "hash.blake3"]),
    ("crypto.sign.ed25519", &["hash.sha512"]),
    ("crypto.verify.ed25519", &["hash.sha512"]),
    ("crypto.sign.p256", &["hash.sha256"]),
    ("crypto.verify.p256", &["hash.sha256"]),
    ("crypto.sign.k256", &["hash.sha256"]),
    ("crypto.verify.k256", &["hash.sha256"]),
    (
        "crypto.cose.sign",
        &["crypto.sign.ed25519", "canonical.encode"],
    ),
    (
        "crypto.cose.verify",
        &["crypto.verify.ed25519", "canonical.encode"],
    ),
    ("crypto.admit.assertion", &["crypto.cose.verify"]),
    ("crypto.admit.revocation", &["crypto.cose.verify"]),
    ("crypto.admit.succession", &["crypto.cose.verify"]),
    ("crypto.aead.seal", &["mem.copy"]),
    ("crypto.aead.open", &["mem.copy"]),
    ("merkle.root", &["hash.sha256"]),
    ("merkle.proof", &["hash.sha256"]),
    ("merkle.verify", &["hash.sha256"]),
    ("digest.insert", &["hash.sha256"]),
    ("digest.merge", &[]),
    ("canonical.encode", &["mem.alloc"]),
    ("canonical.decode", &["mem.alloc"]),
    ("arcswap.load", &["sync.atomic"]),
    ("arcswap.store", &["sync.atomic"]),
    ("imbl.insert", &["mem.alloc"]),
    ("store.tag_put", &["digest.insert", "imbl.insert"]),
    ("store.tag_get", &["arcswap.load"]),
    (
        "store.publish",
        &["store.tag_put", "epoch.sign", "arcswap.store"],
    ),
    ("store.blob_put", &["hash.sha256", "device.seq_write"]),
    ("store.blob_get", &["device.seq_read"]),
    (
        "store.blob_get_verified",
        &["store.blob_get", "hash.sha256"],
    ),
    ("store.blob_get_range", &["device.rand_read"]),
    ("store.ingest", &["store.blob_put"]),
    ("store.epoch_get", &["canonical.decode"]),
    ("store.operation_replay", &["store.epoch_get"]),
    ("store.edge_query", &["canonical.decode", "hash.sha256"]),
    ("store.multipart_complete", &["store.ingest"]),
    // redb makes a durable commit with fdatasync, never fsync.
    ("redb.commit", &["device.fdatasync"]),
    ("redb.read", &["device.rand_read"]),
    ("epoch.sign", &["crypto.cose.sign", "merkle.root"]),
    ("epoch.verify", &["crypto.cose.verify"]),
    (
        "replay.ledger",
        &["canonical.decode", "merkle.root", "digest.insert"],
    ),
    // The server's sweep: resolve every tag root, walk reachability by edge
    // queries, then classify a snapshot of every stored blob identity.
    ("gc.sweep", &["store.tag_get", "store.edge_query"]),
    ("txn.put", &["hash.sha256", "device.seq_write"]),
    ("txn.promote", &["txn.put", "store.ingest"]),
    ("index.seek", &["mem.chase"]),
    ("index.advance", &["mem.read"]),
    ("index.rebuild", &["index.advance"]),
    ("index.insert", &["index.seek", "mem.alloc"]),
    // A request is bounded by the store operation it performs.
    ("http.blob_get", &["store.blob_get"]),
    ("http.blob_put", &["store.blob_put"]),
    ("http.manifest_get", &["store.tag_get", "store.blob_get"]),
];

#[cfg(test)]
mod tests {
    use super::super::operation::SEEDED_OPERATIONS;
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn graph_and_registry_describe_the_same_vocabulary() {
        let graph = DependencyGraph::seeded();
        let in_graph: BTreeSet<&str> = graph.operations().collect();
        let registered: BTreeSet<&str> = SEEDED_OPERATIONS.iter().copied().collect();
        assert_eq!(
            in_graph, registered,
            "every registered operation needs one graph entry"
        );
        assert_eq!(
            SEEDED_DEPS.len(),
            in_graph.len(),
            "no operation declared twice"
        );
        for (op, deps) in SEEDED_DEPS {
            for dep in *deps {
                assert!(
                    registered.contains(dep),
                    "{op} depends on unregistered {dep}"
                );
            }
        }
    }

    #[test]
    fn graph_is_acyclic_and_ordered() {
        let graph = DependencyGraph::seeded();
        for op in graph.operations() {
            assert!(
                !graph.transitive_deps(op).contains(op),
                "{op} reaches itself"
            );
        }
        let order = graph.topo_order();
        let position = |op: &str| order.iter().position(|o| *o == op);
        for op in graph.operations() {
            for dep in graph.direct_deps(op) {
                assert!(position(dep) < position(op), "{dep} must precede {op}");
            }
        }
        assert_eq!(order.len(), SEEDED_OPERATIONS.len());
    }

    #[test]
    fn storage_composites_decompose_to_device_and_digest_floors() {
        let graph = DependencyGraph::seeded();
        let put = graph.transitive_deps("store.blob_put");
        assert!(put.contains("hash.sha256") && put.contains("device.seq_write"));
        // redb's durable commit syncs with fdatasync, never fsync.
        let commit = graph.transitive_deps("redb.commit");
        assert!(commit.contains("device.fdatasync"));
        assert!(!commit.contains("device.fsync"));
        let publish = graph.transitive_deps("store.publish");
        for floor in [
            "crypto.sign.ed25519",
            "merkle.root",
            "digest.insert",
            "sync.atomic",
        ] {
            assert!(publish.contains(floor), "store.publish must reach {floor}");
        }
    }

    #[test]
    fn requests_decompose_to_the_store_operations_they_serve() {
        let graph = DependencyGraph::seeded();
        assert!(
            graph
                .transitive_deps("http.blob_get")
                .contains("device.seq_read")
        );
        let put = graph.transitive_deps("http.blob_put");
        assert!(put.contains("store.blob_put") && put.contains("hash.sha256"));
        let manifest = graph.transitive_deps("http.manifest_get");
        assert!(manifest.contains("store.tag_get") && manifest.contains("store.blob_get"));
    }

    #[test]
    fn composed_deps_exclude_operands() -> TestResult {
        let graph = DependencyGraph::seeded();
        let op = OperationPath::parse("store.tag_put+epoch.sign")?;
        let deps = graph.deps_of(&op);
        assert!(!deps.contains("store.tag_put") && !deps.contains("epoch.sign"));
        assert!(deps.contains("digest.insert") && deps.contains("crypto.sign.ed25519"));
        Ok(())
    }
}
