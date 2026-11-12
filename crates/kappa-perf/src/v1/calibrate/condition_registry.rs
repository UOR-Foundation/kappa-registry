//! The condition registry: every key a measurement may carry, its value
//! type and the operation domains it applies to (`condition`).

/// Value type of a condition key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionType {
    /// One of a closed set of tokens.
    Enum(&'static [&'static str]),
    /// Byte magnitude: integer with optional `k`, `m`, `g` (IEC) suffix.
    Magnitude,
    /// Plain non-negative integer.
    Count,
    /// Thread, worker, client or stream count: digits + `t`/`w`/`c`/`s`.
    Cardinality,
    /// Open identifier `[a-z0-9_]+`.
    Token,
    /// `+`-joined cardinalities or `none`.
    Compound,
}

/// Operation domains a key applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applies {
    All,
    Only(&'static [&'static str]),
}

impl Applies {
    pub(crate) fn contains(self, domain: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(domains) => domains.contains(&domain),
        }
    }
}

/// A registered condition key.
#[derive(Debug)]
pub struct ConditionDef {
    pub key: &'static str,
    pub ctype: ConditionType,
    pub applies: Applies,
}

const AXES: &[&str] = &[
    "sha256",
    "sha512",
    "blake3",
    "sha1",
    "sha3_256",
    "keccak256",
];

/// The maintenance domains: the public `MaintenanceStore` calls and the
/// reopen that runs recovery.
const MAINTENANCE: &[&str] = &["recovery", "settlement", "repair", "reclaim"];

/// The condition registry.
pub const SEEDED_CONDITIONS: &[ConditionDef] = &[
    ConditionDef {
        key: "size",
        ctype: ConditionType::Magnitude,
        applies: Applies::Only(&[
            "mem",
            "device",
            "hash",
            "crypto",
            "store",
            "txn",
            "redb",
            "canonical",
            "index",
            "http",
        ]),
    },
    ConditionDef {
        key: "leaves",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["merkle"]),
    },
    ConditionDef {
        key: "tags",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["store", "digest", "epoch", "replay"]),
    },
    ConditionDef {
        key: "keys",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["index", "imbl", "digest", "gc", "redb", "reconcile"]),
    },
    ConditionDef {
        key: "mutations",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["store", "replay", "epoch", "canonical", "merkle"]),
    },
    ConditionDef {
        key: "axes",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["hash", "store"]),
    },
    ConditionDef {
        key: "readers",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["store", "index", "arcswap"]),
    },
    ConditionDef {
        key: "qd",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["device"]),
    },
    ConditionDef {
        key: "depth",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["index", "crypto"]),
    },
    ConditionDef {
        key: "overflow",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["index"]),
    },
    // Open-loop load: the offered request rate per second, and the client
    // connections it is spread over.
    ConditionDef {
        key: "rate",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["http"]),
    },
    ConditionDef {
        key: "connections",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["http"]),
    },
    ConditionDef {
        key: "threads",
        ctype: ConditionType::Cardinality,
        applies: Applies::Only(&[
            "mem", "sync", "sched", "hash", "crypto", "store", "redb", "txn", "index", "arcswap",
        ]),
    },
    ConditionDef {
        key: "contention",
        ctype: ConditionType::Compound,
        applies: Applies::Only(&["sync", "store", "redb", "txn", "index"]),
    },
    ConditionDef {
        key: "fanout",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["store"]),
    },
    ConditionDef {
        key: "parts",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["store"]),
    },
    ConditionDef {
        key: "backend",
        ctype: ConditionType::Enum(&["memory", "redb"]),
        applies: Applies::Only(&[
            "store",
            "replay",
            "gc",
            "epoch",
            "txn",
            "http",
            "recovery",
            "settlement",
            "repair",
            "reclaim",
        ]),
    },
    ConditionDef {
        key: "durability",
        ctype: ConditionType::Enum(&["none", "eventual", "immediate"]),
        applies: Applies::Only(&["device", "redb", "store", "txn", "http"]),
    },
    ConditionDef {
        key: "axis",
        ctype: ConditionType::Enum(AXES),
        applies: Applies::Only(&["store", "txn", "merkle", "digest"]),
    },
    ConditionDef {
        key: "cache",
        ctype: ConditionType::Enum(&["l1", "l2", "l3", "dram"]),
        applies: Applies::Only(&["mem", "index", "hash", "crypto"]),
    },
    ConditionDef {
        key: "state",
        ctype: ConditionType::Enum(&["cold", "warm"]),
        applies: Applies::Only(&["mem", "device", "index", "store", "redb", "recovery"]),
    },
    ConditionDef {
        key: "order",
        ctype: ConditionType::Enum(&["sequential", "random"]),
        applies: Applies::Only(&["mem", "device", "index", "redb", "store"]),
    },
    ConditionDef {
        key: "hit",
        ctype: ConditionType::Enum(&["hit", "miss"]),
        applies: Applies::Only(&["index", "store", "redb"]),
    },
    ConditionDef {
        key: "mode",
        ctype: ConditionType::Enum(&["exact", "lower_bound"]),
        applies: Applies::Only(&["index"]),
    },
    ConditionDef {
        key: "encryption",
        ctype: ConditionType::Enum(&["on", "off"]),
        applies: Applies::Only(&["store", "redb", "device"]),
    },
    ConditionDef {
        key: "compression",
        ctype: ConditionType::Enum(&["none", "zstd", "xz", "bzip2"]),
        applies: Applies::Only(&["store"]),
    },
    ConditionDef {
        key: "alloc",
        ctype: ConditionType::Enum(&["none", "fresh", "reuse"]),
        applies: Applies::Only(&["mem", "crypto", "canonical"]),
    },
    ConditionDef {
        key: "variant",
        ctype: ConditionType::Token,
        applies: Applies::Only(&[
            "mem",
            "sync",
            "sched",
            "hash",
            "crypto",
            "store",
            "canonical",
            "index",
        ]),
    },
    ConditionDef {
        key: "record",
        ctype: ConditionType::Token,
        applies: Applies::Only(&["canonical", "crypto", "store"]),
    },
    ConditionDef {
        key: "res",
        ctype: ConditionType::Token,
        applies: Applies::All,
    },
    // A reference implementation of the operation (aws-lc assembly, ISA-L
    // multi-buffer lanes, a crate called directly): absent on records of
    // kappa's production path, which `reference::compare` pairs with the
    // best reference agreeing on every other condition.
    ConditionDef {
        key: "impl",
        ctype: ConditionType::Token,
        applies: Applies::Only(&["hash", "crypto"]),
    },
    // Independent objects digested per iteration: the multi-buffer regime,
    // where one core hashes several messages in parallel lanes.
    ConditionDef {
        key: "objects",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["hash"]),
    },
    // What the measured call returned. A refusal is a distinct
    // measurement of the same operation, never filtered out: its cost
    // under overload is what admission control exists to bound. Tokens
    // are bound to `StoreError` variants by `bench::outcome`, one each;
    // `admitted_after_settlement` is an admission the store made only
    // after settling the namespace on its own admission path.
    ConditionDef {
        key: "outcome",
        ctype: ConditionType::Enum(&[
            "admitted",
            "admitted_after_settlement",
            "refused_capacity",
            "refused_unavailable",
            "refused_conflict",
            "refused_rejected",
            "refused_work",
            "refused_io",
            "refused_version",
            "deadline",
            "indeterminate",
            "recovery_required",
            "retained",
        ]),
        applies: Applies::Only(&["store", "txn", "http"]),
    },
    // The unrelated concern running on another namespace of the same
    // store while the subject is measured (PERF-SYS-008).
    ConditionDef {
        key: "interference",
        ctype: ConditionType::Enum(&[
            "none",
            "publisher",
            "readers",
            "settlement",
            "reclaim",
            "gc_sweep",
            "index_rebuild",
        ]),
        applies: Applies::Only(&["store", "txn", "index", "http"]),
    },
    // The storage fault injected before the measured recovery or refusal
    // (`kappa_store_redb::test_support::Fault`, `Loss`, and filesystem
    // manipulation of a namespace's directory).
    ConditionDef {
        key: "fault",
        ctype: ConditionType::Enum(&[
            "none",
            "crash",
            "crash_partial",
            "sync_before",
            "sync_after",
            "refuse_writes",
            "lost_storage",
            "empty_database",
        ]),
        applies: Applies::Only(&["recovery", "settlement", "reclaim", "repair", "store"]),
    },
    // Which database's sync a crash landed in.
    ConditionDef {
        key: "crash_at",
        ctype: ConditionType::Enum(&["registry", "namespace"]),
        applies: Applies::Only(MAINTENANCE),
    },
    // The I/O path the store's databases were opened through: redb's own
    // file backend (production), or the fault backend, which takes a lock
    // and reads metadata on every operation. Records on different paths
    // are not compared.
    ConditionDef {
        key: "io",
        ctype: ConditionType::Enum(&["file", "fault"]),
        applies: Applies::Only(&[
            "store",
            "txn",
            "recovery",
            "settlement",
            "repair",
            "reclaim",
        ]),
    },
    // Committed epochs unsettled when the store was reopened.
    ConditionDef {
        key: "pending",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["recovery", "settlement"]),
    },
    // Entries one bounded maintenance step may examine (`WorkLimit`,
    // `Dimension::Entries`).
    ConditionDef {
        key: "budget",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["settlement", "repair", "reclaim"]),
    },
    // Keys that differ between the two reconciled trees.
    ConditionDef {
        key: "divergence",
        ctype: ConditionType::Count,
        applies: Applies::Only(&["reconcile"]),
    },
];

pub fn lookup(key: &str) -> Option<&'static ConditionDef> {
    SEEDED_CONDITIONS.iter().find(|def| def.key == key)
}
