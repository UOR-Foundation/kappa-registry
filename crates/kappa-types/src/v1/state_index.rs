//! The authenticated current-state index of a namespace: a compact sparse
//! Merkle tree over 256-bit key paths (`state_key`).
//!
//! A subtree holding no entry hashes to [`EMPTY`]; a subtree holding
//! exactly one entry is that entry's leaf, wherever the subtree starts, so
//! a tree of n entries has n leaves and n - 1 branching internal nodes,
//! plus one internal node per level two entries share before their paths
//! diverge. Leaves commit their full path, so a leaf proves its position,
//! and node hashes are domain-separated from each other and from the
//! RFC 9162 trees of `merkle` (`0x10` leaf, `0x11` internal).
//!
//! Updates are batched and incremental: [`apply`] rewrites only the paths
//! the batch touches and reports the nodes it created and the nodes of
//! the previous root it superseded (the nodes of one tree are distinct: a
//! node's hash commits every entry below it, and entry paths fix their
//! positions). A superseded node is no longer reachable from the new root;
//! it may still belong to an older root a reader, a proof, a retirement
//! decision, an audit or an unresolved publication retains, so it is
//! never deleted on that report alone: it passes to the backend's
//! retained-evidence reclamation, which deletes it once no retained root
//! needs it. Nodes are read through [`NodeSource`], which each backend
//! implements over its own storage.
//!
//! Every node read, hashed and allocated is charged to the caller's
//! [`WorkMeter`] before the work is done, so a batch refuses before it
//! passes its budget.
//!
//! A [`Proof`] answers one path against one root: present with its value,
//! or absent (the walk ends at an empty subtree, or at a leaf of another
//! path sharing the walked prefix). [`verify`] recomputes the root from
//! the proof alone.

use std::collections::BTreeMap;

use crate::error::StoreError;
use crate::sha256::Hasher;
use crate::work::{Dimension, WorkMeter};

/// Hash of an empty subtree.
pub const EMPTY: [u8; 32] = [0; 32];

/// Bits in a key path, and so the deepest a proof can walk.
pub const DEPTH: usize = 256;

const LEAF: u8 = 0x10;
const INTERNAL: u8 = 0x11;

/// A key path: `state_key` derives it from a family and a key.
pub type Path = [u8; 32];
/// An entry's value: the digest of its canonical value record.
pub type Value = [u8; 32];

/// One stored node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node {
    Leaf { path: Path, value: Value },
    Internal { left: [u8; 32], right: [u8; 32] },
}

fn leaf_hash(path: &Path, value: &Value) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&[LEAF]);
    hasher.update(path);
    hasher.update(value);
    hasher.finalize()
}

fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&[INTERNAL]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

impl Node {
    pub fn hash(&self) -> [u8; 32] {
        match self {
            Self::Leaf { path, value } => leaf_hash(path, value),
            Self::Internal { left, right } => internal_hash(left, right),
        }
    }

    /// Persisted form: the domain byte, then the two 32-byte fields.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        let (tag, first, second) = match self {
            Self::Leaf { path, value } => (LEAF, path, value),
            Self::Internal { left, right } => (INTERNAL, left, right),
        };
        out[0] = tag;
        out[1..33].copy_from_slice(first);
        out[33..].copy_from_slice(second);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let invalid = || StoreError::Internal("state index node is not 65 bytes".into());
        let (tag, rest) = bytes.split_first().ok_or_else(invalid)?;
        if rest.len() != 64 {
            return Err(invalid());
        }
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        first.copy_from_slice(&rest[..32]);
        second.copy_from_slice(&rest[32..]);
        match *tag {
            LEAF => Ok(Self::Leaf {
                path: first,
                value: second,
            }),
            INTERNAL => Ok(Self::Internal {
                left: first,
                right: second,
            }),
            other => Err(StoreError::Internal(format!(
                "state index node has unknown tag {other:#04x}"
            ))),
        }
    }
}

/// Bit `depth` of `path`, most significant first.
pub const fn bit(path: &Path, depth: usize) -> bool {
    path[depth / 8] >> (7 - depth % 8) & 1 == 1
}

/// Read access to the nodes of the trees a backend retains.
pub trait NodeSource {
    /// The node hashing to `hash`. A node a reachable hash names but the
    /// backend cannot read is unavailable, never absent. A backend whose
    /// storage does not itself guarantee the correspondence establishes it
    /// by hashing the node it read; every read is charged that work
    /// ([`read_work`]) before it is made.
    fn node(&self, hash: &[u8; 32]) -> Result<Node, StoreError>;
}

/// What one stored node read may take: one entry examined, and the node's
/// persisted form held and hashed once to establish that it hashes to the
/// hash it was read by.
pub const fn read_work() -> [(Dimension, u64); 3] {
    [
        (Dimension::Entries, 1),
        (Dimension::BytesAllocated, NODE_BYTES),
        (Dimension::BytesHashed, NODE_BYTES),
    ]
}

/// What one batch did.
///
/// The new root, the nodes it created, and the nodes of the previous root
/// it superseded. A superseded node is not deletion permission (see the
/// module documentation); a node can be both superseded and created by one
/// batch, and is then still in the tree.
#[derive(Debug, Default)]
pub struct Update {
    pub root: [u8; 32],
    pub created: Vec<Node>,
    pub superseded: Vec<[u8; 32]>,
}

/// One change: set `path` to `Some(value)`, or remove it (`None`).
pub type Change = (Path, Option<Value>);

/// The final effect of execution-ordered `changes` at each path: the last
/// one, removal included, sorted by path with no path twice, as [`apply`]
/// requires. Writers and replay reduce through this one rule, so an epoch's
/// index root is the root its ledger derives.
pub fn final_changes(mut changes: Vec<Change>) -> Vec<Change> {
    // Reversed, the last effect at a path comes first; the stable sort keeps
    // it first among its path's effects, and dedup keeps exactly it.
    changes.reverse();
    changes.sort_by_key(|(path, _)| *path);
    changes.dedup_by_key(|(path, _)| *path);
    changes
}

/// Bytes one node hashes and occupies.
pub const NODE_BYTES: u64 = 65;

struct Batch<'a> {
    source: &'a dyn NodeSource,
    meter: &'a mut WorkMeter,
    /// Every node this batch created, by hash. Each is reachable from the
    /// new root: a subtree is built only to be returned, and `join` drops
    /// only an empty child.
    created: BTreeMap<[u8; 32], Node>,
    superseded: Vec<[u8; 32]>,
}

impl Batch<'_> {
    fn create(&mut self, node: Node) -> Result<[u8; 32], StoreError> {
        self.meter.charge_all(&[
            (Dimension::BytesHashed, NODE_BYTES),
            (Dimension::BytesAllocated, NODE_BYTES),
        ])?;
        let hash = node.hash();
        self.created.insert(hash, node);
        Ok(hash)
    }

    /// The node `hash` names: one this batch created, or a stored one,
    /// charged its read work ([`read_work`]) first.
    fn read(&mut self, hash: &[u8; 32]) -> Result<Node, StoreError> {
        if let Some(node) = self.created.get(hash) {
            return Ok(*node);
        }
        self.meter.charge_all(&read_work())?;
        self.source.node(hash)
    }

    /// The subtree at `depth` holding exactly `leaves`, sorted by path.
    fn build(&mut self, depth: usize, leaves: &[(Path, Value)]) -> Result<[u8; 32], StoreError> {
        match leaves {
            [] => Ok(EMPTY),
            [(path, value)] => self.create(Node::Leaf {
                path: *path,
                value: *value,
            }),
            _ => {
                if depth == DEPTH {
                    return Err(StoreError::Internal(
                        "two state index entries share a full path".into(),
                    ));
                }
                let split = leaves.partition_point(|(path, _)| !bit(path, depth));
                let left = self.build(depth + 1, &leaves[..split])?;
                let right = self.build(depth + 1, &leaves[split..])?;
                self.create(Node::Internal { left, right })
            }
        }
    }

    /// `hash` at `depth` after `changes`, sorted by path and all below it.
    fn update(
        &mut self,
        hash: [u8; 32],
        depth: usize,
        changes: &[Change],
    ) -> Result<[u8; 32], StoreError> {
        if changes.is_empty() {
            return Ok(hash);
        }
        if hash == EMPTY {
            return self.build(depth, &present(changes, None));
        }
        match self.read(&hash)? {
            Node::Leaf { path, value } => {
                let rebuilt = self.build(depth, &present(changes, Some((path, value))))?;
                if rebuilt != hash {
                    self.superseded.push(hash);
                }
                Ok(rebuilt)
            }
            Node::Internal { left, right } => {
                if depth == DEPTH {
                    return Err(StoreError::Internal(
                        "state index internal node below the deepest level".into(),
                    ));
                }
                let split = changes.partition_point(|(path, _)| !bit(path, depth));
                let new_left = self.update(left, depth + 1, &changes[..split])?;
                let new_right = self.update(right, depth + 1, &changes[split..])?;
                if (new_left, new_right) == (left, right) {
                    return Ok(hash);
                }
                self.superseded.push(hash);
                self.join(new_left, new_right)
            }
        }
    }

    /// The subtree with children `left` and `right`: empty when both are,
    /// the one child when the other is empty and it is a leaf (a single
    /// entry rises to the top of its subtree), otherwise a new internal
    /// node.
    fn join(&mut self, left: [u8; 32], right: [u8; 32]) -> Result<[u8; 32], StoreError> {
        let lone = match (left == EMPTY, right == EMPTY) {
            (true, true) => return Ok(EMPTY),
            (true, false) => Some(right),
            (false, true) => Some(left),
            (false, false) => None,
        };
        if let Some(child) = lone
            && matches!(self.read(&child)?, Node::Leaf { .. })
        {
            return Ok(child);
        }
        self.create(Node::Internal { left, right })
    }
}

/// The entries present after `changes` over the one existing entry
/// `existing`, sorted by path.
fn present(changes: &[Change], existing: Option<(Path, Value)>) -> Vec<(Path, Value)> {
    let mut out: Vec<(Path, Value)> = changes
        .iter()
        .filter_map(|(path, value)| value.map(|value| (*path, value)))
        .collect();
    if let Some((path, value)) = existing
        && !changes.iter().any(|(changed, _)| *changed == path)
    {
        let at = out.partition_point(|(other, _)| *other < path);
        out.insert(at, (path, value));
    }
    out
}

/// Apply `changes` to the tree at `root`, charging `meter` for every node
/// read, hashed and created before doing it. `changes` must be sorted by
/// path with no path twice.
pub fn apply(
    source: &dyn NodeSource,
    root: [u8; 32],
    changes: &[Change],
    meter: &mut WorkMeter,
) -> Result<Update, StoreError> {
    if changes.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(StoreError::Internal(
            "state index changes are not sorted with distinct paths".into(),
        ));
    }
    let mut batch = Batch {
        source,
        meter,
        created: BTreeMap::new(),
        superseded: Vec::new(),
    };
    let root = batch.update(root, 0, changes)?;
    Ok(Update {
        root,
        created: batch.created.into_values().collect(),
        superseded: batch.superseded,
    })
}

/// Where a proof's walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// An empty subtree: the path is absent.
    Empty,
    /// A leaf: the path's own (present), or another path's sharing the
    /// walked prefix (absent).
    Leaf { path: Path, value: Value },
}

/// The siblings along one path from the root, top first, and where the
/// walk ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub siblings: Vec<[u8; 32]>,
    pub terminal: Terminal,
}

/// The value of `path` in the tree at `root`, with its proof, charging
/// `meter` each node read's work ([`read_work`]) and the proof's sibling
/// buffer before it grows.
pub fn lookup(
    source: &dyn NodeSource,
    root: [u8; 32],
    path: &Path,
    meter: &mut WorkMeter,
) -> Result<(Option<Value>, Proof), StoreError> {
    let mut siblings = Vec::new();
    let mut hash = root;
    loop {
        if hash == EMPTY {
            return Ok((
                None,
                Proof {
                    siblings,
                    terminal: Terminal::Empty,
                },
            ));
        }
        meter.charge_all(&read_work())?;
        meter.charge(Dimension::BytesAllocated, 32)?;
        match source.node(&hash)? {
            Node::Leaf { path: leaf, value } => {
                let found = (leaf == *path).then_some(value);
                return Ok((
                    found,
                    Proof {
                        siblings,
                        terminal: Terminal::Leaf { path: leaf, value },
                    },
                ));
            }
            Node::Internal { left, right } => {
                let depth = siblings.len();
                if depth == DEPTH {
                    return Err(StoreError::Internal(
                        "state index walk passed the deepest level".into(),
                    ));
                }
                let (next, sibling) = if bit(path, depth) {
                    (right, left)
                } else {
                    (left, right)
                };
                siblings.push(sibling);
                hash = next;
            }
        }
    }
}

/// Whether `proof` shows that `path` holds `value` (`None`: is absent) in
/// the tree at `root`.
pub fn verify(root: &[u8; 32], path: &Path, value: Option<&Value>, proof: &Proof) -> bool {
    let depth = proof.siblings.len();
    if depth > DEPTH {
        return false;
    }
    let mut hash = match (proof.terminal, value) {
        (Terminal::Empty, None) => EMPTY,
        (Terminal::Empty, Some(_)) => return false,
        (
            Terminal::Leaf {
                path: leaf,
                value: held,
            },
            Some(value),
        ) => {
            if leaf != *path || held != *value {
                return false;
            }
            leaf_hash(&leaf, &held)
        }
        (
            Terminal::Leaf {
                path: leaf,
                value: held,
            },
            None,
        ) => {
            if leaf == *path || (0..depth).any(|level| bit(&leaf, level) != bit(path, level)) {
                return false;
            }
            leaf_hash(&leaf, &held)
        }
    };
    for (level, sibling) in proof.siblings.iter().enumerate().rev() {
        hash = if bit(path, level) {
            internal_hash(sibling, &hash)
        } else {
            internal_hash(&hash, sibling)
        };
    }
    hash == *root
}

#[cfg(test)]
#[path = "state_index_tests.rs"]
mod tests;
