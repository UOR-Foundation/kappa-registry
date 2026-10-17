//! The directory's in-memory state: the map in label order and the log,
//! with the rules that admit a transition and the roots they commit to.

use std::collections::BTreeMap;

use dcbor::prelude::*;

use kappa_types::canonical::canonical_bytes;
use kappa_types::kappa::Kappa;
use kappa_types::merkle_index;

use crate::error::DirectoryError;
use crate::record::{Commitment, Entry, LogRecord, MapRecord, Transition};

/// The map and the log the current commitment covers.
#[derive(Debug, Clone, Default)]
pub struct DirectoryState {
    entries: BTreeMap<Vec<u8>, Entry>,
    log: Vec<Transition>,
}

/// Where a label sits in the map: at a leaf, or between two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Position {
    /// The leaf at this index carries the label.
    At(usize),
    /// The label would sit between these leaves: the index of the last
    /// leaf below it and of the first leaf above it, each absent at the
    /// edge of the map.
    Between {
        left: Option<usize>,
        right: Option<usize>,
    },
}

impl DirectoryState {
    /// Rebuild the state from the published records, verifying that the
    /// map is in label order with no duplicate and that replaying the log
    /// reproduces exactly the published map, so a published state is
    /// admitted only when it is the deterministic function of its log.
    pub fn from_records(map: &MapRecord, log: &LogRecord) -> Result<Self, DirectoryError> {
        let mut replayed = Self::default();
        for transition in &log.transitions {
            replayed.admit(transition)?;
        }
        let mut previous: Option<&[u8]> = None;
        for entry in &map.entries {
            if previous.is_some_and(|previous| previous >= entry.label.as_ref()) {
                return Err(DirectoryError::Verification(
                    "published map is not in strict label order".into(),
                ));
            }
            previous = Some(entry.label.as_ref());
        }
        let published: Vec<&Entry> = map.entries.iter().collect();
        let rebuilt: Vec<&Entry> = replayed.entries.values().collect();
        if published != rebuilt {
            return Err(DirectoryError::Verification(
                "published map is not the replay of the published log".into(),
            ));
        }
        Ok(replayed)
    }

    pub fn entry(&self, label: &[u8]) -> Option<&Entry> {
        self.entries.get(label)
    }

    pub fn log(&self) -> &[Transition] {
        &self.log
    }

    pub fn leaf_count(&self) -> u64 {
        self.entries.len() as u64
    }

    /// The transition that applying `request` would record, or `None`
    /// when the map already reflects it (a retried publication, a
    /// retraction of an already retracted label).
    pub fn derive(
        &self,
        label: &[u8],
        value: Option<&Kappa>,
        epoch: u64,
    ) -> Result<Option<Transition>, DirectoryError> {
        let current = self.entries.get(label);
        match (current, value) {
            (Some(entry), Some(value)) if entry.is_active() && &entry.value == value => Ok(None),
            (Some(entry), Some(value)) => Ok(Some(Transition {
                label: ByteString::from(label),
                value: Some(value.clone()),
                version: entry
                    .version
                    .checked_add(1)
                    .ok_or_else(|| DirectoryError::Rejected("label version exhausted".into()))?,
                epoch,
            })),
            (None, Some(value)) => Ok(Some(Transition {
                label: ByteString::from(label),
                value: Some(value.clone()),
                version: 1,
                epoch,
            })),
            (Some(entry), None) if !entry.is_active() => Ok(None),
            (Some(entry), None) => Ok(Some(Transition {
                label: ByteString::from(label),
                value: None,
                version: entry.version,
                epoch,
            })),
            (None, None) => Err(DirectoryError::Rejected(
                "retraction of a label that was never asserted".into(),
            )),
        }
    }

    /// Admit `transition`: the rules every replay applies identically. A
    /// set increments the version (or starts it at 1) and makes the label
    /// active; a retraction keeps the version and marks the epoch.
    pub fn admit(&mut self, transition: &Transition) -> Result<(), DirectoryError> {
        let label = transition.label.as_ref().to_vec();
        match (&transition.value, self.entries.get_mut(&label)) {
            (Some(value), Some(entry)) => {
                if transition.version != entry.version + 1 {
                    return Err(DirectoryError::Verification(format!(
                        "transition version {} does not follow {}",
                        transition.version, entry.version
                    )));
                }
                entry.value = value.clone();
                entry.version = transition.version;
                entry.retracted_at = None;
            }
            (Some(value), None) => {
                if transition.version != 1 {
                    return Err(DirectoryError::Verification(
                        "first transition of a label must be version 1".into(),
                    ));
                }
                self.entries.insert(
                    label,
                    Entry {
                        label: transition.label.clone(),
                        value: value.clone(),
                        version: 1,
                        first_epoch: transition.epoch,
                        retracted_at: None,
                    },
                );
            }
            (None, Some(entry)) => {
                if transition.version != entry.version || !entry.is_active() {
                    return Err(DirectoryError::Verification(
                        "retraction names a version that is not the active one".into(),
                    ));
                }
                entry.retracted_at = Some(transition.epoch);
            }
            (None, None) => {
                return Err(DirectoryError::Verification(
                    "retraction of a label the map does not hold".into(),
                ));
            }
        }
        self.log.push(transition.clone());
        Ok(())
    }

    /// The canonical leaves of the map, in label order.
    pub fn map_leaves(&self) -> Vec<Vec<u8>> {
        self.entries.values().map(canonical_bytes).collect()
    }

    /// The canonical leaves of the log, in order.
    pub fn log_leaves(&self) -> Vec<Vec<u8>> {
        self.log.iter().map(canonical_bytes).collect()
    }

    /// Where `label` sits in the map.
    pub fn position(&self, label: &[u8]) -> Position {
        let mut left = None;
        for (index, key) in self.entries.keys().enumerate() {
            match key.as_slice().cmp(label) {
                std::cmp::Ordering::Equal => return Position::At(index),
                std::cmp::Ordering::Less => left = Some(index),
                std::cmp::Ordering::Greater => {
                    return Position::Between {
                        left,
                        right: Some(index),
                    };
                }
            }
        }
        Position::Between { left, right: None }
    }

    /// The entry at leaf `index`.
    pub fn entry_at(&self, index: usize) -> Option<&Entry> {
        self.entries.values().nth(index)
    }

    /// The commitment of this state at `epoch`, extending `previous`.
    pub fn commitment(&self, epoch: u64, previous: Option<Kappa>) -> Commitment {
        let map = self.map_leaves();
        let map_refs: Vec<&[u8]> = map.iter().map(Vec::as_slice).collect();
        let log = self.log_leaves();
        let log_refs: Vec<&[u8]> = log.iter().map(Vec::as_slice).collect();
        Commitment {
            epoch,
            map_root: ByteString::from(merkle_index::root(&map_refs)),
            leaf_count: map_refs.len() as u64,
            log_root: ByteString::from(merkle_index::root(&log_refs)),
            log_size: log_refs.len() as u64,
            previous,
        }
    }

    pub fn map_record(&self) -> MapRecord {
        MapRecord {
            entries: self.entries.values().cloned().collect(),
        }
    }

    pub fn log_record(&self) -> LogRecord {
        LogRecord {
            transitions: self.log.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(
        state: &mut DirectoryState,
        label: &[u8],
        value: &[u8],
        epoch: u64,
    ) -> Result<(), DirectoryError> {
        let transition = state
            .derive(label, Some(&Kappa::sha256(value)), epoch)?
            .ok_or_else(|| DirectoryError::Rejected("no transition".into()))?;
        state.admit(&transition)
    }

    #[test]
    fn transitions_are_derived_idempotently_and_replay_rebuilds_the_map()
    -> Result<(), DirectoryError> {
        let mut state = DirectoryState::default();
        set(&mut state, b"b", b"one", 2)?;
        set(&mut state, b"a", b"two", 3)?;
        assert!(
            state
                .derive(b"b", Some(&Kappa::sha256(b"one")), 4)?
                .is_none()
        );
        set(&mut state, b"b", b"three", 4)?;
        assert_eq!(state.entry(b"b").map(|e| e.version), Some(2));
        let retract = state
            .derive(b"b", None, 5)?
            .ok_or_else(|| DirectoryError::Rejected("no retraction".into()))?;
        state.admit(&retract)?;
        assert!(state.derive(b"b", None, 6)?.is_none());
        assert!(matches!(
            state.derive(b"zzz", None, 6),
            Err(DirectoryError::Rejected(_))
        ));
        assert_eq!(state.entry(b"b").and_then(|e| e.retracted_at), Some(5));
        // A re-assertion after retraction is active again at a new version.
        set(&mut state, b"b", b"four", 7)?;
        assert_eq!(
            state.entry(b"b").map(|e| (e.version, e.is_active())),
            Some((3, true))
        );
        assert_eq!(state.position(b"a"), Position::At(0));
        assert_eq!(
            state.position(b"aa"),
            Position::Between {
                left: Some(0),
                right: Some(1)
            }
        );
        assert_eq!(
            state.position(b"0"),
            Position::Between {
                left: None,
                right: Some(0)
            }
        );
        assert_eq!(
            state.position(b"c"),
            Position::Between {
                left: Some(1),
                right: None
            }
        );
        let rebuilt = DirectoryState::from_records(&state.map_record(), &state.log_record())?;
        assert_eq!(rebuilt.commitment(7, None), state.commitment(7, None));
        // A map that is not the replay of its log is refused.
        let mut forged = state.map_record();
        forged.entries[0].value = Kappa::sha256(b"forged");
        assert!(matches!(
            DirectoryState::from_records(&forged, &state.log_record()),
            Err(DirectoryError::Verification(_))
        ));
        let mut unordered = state.map_record();
        unordered.entries.swap(0, 1);
        assert!(matches!(
            DirectoryState::from_records(&unordered, &state.log_record()),
            Err(DirectoryError::Verification(_))
        ));
        Ok(())
    }
}
