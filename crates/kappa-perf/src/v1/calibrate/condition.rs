//! Typed measurement conditions.
//!
//! A condition parameterizes a measurement without changing its operation:
//! `hash.sha256?size=64k` and `hash.sha256?size=1m` are distinct points of
//! one operation. Every key is registered with a value type and the
//! operation domains it applies to. Values are canonicalized by meaning, not
//! spelling: `size=65536` and `size=64k` are the same condition, so the same
//! measurement can never be recorded under two identifiers.

use std::collections::BTreeMap;
use std::fmt;

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
    fn contains(self, domain: &str) -> bool {
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
        applies: Applies::Only(&["index", "imbl", "digest", "gc", "redb"]),
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
        applies: Applies::Only(&["store", "replay", "gc", "epoch", "txn", "http"]),
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
        applies: Applies::Only(&["mem", "device", "index", "store", "redb"]),
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
];

/// Why a condition was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConditionError {
    #[error("unregistered condition key '{0}'")]
    Unregistered(String),
    #[error("condition '{key}' does not apply to operation domain '{domain}'")]
    NotApplicable { key: String, domain: String },
    #[error("invalid value '{value}' for condition '{key}': {reason}")]
    InvalidValue {
        key: String,
        value: String,
        reason: String,
    },
    #[error("duplicate condition key '{0}'")]
    Duplicate(String),
    #[error("malformed condition pair '{0}'")]
    Malformed(String),
}

pub fn lookup(key: &str) -> Option<&'static ConditionDef> {
    SEEDED_CONDITIONS.iter().find(|def| def.key == key)
}

/// A canonical, sorted set of conditions.
#[derive(
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Conditions(BTreeMap<String, String>);

impl Conditions {
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Insert a key and value, canonicalizing the value by its registered
    /// type. Domain applicability is checked when the conditions are bound
    /// to an operation.
    pub fn with(mut self, key: &str, value: &str) -> Result<Self, ConditionError> {
        let def = lookup(key).ok_or_else(|| ConditionError::Unregistered(key.to_owned()))?;
        let canonical = canonicalize(def, value)?;
        if self.0.insert(key.to_owned(), canonical).is_some() {
            return Err(ConditionError::Duplicate(key.to_owned()));
        }
        Ok(self)
    }

    /// Parse `k=v&k=v`. Duplicate keys are rejected, not overwritten.
    pub fn parse(raw: &str) -> Result<Self, ConditionError> {
        let mut conditions = Self::new();
        if raw.is_empty() {
            return Ok(conditions);
        }
        for pair in raw.split('&') {
            let (key, value) = pair
                .split_once('=')
                .filter(|(key, value)| !key.is_empty() && !value.is_empty())
                .ok_or_else(|| ConditionError::Malformed(pair.to_owned()))?;
            conditions = conditions.with(key, value)?;
        }
        Ok(conditions)
    }

    /// Every key applies to at least one of `domains`.
    pub fn check_applicable(&self, domains: &[&str]) -> Result<(), ConditionError> {
        for key in self.0.keys() {
            let def = lookup(key).ok_or_else(|| ConditionError::Unregistered(key.clone()))?;
            if !domains.iter().any(|domain| def.applies.contains(domain)) {
                return Err(ConditionError::NotApplicable {
                    key: key.clone(),
                    domain: domains.join("+"),
                });
            }
        }
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Whether every condition of `other` is present with the same value.
    pub fn is_superset_of(&self, other: &Self) -> bool {
        other
            .iter()
            .all(|(key, value)| self.get(key) == Some(value))
    }

    /// Byte value of a magnitude condition.
    pub fn magnitude(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|value| parse_magnitude(value).ok())
    }

    /// Integer value of a count condition.
    pub fn count(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|value| value.parse().ok())
    }

    // Infallible builders: these generate canonical values directly.

    #[must_use]
    pub fn size(self, bytes: u64) -> Self {
        self.set_canonical("size", format_magnitude(bytes))
    }

    #[must_use]
    pub fn count_of(self, key: &'static str, value: u64) -> Self {
        debug_assert!(lookup(key).is_some_and(|def| def.ctype == ConditionType::Count));
        self.set_canonical(key, value.to_string())
    }

    #[must_use]
    pub fn threads(self, threads: u32) -> Self {
        self.set_canonical("threads", format!("{threads}t"))
    }

    fn set_canonical(mut self, key: &'static str, value: String) -> Self {
        self.0.insert(key.to_owned(), value);
        self
    }
}

impl fmt::Display for Conditions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, (key, value)) in self.0.iter().enumerate() {
            f.write_str(if index == 0 { "?" } else { "&" })?;
            write!(f, "{key}={value}")?;
        }
        Ok(())
    }
}

fn invalid(key: &str, value: &str, reason: impl Into<String>) -> ConditionError {
    ConditionError::InvalidValue {
        key: key.to_owned(),
        value: value.to_owned(),
        reason: reason.into(),
    }
}

fn canonicalize(def: &ConditionDef, value: &str) -> Result<String, ConditionError> {
    match def.ctype {
        ConditionType::Enum(values) => {
            if values.contains(&value) {
                Ok(value.to_owned())
            } else {
                Err(invalid(
                    def.key,
                    value,
                    format!("expected one of {values:?}"),
                ))
            }
        }
        ConditionType::Magnitude => parse_magnitude(value)
            .map(format_magnitude)
            .map_err(|reason| invalid(def.key, value, reason)),
        ConditionType::Count => parse_count(value)
            .map(|count| count.to_string())
            .map_err(|reason| invalid(def.key, value, reason)),
        ConditionType::Cardinality => {
            validate_cardinality(value).map_err(|reason| invalid(def.key, value, reason))?;
            Ok(value.to_owned())
        }
        ConditionType::Token => {
            if !value.is_empty()
                && value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                Ok(value.to_owned())
            } else {
                Err(invalid(def.key, value, "token must be [a-z0-9_]+"))
            }
        }
        ConditionType::Compound => {
            let mut parts: Vec<&str> = value.split('+').collect();
            for part in &parts {
                if *part != "none" {
                    validate_cardinality(part).map_err(|reason| invalid(def.key, value, reason))?;
                }
            }
            parts.sort_unstable();
            parts.dedup();
            if parts.len() > 1 && parts.contains(&"none") {
                return Err(invalid(def.key, value, "'none' cannot combine with counts"));
            }
            Ok(parts.join("+"))
        }
    }
}

fn parse_count(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.chars().all(|c| c.is_ascii_digit()) {
        return Err("count must be decimal digits".into());
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err("count has leading zeros".into());
    }
    value.parse().map_err(|error| format!("{error}"))
}

/// Parse `digits[k|m|g]` into bytes (IEC multiples).
pub fn parse_magnitude(value: &str) -> Result<u64, String> {
    let (digits, shift) = match value.as_bytes().last() {
        Some(b'k') => (&value[..value.len() - 1], 10),
        Some(b'm') => (&value[..value.len() - 1], 20),
        Some(b'g') => (&value[..value.len() - 1], 30),
        _ => (value, 0),
    };
    let base = parse_count(digits)?;
    base.checked_mul(1u64 << shift)
        .ok_or_else(|| "magnitude overflows u64".into())
}

/// Render bytes with the largest IEC suffix that divides them exactly.
pub fn format_magnitude(bytes: u64) -> String {
    const UNITS: [(u64, &str); 3] = [(1 << 30, "g"), (1 << 20, "m"), (1 << 10, "k")];
    for (unit, suffix) in UNITS {
        if bytes >= unit && bytes.is_multiple_of(unit) {
            return format!("{}{suffix}", bytes / unit);
        }
    }
    bytes.to_string()
}

fn validate_cardinality(value: &str) -> Result<(), String> {
    let (digits, suffix) = value.split_at(value.len().saturating_sub(1));
    if !matches!(suffix, "t" | "w" | "c" | "s") {
        return Err("cardinality must end in t, w, c or s".into());
    }
    parse_count(digits).and_then(|count| {
        if count == 0 {
            Err("cardinality must be positive".into())
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
#[path = "condition_tests.rs"]
mod tests;
