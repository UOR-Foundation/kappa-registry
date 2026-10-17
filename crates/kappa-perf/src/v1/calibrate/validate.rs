//! Physics-derived validation.
//!
//! A composite measurement can never beat the floors it is built from: a
//! blob cannot be stored faster than it is hashed or written, a durable
//! commit cannot complete faster than fsync, an epoch cannot be published
//! faster than it is signed. Each rule states both sides with their
//! quantities, the conditions that select them, and the conditions that
//! must agree for the comparison to be meaningful. A rule is evaluated
//! against every matching bound, not the first found, and every bound must
//! hold. Violations of `Error` rules make the record untrusted; the record
//! is still emitted, with the diagnosis, because failures are data.

use super::grammar::OscId;
use super::quantity::Quantity;
use super::record::{Severity, ValidationResult};

/// A condition a selected measurement must satisfy.
#[derive(Debug, Clone, Copy)]
pub enum Cond {
    Eq(&'static str, &'static str),
    Ne(&'static str, &'static str),
    Present(&'static str),
}

/// Which operation a selector names.
#[derive(Debug, Clone, Copy)]
pub enum Op {
    Exact(&'static str),
    /// Any operation (subject side only).
    Any,
    /// The subject's operation (bound side only).
    SameAsSubject,
}

/// Which statistic of a measurement a selector compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stat {
    /// The record's value: the median of a latency distribution, criterion's
    /// typical estimate, or a directly recorded value.
    Value,
    /// The value at the 99th-percentile iteration time, in the quantity's
    /// unit. Only distributions have one; a measurement without it is not
    /// compared.
    Tail,
}

#[derive(Debug, Clone)]
pub struct Selector {
    pub quantity: Quantity,
    pub op: Op,
    pub conds: Vec<Cond>,
    pub stat: Stat,
}

/// How the subject relates to the bound value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// subject <= bound * multiplier
    Le,
    /// subject >= bound * multiplier
    Ge,
    /// subject <= bound * multiplier * threads(subject) / threads(bound)
    LeThreadScaled,
}

/// Which conditions must agree between subject and bound.
#[derive(Debug, Clone)]
pub enum Agree {
    Keys(Vec<&'static str>),
    AllExcept(Vec<&'static str>),
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub severity: Severity,
    pub subject: Selector,
    pub bound: Selector,
    pub relation: Relation,
    pub multiplier: f64,
    pub agree: Agree,
    pub diagnosis: &'static str,
}

/// A measurement available as a subject or a bound.
#[derive(Debug, Clone, Copy)]
pub struct Established<'a> {
    pub id: &'a OscId,
    pub value: f64,
    /// [`Stat::Tail`] of the measurement, when it has a distribution.
    pub tail: Option<f64>,
    pub from_baseline: bool,
}

impl Established<'_> {
    const fn stat(&self, stat: Stat) -> Option<f64> {
        match stat {
            Stat::Value => Some(self.value),
            Stat::Tail => self.tail,
        }
    }
}

fn sel(quantity: Quantity, op: Op, conds: &[Cond]) -> Selector {
    Selector {
        quantity,
        op,
        conds: conds.to_vec(),
        stat: Stat::Value,
    }
}

fn tail(quantity: Quantity, op: Op, conds: &[Cond]) -> Selector {
    Selector {
        stat: Stat::Tail,
        ..sel(quantity, op, conds)
    }
}

const fn stat_label(stat: Stat) -> &'static str {
    match stat {
        Stat::Value => "",
        Stat::Tail => "p99 ",
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "a rule is a table row; named fields are at the call site"
)]
fn rule(
    id: impl Into<String>,
    severity: Severity,
    subject: Selector,
    relation: Relation,
    multiplier: f64,
    bound: Selector,
    agree: Agree,
    diagnosis: &'static str,
) -> Rule {
    Rule {
        id: id.into(),
        severity,
        subject,
        bound,
        relation,
        multiplier,
        agree,
        diagnosis,
    }
}

/// Conditions a digest bound shares with its subject: the single-object
/// production digest the subject runs, never a multi-object aggregate and
/// never a reference implementation the production path does not call.
const DIGEST_BOUND: &[&str] = &["size", "objects", "impl"];

/// The kappa-registry rule table.
#[allow(clippy::too_many_lines, reason = "one row per physical constraint")]
pub fn rules() -> Vec<Rule> {
    use Cond::{Eq, Ne, Present};
    use Op::{Any, Exact, SameAsSubject};
    use Quantity::{Bw, Lat, Ops};
    use Relation::{Ge, Le, LeThreadScaled};
    use Severity::{Error, Warn};
    let keys = |k: &[&'static str]| Agree::Keys(k.to_vec());

    let mut rules = vec![
        rule(
            "copy_le_read",
            Error,
            sel(Bw, Exact("mem.copy"), &[]),
            Le,
            1.0,
            sel(Bw, Exact("mem.read"), &[]),
            keys(&["size"]),
            "copy bandwidth exceeds read bandwidth: the copy was elided or the read loop is dependency-bound",
        ),
        rule(
            "blob_put_le_seq_write",
            Error,
            sel(Bw, Exact("store.blob_put"), &[]),
            Le,
            1.0,
            sel(Bw, Exact("device.seq_write"), &[]),
            keys(&["size", "durability"]),
            "blob ingest exceeds sequential device write at the same size and durability: the write did not reach the device",
        ),
        rule(
            "verified_read_le_unverified",
            Error,
            sel(Bw, Exact("store.blob_get_verified"), &[]),
            Le,
            1.05,
            sel(Bw, Exact("store.blob_get"), &[]),
            keys(&["size", "backend"]),
            "verified read exceeds unverified read of the same blob: verification work was skipped",
        ),
        // At axes=1 (where the primary axis IS the mandatory axis),
        // ingest and blob_put do identical work; measurement noise on
        // sub-10us operations at 4k crosses a tight bound. 1.10 absorbs
        // noise; an ingest that skipped its hash would be orders of
        // magnitude faster.
        rule(
            "ingest_le_blob_put",
            Error,
            sel(Bw, Exact("store.ingest"), &[]),
            Le,
            1.10,
            sel(Bw, Exact("store.blob_put"), &[]),
            keys(&["size", "backend", "axis"]),
            "ingest with mandatory secondary axes exceeds single-axis blob put",
        ),
        rule(
            "multi_axis_le_sha256",
            Error,
            sel(Bw, Exact("hash.multi"), &[]),
            Le,
            1.0,
            sel(Bw, Exact("hash.sha256"), &[]),
            keys(DIGEST_BOUND),
            "single-pass multi-axis hashing exceeds its slowest constituent axis",
        ),
        rule(
            "multi_axis_le_blake3",
            Error,
            sel(Bw, Exact("hash.multi"), &[]),
            Le,
            1.0,
            sel(Bw, Exact("hash.blake3"), &[]),
            keys(DIGEST_BOUND),
            "single-pass multi-axis hashing exceeds a constituent axis",
        ),
        // redb 4.3.0 makes every durable commit durable with one
        // `StorageBackend::sync_data` (`File::sync_data`, fdatasync), two
        // with two-phase commit; it never issues fsync. One fdatasync is
        // therefore the floor of a durable commit and of every durable
        // publication, which commits through redb.
        //
        // On NVMe devices with write-cache enabled, both the standalone
        // fdatasync and the commit's fdatasync complete from the drive's
        // DRAM cache in microseconds. Measurement noise can make the
        // commit appear up to 5% faster than the standalone call without
        // indicating a skipped sync. The 0.95 multiplier absorbs that
        // noise; a commit that genuinely skips fdatasync would be 10-100x
        // faster than the floor. Severity Warn: the operator sees it
        // without gating the session, since a fast NVMe with power-loss
        // protected cache IS durable despite a fast fdatasync.
        rule(
            "redb_commit_ge_fdatasync",
            Warn,
            sel(Lat, Exact("redb.commit"), &[Eq("durability", "immediate")]),
            Ge,
            0.95,
            sel(Lat, Exact("device.fdatasync"), &[]),
            keys(&[]),
            "durable redb commit completes faster than one fdatasync: the commit was not durable",
        ),
        rule(
            "durable_publish_ge_fdatasync",
            Error,
            sel(
                Lat,
                Exact("store.publish"),
                &[Eq("backend", "redb"), Eq("durability", "immediate")],
            ),
            Ge,
            1.0,
            sel(Lat, Exact("device.fdatasync"), &[]),
            keys(&[]),
            "durable publication completes faster than one fdatasync: the epoch was not durable",
        ),
        rule(
            "publish_ge_epoch_sign",
            Error,
            sel(Lat, Exact("store.publish"), &[]),
            Ge,
            1.0,
            sel(Lat, Exact("epoch.sign"), &[]),
            keys(&[]),
            "publication completes faster than signing its epoch: the epoch was not signed",
        ),
        rule(
            "epoch_sign_ge_cose_sign",
            Error,
            sel(Lat, Exact("epoch.sign"), &[]),
            Ge,
            1.0,
            sel(Lat, Exact("crypto.cose.sign"), &[]),
            keys(&[]),
            "epoch signing completes faster than one COSE signature",
        ),
        rule(
            "cose_sign_ge_sign",
            Error,
            sel(Lat, Exact("crypto.cose.sign"), &[]),
            Ge,
            1.0,
            sel(Lat, Exact("crypto.sign.ed25519"), &[]),
            keys(&[]),
            "COSE signing completes faster than the raw signature it wraps",
        ),
        rule(
            "cose_verify_ge_verify",
            Error,
            sel(Lat, Exact("crypto.cose.verify"), &[]),
            Ge,
            1.0,
            sel(Lat, Exact("crypto.verify.ed25519"), &[]),
            keys(&[]),
            "COSE verification completes faster than the raw verification it wraps",
        ),
        rule(
            "admit_assertion_ge_cose_verify",
            Error,
            sel(Lat, Exact("crypto.admit.assertion"), &[]),
            Ge,
            1.0,
            sel(Lat, Exact("crypto.cose.verify"), &[]),
            keys(&[]),
            "assertion admission completes faster than verifying its signature",
        ),
        rule(
            "admit_succession_ge_two_verifies",
            Error,
            sel(Lat, Exact("crypto.admit.succession"), &[]),
            Ge,
            2.0,
            sel(Lat, Exact("crypto.verify.ed25519"), &[]),
            keys(&[]),
            "dual-signed succession admission completes faster than two signature verifications",
        ),
        rule(
            "seal_le_copy",
            Error,
            sel(Bw, Exact("crypto.aead.seal"), &[]),
            Le,
            1.0,
            sel(Bw, Exact("mem.copy"), &[]),
            keys(&["size"]),
            "AEAD seal exceeds memcpy at the same size; seal performs at least a copy",
        ),
        rule(
            "open_le_seal",
            Warn,
            sel(Bw, Exact("crypto.aead.open"), &[]),
            Le,
            1.1,
            sel(Bw, Exact("crypto.aead.seal"), &[]),
            keys(&["size", "variant"]),
            "AEAD open significantly exceeds seal for the same cipher and size",
        ),
        rule(
            "fdatasync_le_fsync",
            Warn,
            sel(Lat, Exact("device.fdatasync"), &[]),
            Le,
            1.1,
            sel(Lat, Exact("device.fsync"), &[]),
            keys(&["size"]),
            "fdatasync slower than fsync: metadata flush accounting is inverted",
        ),
        rule(
            "seq_read_ge_rand_read",
            Warn,
            sel(Bw, Exact("device.seq_read"), &[]),
            Ge,
            1.0,
            sel(Bw, Exact("device.rand_read"), &[]),
            keys(&["size", "qd"]),
            "random reads outpace sequential reads at the same size and queue depth: the page cache served one of them",
        ),
        rule(
            "memory_publish_le_redb",
            Warn,
            sel(Lat, Exact("store.publish"), &[Eq("backend", "memory")]),
            Le,
            1.0,
            sel(Lat, Exact("store.publish"), &[Eq("backend", "redb")]),
            keys(&["tags", "mutations"]),
            "in-memory publication slower than durable publication of the same shape",
        ),
        // Time to first result is cursor positioning on the smallest key; it
        // must not grow with the index. A violation is a correct, slow
        // measurement, so it warns and the record stays trusted.
        rule(
            "first_result_p99_10m_le_2x_100k",
            Warn,
            tail(
                Lat,
                Exact("index.advance"),
                &[Eq("variant", "first"), Eq("keys", "10000000")],
            ),
            Le,
            2.0,
            tail(
                Lat,
                SameAsSubject,
                &[Eq("variant", "first"), Eq("keys", "100000")],
            ),
            keys(&["depth", "state", "variant"]),
            "time to first result at 10^7 keys exceeds twice its p99 at 10^5 keys: positioning cost grows with the index",
        ),
        rule(
            "scaling_not_superlinear",
            Warn,
            sel(Ops, Any, &[Present("threads"), Ne("threads", "1t")]),
            LeThreadScaled,
            1.1,
            sel(Ops, SameAsSubject, &[Eq("threads", "1t")]),
            Agree::AllExcept(vec!["threads"]),
            "rate scales superlinearly with threads: the single-thread case was contended or the parallel case skipped work",
        ),
    ];
    for axis in [
        "sha256",
        "sha512",
        "blake3",
        "sha1",
        "sha3_256",
        "keccak256",
    ] {
        let hash_op: &'static str = match axis {
            "sha256" => "hash.sha256",
            "sha512" => "hash.sha512",
            "blake3" => "hash.blake3",
            "sha1" => "hash.sha1",
            "sha3_256" => "hash.sha3_256",
            _ => "hash.keccak256",
        };
        rules.push(rule(format!("blob_put_le_hash_{axis}"), Error, sel(Bw, Exact("store.blob_put"), &[Eq("axis", axis)]), Le, 1.0, sel(Bw, Exact(hash_op), &[]), keys(DIGEST_BOUND),
            "blob ingest exceeds the digest rate of its axis: content was stored without being hashed"));
        // The verified read hashes the same bytes the standalone hash
        // bench does, but on the memory backend the content is already
        // in L2/L3 from the store's Arc; the standalone hash bench may
        // start cold. 1.05 absorbs the cache advantage; a skipped
        // verification would be 2-10x faster than the hash alone.
        rules.push(rule(format!("verified_read_le_hash_{axis}"), Error, sel(Bw, Exact("store.blob_get_verified"), &[Eq("axis", axis)]), Le, 1.05, sel(Bw, Exact(hash_op), &[]), keys(DIGEST_BOUND),
            "verified read exceeds the digest rate of its axis: content was returned without verification"));
        rules.push(rule(
            format!("txn_put_le_hash_{axis}"),
            Error,
            sel(Bw, Exact("txn.put"), &[Eq("axis", axis)]),
            Le,
            1.0,
            sel(Bw, Exact(hash_op), &[]),
            keys(DIGEST_BOUND),
            "transaction staging exceeds the digest rate that verifies staged content",
        ));
    }
    rules
}

fn conds_hold(id: &OscId, conds: &[Cond]) -> bool {
    let c = id.conditions();
    conds.iter().all(|cond| match *cond {
        Cond::Eq(k, v) => c.get(k) == Some(v),
        Cond::Ne(k, v) => c.get(k) != Some(v),
        Cond::Present(k) => c.contains_key(k),
    })
}

fn subject_matches(rule: &Rule, id: &OscId) -> bool {
    let op_ok = match rule.subject.op {
        Op::Exact(op) => id.operation().canonical() == op,
        Op::Any => true,
        Op::SameAsSubject => false,
    };
    op_ok && id.quantity() == rule.subject.quantity && conds_hold(id, &rule.subject.conds)
}

fn bound_matches(rule: &Rule, subject: &OscId, bound: &OscId) -> bool {
    let op_ok = match rule.bound.op {
        Op::Exact(op) => bound.operation().canonical() == op,
        Op::SameAsSubject => bound.operation() == subject.operation(),
        Op::Any => true,
    };
    let (s, b) = (subject.conditions(), bound.conditions());
    let agree = match &rule.agree {
        Agree::Keys(keys) => keys.iter().all(|k| s.get(k) == b.get(k)),
        Agree::AllExcept(excluded) => {
            let relevant = |(k, _): &(&str, &str)| !excluded.contains(k);
            s.iter().filter(relevant).all(|(k, v)| b.get(k) == Some(v))
                && b.iter().filter(relevant).all(|(k, v)| s.get(k) == Some(v))
        }
    };
    op_ok
        && agree
        && bound.quantity() == rule.bound.quantity
        && conds_hold(bound, &rule.bound.conds)
        && bound.strip_substrate() != subject.strip_substrate()
}

fn threads(id: &OscId) -> Option<f64> {
    id.conditions()
        .get("threads")
        .and_then(|t| t.strip_suffix('t'))
        .and_then(|n| n.parse::<u32>().ok())
        .map(f64::from)
}

/// Evaluate every rule whose subject matches `subject` against every
/// matching established bound. A rule comparing a statistic that either
/// side lacks yields no result.
pub fn evaluate(
    rules: &[Rule],
    subject: &Established<'_>,
    established: &[Established<'_>],
) -> Vec<ValidationResult> {
    let id = subject.id;
    let mut results = Vec::new();
    for rule in rules.iter().filter(|rule| subject_matches(rule, id)) {
        let Some(value) = subject.stat(rule.subject.stat) else {
            continue;
        };
        for bound in established.iter().filter(|b| bound_matches(rule, id, b.id)) {
            let Some(bound_value) = bound.stat(rule.bound.stat) else {
                continue;
            };
            let (threshold, symbol) = match rule.relation {
                Relation::Le => (bound_value * rule.multiplier, "<="),
                Relation::Ge => (bound_value * rule.multiplier, ">="),
                Relation::LeThreadScaled => match (threads(id), threads(bound.id)) {
                    (Some(st), Some(bt)) if bt > 0.0 => {
                        (bound_value * rule.multiplier * st / bt, "<=")
                    }
                    _ => continue,
                },
            };
            let passed = if rule.relation == Relation::Ge {
                value >= threshold
            } else {
                value <= threshold
            };
            results.push(ValidationResult {
                rule: rule.id.clone(),
                predicate: format!(
                    "{}{} {symbol} {}{} x {:.2}",
                    stat_label(rule.subject.stat),
                    id.canonical(),
                    stat_label(rule.bound.stat),
                    bound.id.canonical(),
                    rule.multiplier
                ),
                bound_id: bound.id.canonical(),
                observed: value,
                bound: threshold,
                passed,
                severity: rule.severity,
                bound_from_baseline: bound.from_baseline,
                diagnosis: (!passed).then(|| rule.diagnosis.to_owned()),
            });
        }
    }
    results
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod tests;
