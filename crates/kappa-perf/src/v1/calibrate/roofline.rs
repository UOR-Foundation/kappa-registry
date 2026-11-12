//! Roofline grading (KAPPA-PERF-001 sections 1.2 and 1.3).
//!
//! Conformance asserts a fraction of a measured roofline, never an absolute
//! number. Each operation class names the calibrated floors that bound it:
//! single-object ingest by min(device write, slowest required digest),
//! verified read by min(device read, digest rate), epoch advance by
//! min(device sync rate, signature rate), index seek by depth times the
//! dependent-load latency of the resident tier, rebuild by a sequential
//! pass over the key bytes. Every term is expressed in the subject's
//! quantity; the bound is the binding term (the smallest rate or the
//! largest latency). For each term the best measured floor on this host is
//! used, because the roofline is the hardware ceiling. A class whose terms
//! are not all established yields a diagnosis, not a guessed grade, and the
//! grade never affects trust (PERF-DOC-002).

use super::grammar::OscId;
use super::quantity::Quantity;
use super::record::{Grade, Roofline};
use super::validate::Established;

/// How a term's floor value is transformed into the subject's quantity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scale {
    /// Convert between latency (ns/op) and rate (ops/s) as needed.
    Unit,
    /// Latency floor multiplied by the subject's count condition (e.g.
    /// descent depth times dependent-load latency).
    ByCount(&'static str),
    /// Latency bound = subject's `size` bytes / floor bandwidth.
    BytesOverBandwidth,
}

/// Which operation a term reads its floor from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermOp {
    Exact(&'static str),
    /// `hash.<axis>` for the subject's `axis` condition.
    HashOfAxis,
}

#[derive(Debug, Clone)]
pub struct Term {
    pub quantity: Quantity,
    pub op: TermOp,
    /// Conditions that must agree between subject and floor.
    pub agree: &'static [&'static str],
    /// Conditions the subject must carry for this term to apply at all.
    pub when: &'static [(&'static str, &'static str)],
    pub scale: Scale,
}

#[derive(Debug, Clone)]
pub struct RooflineClass {
    pub name: &'static str,
    pub subject_ops: &'static [&'static str],
    pub subject_quantities: &'static [Quantity],
    pub terms: Vec<Term>,
}

const fn term(
    quantity: Quantity,
    op: TermOp,
    agree: &'static [&'static str],
    when: &'static [(&'static str, &'static str)],
    scale: Scale,
) -> Term {
    Term {
        quantity,
        op,
        agree,
        when,
        scale,
    }
}

/// A single object's digest bound: the best implementation measured at the
/// subject's size, reference implementations included, never the aggregate
/// rate of several objects hashed in parallel lanes.
const SINGLE_OBJECT_DIGEST: &[&str] = &["size", "objects"];

/// The operation classes of section 1.3 expressed over the vocabulary.
pub fn classes() -> Vec<RooflineClass> {
    use Quantity::{Bw, Lat, Ops};
    use Scale::{ByCount, BytesOverBandwidth, Unit};
    use TermOp::{Exact, HashOfAxis};
    vec![
        RooflineClass {
            name: "ingest_single_object",
            subject_ops: &["store.blob_put", "store.ingest", "txn.put"],
            subject_quantities: &[Bw],
            terms: vec![
                term(
                    Bw,
                    Exact("device.seq_write"),
                    &["size", "durability"],
                    &[],
                    Unit,
                ),
                term(Bw, HashOfAxis, SINGLE_OBJECT_DIGEST, &[], Unit),
            ],
        },
        RooflineClass {
            name: "read_verified",
            subject_ops: &["store.blob_get_verified"],
            subject_quantities: &[Bw],
            terms: vec![
                term(Bw, Exact("device.seq_read"), &["size"], &[], Unit),
                term(Bw, HashOfAxis, SINGLE_OBJECT_DIGEST, &[], Unit),
            ],
        },
        RooflineClass {
            name: "read_unverified",
            subject_ops: &["store.blob_get"],
            subject_quantities: &[Bw],
            terms: vec![term(Bw, Exact("device.seq_read"), &["size"], &[], Unit)],
        },
        RooflineClass {
            name: "range_read",
            subject_ops: &["store.blob_get_range"],
            subject_quantities: &[Bw],
            terms: vec![term(Bw, Exact("device.rand_read"), &["size"], &[], Unit)],
        },
        // The device sync of a durable commit is the one redb issues:
        // `File::sync_data` (fdatasync), never fsync.
        RooflineClass {
            name: "epoch_advance",
            subject_ops: &["store.publish"],
            subject_quantities: &[Ops, Lat],
            terms: vec![
                term(Lat, Exact("crypto.sign.ed25519"), &[], &[], Unit),
                term(
                    Lat,
                    Exact("device.fdatasync"),
                    &[],
                    &[("backend", "redb"), ("durability", "immediate")],
                    Unit,
                ),
            ],
        },
        RooflineClass {
            name: "durable_commit",
            subject_ops: &["redb.commit"],
            subject_quantities: &[Ops, Lat],
            terms: vec![term(
                Lat,
                Exact("device.fdatasync"),
                &[],
                &[("durability", "immediate")],
                Unit,
            )],
        },
        // Recovery at open commits once through redb: its floor is the
        // device sync of that commit. A settlement step may settle
        // nothing and commit nothing, so it is validated (Warn rules) but
        // not graded.
        RooflineClass {
            name: "maintenance",
            subject_ops: &["recovery.open"],
            subject_quantities: &[Lat],
            terms: vec![term(
                Lat,
                Exact("device.fdatasync"),
                &[],
                &[("backend", "redb")],
                Unit,
            )],
        },
        RooflineClass {
            name: "index_seek",
            subject_ops: &["index.seek"],
            subject_quantities: &[Lat],
            terms: vec![term(
                Lat,
                Exact("mem.chase"),
                &["cache"],
                &[],
                ByCount("depth"),
            )],
        },
        RooflineClass {
            name: "index_rebuild",
            subject_ops: &["index.rebuild"],
            subject_quantities: &[Lat],
            terms: vec![term(Bw, Exact("mem.read"), &[], &[], BytesOverBandwidth)],
        },
    ]
}

fn hash_op(axis: &str) -> Option<&'static str> {
    Some(match axis {
        "sha256" => "hash.sha256",
        "sha512" => "hash.sha512",
        "blake3" => "hash.blake3",
        "sha1" => "hash.sha1",
        "sha3_256" => "hash.sha3_256",
        "keccak256" => "hash.keccak256",
        _ => return None,
    })
}

/// A floor converted into the subject's quantity.
#[allow(
    clippy::cast_precision_loss,
    reason = "sizes and counts far below 2^53"
)]
fn convert(term: &Term, subject: &OscId, floor: f64) -> Option<f64> {
    let target = subject.quantity();
    let value = match term.scale {
        Scale::Unit => match (term.quantity, target) {
            (a, b) if a == b => floor,
            (Quantity::Lat, Quantity::Ops) | (Quantity::Ops, Quantity::Lat) => 1e9 / floor,
            _ => return None,
        },
        Scale::ByCount(key) => {
            let count = subject.conditions().count(key)? as f64;
            match (term.quantity, target) {
                (Quantity::Lat, Quantity::Lat) => floor * count,
                _ => return None,
            }
        }
        Scale::BytesOverBandwidth => {
            let bytes = subject.conditions().magnitude("size")? as f64;
            match (term.quantity, target) {
                (Quantity::Bw, Quantity::Lat) => bytes / floor * 1e9,
                _ => return None,
            }
        }
    };
    (value.is_finite() && value > 0.0).then_some(value)
}

/// Grade `subject` if it belongs to a class.
///
/// `Ok(None)`: no class covers the subject. `Err`: a class covers it but a
/// term's floor is not established on this host.
pub fn grade(
    classes: &[RooflineClass],
    subject: &OscId,
    value: f64,
    established: &[Established<'_>],
) -> Result<Option<Roofline>, String> {
    let op = subject.operation().canonical();
    let Some(class) = classes.iter().find(|c| {
        c.subject_ops.contains(&op.as_str()) && c.subject_quantities.contains(&subject.quantity())
    }) else {
        return Ok(None);
    };
    let higher_is_better = subject.quantity().higher_is_better();
    // Resolve every applicable term's floor operation first: a subject that
    // omits a condition its class requires is malformed, whatever floors
    // happen to be established.
    let mut applicable = Vec::with_capacity(class.terms.len());
    for term in &class.terms {
        if !term
            .when
            .iter()
            .all(|(k, v)| subject.conditions().get(k) == Some(*v))
        {
            continue;
        }
        let floor_op = match term.op {
            TermOp::Exact(op) => op,
            TermOp::HashOfAxis => {
                let axis = subject
                    .conditions()
                    .get("axis")
                    .ok_or_else(|| format!("{}: subject declares no axis", class.name))?;
                hash_op(axis).ok_or_else(|| format!("{}: unknown axis {axis}", class.name))?
            }
        };
        applicable.push((term, floor_op));
    }
    let mut binding: Option<f64> = None;
    let mut bound_ids = Vec::new();
    for (term, floor_op) in applicable {
        // Best measured floor: the hardware ceiling for this term.
        let best = established
            .iter()
            .filter(|e| {
                e.id.quantity() == term.quantity
                    && e.id.operation().canonical() == floor_op
                    && term
                        .agree
                        .iter()
                        .all(|k| e.id.conditions().get(k) == subject.conditions().get(k))
            })
            .filter_map(|e| convert(term, subject, e.value).map(|v| (v, e.id.canonical())))
            .reduce(|a, b| {
                let better = if higher_is_better {
                    b.0 > a.0
                } else {
                    b.0 < a.0
                };
                if better { b } else { a }
            });
        let (term_value, term_id) = best.ok_or_else(|| {
            format!(
                "{}: floor {} {floor_op} not established",
                class.name, term.quantity
            )
        })?;
        bound_ids.push(term_id);
        binding = Some(match binding {
            None => term_value,
            Some(current) if higher_is_better => current.min(term_value),
            Some(current) => current.max(term_value),
        });
    }
    let bound_value = binding
        .ok_or_else(|| format!("{}: no term applies to {}", class.name, subject.canonical()))?;
    let fraction = subject
        .quantity()
        .achieved_fraction(value, bound_value)
        .ok_or_else(|| {
            format!(
                "{}: value {value} or bound {bound_value} not positive",
                class.name
            )
        })?;
    Ok(Some(Roofline {
        class: class.name.to_owned(),
        bound_ids,
        bound_value,
        fraction,
        grade: Grade::from_fraction(fraction),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn id(raw: &str) -> Result<OscId, Box<dyn std::error::Error>> {
        Ok(raw.parse()?)
    }

    #[test]
    fn classes_cover_each_subject_once_and_name_registered_operations() {
        let classes = classes();
        for class in &classes {
            for op in class.subject_ops {
                assert!(
                    super::super::operation::OperationPath::parse(op).is_ok(),
                    "{op}"
                );
                for quantity in class.subject_quantities {
                    let owners = classes
                        .iter()
                        .filter(|c| {
                            c.subject_ops.contains(op) && c.subject_quantities.contains(quantity)
                        })
                        .count();
                    assert_eq!(
                        owners, 1,
                        "{quantity}/{op} must belong to exactly one class"
                    );
                }
            }
            for term in &class.terms {
                if let TermOp::Exact(op) = term.op {
                    assert!(
                        super::super::operation::OperationPath::parse(op).is_ok(),
                        "{op}"
                    );
                }
            }
        }
    }

    #[test]
    fn ingest_is_bounded_by_the_slower_of_device_and_digest() -> TestResult {
        let write = id("osc:bw/device.seq_write?durability=none&size=1m")?;
        let write_slow = id("osc:bw/device.seq_write?durability=none&qd=1&size=1m")?;
        let hash = id("osc:bw/hash.sha256?size=1m")?;
        let established = [
            Established {
                id: &write,
                value: 2e9,
                tail: None,
                from_baseline: true,
            },
            Established {
                id: &write_slow,
                value: 1e8,
                tail: None,
                from_baseline: true,
            },
            Established {
                id: &hash,
                value: 4e8,
                tail: None,
                from_baseline: false,
            },
        ];
        let put = id("osc:bw/store.blob_put?axis=sha256&durability=none&size=1m")?;
        let roof = grade(&classes(), &put, 3.6e8, &established)?.ok_or("ungraded")?;
        assert_eq!(roof.class, "ingest_single_object");
        assert!(
            (roof.bound_value - 4e8).abs() < 1.0,
            "digest binds: {roof:?}"
        );
        assert!((roof.fraction - 0.9).abs() < 1e-9);
        assert_eq!(roof.grade, Grade::A);
        assert!(
            roof.bound_ids.contains(&write.canonical()),
            "best device floor chosen"
        );
        Ok(())
    }

    #[test]
    fn durable_publication_is_bounded_by_fdatasync_rate() -> TestResult {
        let sign = id("osc:lat/crypto.sign.ed25519")?;
        let fdatasync = id("osc:lat/device.fdatasync?size=4k")?;
        // A slower fsync floor must not be the bound: the durable path never
        // issues fsync.
        let fsync = id("osc:lat/device.fsync?size=4k")?;
        let established = [
            Established {
                id: &sign,
                value: 20_000.0,
                tail: None,
                from_baseline: true,
            },
            Established {
                id: &fdatasync,
                value: 1_000_000.0,
                tail: None,
                from_baseline: true,
            },
            Established {
                id: &fsync,
                value: 2_000_000.0,
                tail: None,
                from_baseline: true,
            },
        ];
        let durable = id("osc:ops/store.publish?backend=redb&durability=immediate")?;
        let roof = grade(&classes(), &durable, 300.0, &established)?.ok_or("ungraded")?;
        assert!(
            (roof.bound_value - 1_000.0).abs() < 1e-6,
            "fdatasync rate binds: {roof:?}"
        );
        assert!(!roof.bound_ids.contains(&fsync.canonical()));
        assert_eq!(roof.grade, Grade::D);
        let commit = id("osc:lat/redb.commit?durability=immediate")?;
        let roof = grade(&classes(), &commit, 1_250_000.0, &established)?.ok_or("ungraded")?;
        assert_eq!(roof.class, "durable_commit");
        assert!((roof.fraction - 0.8).abs() < 1e-9, "{roof:?}");
        let memory = id("osc:ops/store.publish?backend=memory")?;
        let roof = grade(&classes(), &memory, 45_000.0, &established)?.ok_or("ungraded")?;
        assert!(
            (roof.bound_value - 50_000.0).abs() < 1e-6,
            "signature rate binds in memory"
        );
        assert_eq!(roof.grade, Grade::A);
        Ok(())
    }

    #[test]
    fn seek_and_rebuild_bounds_scale_with_subject_conditions() -> TestResult {
        let chase = id("osc:lat/mem.chase?cache=l2")?;
        let read = id("osc:bw/mem.read?size=64m")?;
        let established = [
            Established {
                id: &chase,
                value: 4.0,
                tail: None,
                from_baseline: true,
            },
            Established {
                id: &read,
                value: 1e10,
                tail: None,
                from_baseline: true,
            },
        ];
        let seek = id("osc:lat/index.seek?cache=l2&depth=8")?;
        let roof = grade(&classes(), &seek, 64.0, &established)?.ok_or("ungraded")?;
        assert!((roof.bound_value - 32.0).abs() < 1e-9);
        assert_eq!(roof.grade, Grade::C);
        let rebuild = id("osc:lat/index.rebuild?keys=1000&size=1g")?;
        let roof = grade(&classes(), &rebuild, 1e9, &established)?.ok_or("ungraded")?;
        assert!((roof.bound_value - 107_374_182.4).abs() < 1.0);
        Ok(())
    }

    #[test]
    fn ingest_bound_takes_the_best_single_object_digest_never_a_lane_aggregate() -> TestResult {
        let write = id("osc:bw/device.seq_write?durability=none&size=1m")?;
        let ours = id("osc:bw/hash.sha256?size=1m")?;
        let reference = id("osc:bw/hash.sha256?impl=aws_lc&size=1m")?;
        let lanes = id("osc:bw/hash.sha256?impl=isal_mb&objects=8&size=1m")?;
        let floor = |id, value| Established {
            id,
            value,
            tail: None,
            from_baseline: false,
        };
        let established = [
            floor(&write, 2e9),
            floor(&ours, 1.4e8),
            floor(&reference, 4.6e8),
            floor(&lanes, 1.2e9),
        ];
        let put = id("osc:bw/store.blob_put?axis=sha256&durability=none&size=1m")?;
        let roof = grade(&classes(), &put, 1.3e8, &established)?.ok_or("ungraded")?;
        assert!(
            (roof.bound_value - 4.6e8).abs() < 1.0,
            "the reference digest binds: {roof:?}"
        );
        assert!(roof.bound_ids.contains(&reference.canonical()));
        assert!(!roof.bound_ids.contains(&lanes.canonical()));
        Ok(())
    }

    #[test]
    fn missing_floors_and_unclassed_subjects_are_distinguished() -> TestResult {
        let put = id("osc:bw/store.blob_put?axis=sha256&size=1m")?;
        assert!(grade(&classes(), &put, 1.0, &[]).is_err());
        let hash = id("osc:bw/hash.sha256?size=1m")?;
        assert_eq!(grade(&classes(), &hash, 1.0, &[])?, None);
        let no_axis = id("osc:bw/store.blob_put?size=1m")?;
        assert!(grade(&classes(), &no_axis, 1.0, &[]).is_err_and(|e| e.contains("axis")));
        Ok(())
    }
}
