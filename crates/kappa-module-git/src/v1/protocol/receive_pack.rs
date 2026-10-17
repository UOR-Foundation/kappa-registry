//! git-receive-pack in three phases.
//!
//! 1. [`prepare_receive_pack`] parses the commands, retains the pack, and
//!    runs the pre-receive hook. Nothing is written.
//! 2. [`apply_ref_updates`] runs inside the repository's execution: the
//!    pack's objects are prepared through the store and installed in the
//!    execution, then every command is checked against the ref's current
//!    value under the execution's writer, so a stale command is rejected
//!    instead of overwriting a concurrent push. The objects and the
//!    accepted updates publish together in one signed epoch; a push whose
//!    every command is rejected installs nothing.
//! 3. [`write_receive_report`] writes report-status after publication.

use std::io::{BufReader, Read, Write};
use std::sync::Arc;

use gix_packetline::PacketLineRef;
use gix_packetline::blocking_io::encode;

use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::blob::BlobStore;
use kappa_store::traits::tag::TagStore;
use kappa_store::{ContentPreparation, ExecutionWrites, PreparationBounds};

use crate::delta::DeltaBudget;
use crate::envelope;
use crate::hooks;
use crate::ingest;
use crate::refs;

use super::ProtocolError;
use super::graph;
use super::upload_pack::decode_line;

/// Parsed commands of one push and its pack, after the pre-receive hook.
#[derive(Debug)]
pub struct ReceivePlan {
    updates: Vec<hooks::RefUpdate>,
    rejection: Option<String>,
    object_hash: gix_hash::Kind,
    /// The packfile following the commands, ingested by
    /// [`apply_ref_updates`].
    pack: Vec<u8>,
}

impl ReceivePlan {
    /// The pre-receive hook's rejection; a rejected push writes no ref.
    pub fn rejection(&self) -> Option<&str> {
        self.rejection.as_deref()
    }

    pub fn updates(&self) -> &[hooks::RefUpdate] {
        &self.updates
    }

    fn zero_oid(&self) -> String {
        "0".repeat(self.object_hash.len_in_bytes() * 2)
    }

    fn kappa(&self, oid: &str) -> Result<Kappa, ProtocolError> {
        let label = format!("{}:{oid}", envelope::hash_prefix(self.object_hash));
        Kappa::parse(&label).map_err(|e| ProtocolError::Protocol(format!("invalid OID {oid}: {e}")))
    }
}

/// Per-command result of applying a plan: `None` accepted, `Some(reason)`
/// rejected.
#[derive(Debug, Default, Clone)]
pub struct RefOutcomes {
    rejections: Vec<Option<String>>,
}

impl RefOutcomes {
    /// True when at least one ref changed and the execution must publish.
    pub fn changed(&self) -> bool {
        self.rejections.iter().any(Option::is_none)
    }

    /// The plan's commands that were applied, for the post-receive hook.
    pub fn accepted(&self, plan: &ReceivePlan) -> Vec<hooks::RefUpdate> {
        plan.updates
            .iter()
            .zip(&self.rejections)
            .filter(|(_, rejection)| rejection.is_none())
            .map(|(update, _)| update.clone())
            .collect()
    }
}

/// Persisted in an operation receipt as one string per command: `+` for an
/// accepted command, `-` followed by the reason for a rejected one.
impl kappa_handler::OperationResult for RefOutcomes {
    fn encode(&self) -> Vec<u8> {
        let entries: Vec<String> = self
            .rejections
            .iter()
            .map(|rejection| {
                rejection
                    .as_ref()
                    .map_or_else(|| "+".to_string(), |reason| format!("-{reason}"))
            })
            .collect();
        entries.encode()
    }

    fn decode(bytes: &[u8]) -> Result<Self, kappa_handler::HandlerError> {
        let rejections = Vec::<String>::decode(bytes)?
            .into_iter()
            .map(|entry| match entry.split_at_checked(1) {
                Some(("+", "")) => Ok(None),
                Some(("-", reason)) => Ok(Some(reason.to_string())),
                _ => Err(kappa_handler::HandlerError::internal(
                    "operation receipt carries an invalid ref outcome",
                )),
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { rejections })
    }
}

/// Phase 1: parse commands, retain the pack, and run the pre-receive hook.
pub fn prepare_receive_pack<R: Read, S: BlobStore + TagStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    request: R,
    object_hash: gix_hash::Kind,
) -> Result<ReceivePlan, ProtocolError> {
    let mut buf_reader = BufReader::new(request);
    let mut updates = Vec::new();
    let mut reader = gix_packetline::blocking_io::StreamingPeekableIter::new(
        &mut buf_reader,
        &[PacketLineRef::Flush],
        false,
    );
    while let Some(line_result) = reader.read_line() {
        let text = decode_line(line_result)?;
        let cmd = text.split('\0').next().unwrap_or(&text);
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if let [old_oid, new_oid, ref_name, ..] = parts.as_slice() {
            updates.push(hooks::RefUpdate {
                old_oid: (*old_oid).to_string(),
                new_oid: (*new_oid).to_string(),
                ref_name: (*ref_name).to_string(),
            });
        }
    }

    let mut pack = Vec::new();
    reader.into_inner().read_to_end(&mut pack)?;

    let rejection = match hooks::run_pre_receive(store, namespace, &updates, 30) {
        Ok(()) => None,
        Err(hooks::HookError::Rejected(msg)) => Some(msg),
        Err(hooks::HookError::Timeout(secs)) => Some(format!("hook timed out after {secs}s")),
        Err(e) => Some(e.to_string()),
    };
    Ok(ReceivePlan {
        updates,
        rejection,
        object_hash,
        pack,
    })
}

/// Phase 2: ingest the plan's pack and apply its ref commands inside the
/// repository execution.
///
/// Objects are prepared through `store` within `bounds`, with delta
/// results reserved against `budget`, and installed in the execution
/// before any ref is read. A rejected command records its reason and
/// writes nothing; store failures latch the execution and are returned.
pub fn apply_ref_updates<S: ContentPreparation + ?Sized, E: ExecutionWrites + ?Sized>(
    store: &S,
    execution: &mut E,
    plan: &ReceivePlan,
    bounds: PreparationBounds,
    budget: &Arc<DeltaBudget>,
) -> Result<RefOutcomes, ProtocolError> {
    if !plan.pack.is_empty() {
        let pack_result = ingest::ingest_pack(
            store,
            execution,
            plan.pack.as_slice(),
            plan.object_hash,
            bounds,
            budget,
        )?;
        tracing::info!(
            objects = pack_result.objects_ingested,
            dedup = pack_result.objects_deduplicated,
            "pack ingested"
        );
    }
    let zero_oid = plan.zero_oid();
    let mut outcomes = RefOutcomes::default();
    for update in &plan.updates {
        let old = (update.old_oid != zero_oid)
            .then(|| plan.kappa(&update.old_oid))
            .transpose()?;
        let result = if update.new_oid == zero_oid {
            refs::delete_ref(execution, &update.ref_name, old.as_ref())
        } else {
            let new = plan.kappa(&update.new_oid)?;
            refs::update_ref(execution, &update.ref_name, &new, old.as_ref())
        };
        match result {
            Ok(()) => outcomes.rejections.push(None),
            Err(error) if error.is_rejection() => outcomes.rejections.push(Some(error.to_string())),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(outcomes)
}

/// Phase 3: write report-status. `outcomes` is `None` when the pre-receive
/// hook rejected the push.
pub fn write_receive_report<W: Write, S: BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    plan: &ReceivePlan,
    outcomes: Option<&RefOutcomes>,
    mut response: W,
) -> Result<(), ProtocolError> {
    let (Some(outcomes), None) = (outcomes, plan.rejection()) else {
        let reason = plan.rejection().unwrap_or("push not applied");
        for update in &plan.updates {
            let line = format!(
                "ng {} pre-receive hook declined: {reason}\n",
                update.ref_name
            );
            encode::data_to_write(line.as_bytes(), &mut response)?;
        }
        encode::flush_to_write(&mut response)?;
        return Ok(());
    };

    write_sideband_line(&mut response, b"unpack ok\n")?;
    let zero_oid = plan.zero_oid();
    let prefix = envelope::hash_prefix(plan.object_hash);
    for (update, rejection) in plan.updates.iter().zip(&outcomes.rejections) {
        let mut inner = Vec::new();
        match rejection {
            Some(reason) => {
                let line = format!("ng {} {reason}\n", update.ref_name);
                encode::data_to_write(line.as_bytes(), &mut inner)?;
            }
            None => {
                let line = format!("ok {}\n", update.ref_name);
                encode::data_to_write(line.as_bytes(), &mut inner)?;
                // report-status-v2 option lines
                for option in [
                    format!("option refname {}\n", update.ref_name),
                    format!("option old-oid {}\n", update.old_oid),
                    format!("option new-oid {}\n", update.new_oid),
                ] {
                    encode::data_to_write(option.as_bytes(), &mut inner)?;
                }
                if update.old_oid != zero_oid && update.new_oid != zero_oid {
                    let new_reachable = graph::walk_reachable(
                        store,
                        namespace,
                        vec![update.new_oid.clone()],
                        plan.object_hash,
                    );
                    if !new_reachable.contains(&format!("{prefix}:{}", update.old_oid)) {
                        encode::data_to_write(b"option forced-update\n", &mut inner)?;
                    }
                }
            }
        }
        write_sideband(&mut response, &inner)?;
    }

    // Inner flush inside side-band channel 1, then the outer flush.
    let mut inner = Vec::new();
    encode::flush_to_write(&mut inner)?;
    write_sideband(&mut response, &inner)?;
    encode::flush_to_write(&mut response)?;
    Ok(())
}

fn write_sideband<W: Write>(out: &mut W, inner: &[u8]) -> Result<(), ProtocolError> {
    let mut sb = Vec::with_capacity(1 + inner.len());
    sb.push(1);
    sb.extend_from_slice(inner);
    encode::data_to_write(&sb, out)?;
    Ok(())
}

fn write_sideband_line<W: Write>(out: &mut W, data: &[u8]) -> Result<(), ProtocolError> {
    let mut inner = Vec::new();
    encode::data_to_write(data, &mut inner)?;
    write_sideband(out, &inner)
}
