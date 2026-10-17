use kappa_types::ProtocolId;
use std::sync::LazyLock;

static PROTOCOL_ID: LazyLock<ProtocolId> =
    LazyLock::new(|| ProtocolId::new("git").expect("valid protocol id"));

/// Git smart HTTP protocol surface identifier.
pub fn protocol_id() -> &'static ProtocolId {
    &PROTOCOL_ID
}

pub mod delta;
pub mod detect;
pub mod envelope;
pub mod handlers;
pub mod hooks;
pub mod ingest;
pub mod lfs;
pub mod packgen;
pub mod protocol;
pub mod provider;
pub mod refs;

pub use detect::{GitDumbHttpDetector, GitHeaderDetector, GitPathDetector};
pub use envelope::{
    EnvelopeError, git_object_id_sha1, git_object_id_sha256, kappa_to_oid, oid_to_kappa, unwrap,
    wrap,
};
pub use handlers::register;
pub use hooks::{HookError, RefUpdate, delete_hook, run_pre_receive, set_hook, spawn_post_receive};
pub use ingest::{IngestError, PackIngestResult, ingest_pack};
pub use lfs::{BatchRequest, BatchResponse, process_batch, verify_object};
pub use packgen::{PackGenError, PackGenerateResult, generate_pack};
pub use protocol::{
    ProtocolError, ReceivePlan, RefOutcomes, apply_ref_updates, handle_upload_pack,
    handle_v2_upload_pack, prepare_receive_pack, write_receive_report, write_ref_advertisement,
    write_v2_capability_advertisement,
};
pub use provider::KappaStoreObjectProvider;
pub use refs::{
    RefError, delete_ref, list_refs, resolve_ref, resolve_ref_in, set_symbolic_ref, update_ref,
};
