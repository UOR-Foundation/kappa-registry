#![forbid(unsafe_code)]
//! Git smart HTTP protocol module for kappa-registry.
//!
//! Provides Git protocol support over the KappaStore trait. Objects are
//! stored as Git envelopes (the hash preimage). The protocol layer strips
//! envelopes before serving content to Git clients.
//!
//! Standard Git smart HTTP paths:
//!   GET  /{repo}/info/refs?service=git-upload-pack
//!   POST /{repo}/git-upload-pack
//!   GET  /{repo}/info/refs?service=git-receive-pack
//!   POST /{repo}/git-receive-pack
//!
//! No dependency on topcoat, tokio, redb, or any HTTP type. WASM-portable.

pub mod envelope;
pub mod hooks;
pub mod ingest;
pub mod lfs;
pub mod packgen;
pub mod protocol;
pub mod provider;
pub mod refs;

pub use envelope::{
    git_object_id_sha1, git_object_id_sha256, kappa_to_oid, oid_to_kappa,
    unwrap, wrap, EnvelopeError,
};
pub use hooks::{run_pre_receive, spawn_post_receive, set_hook, delete_hook, HookError, RefUpdate};
pub use ingest::{ingest_pack, IngestError, PackIngestResult};
pub use lfs::{process_batch, verify_object, BatchRequest, BatchResponse};
pub use packgen::{generate_pack, PackGenError, PackGenerateResult};
pub use protocol::{
    handle_receive_pack, handle_upload_pack, handle_v2_upload_pack,
    write_ref_advertisement, write_v2_capability_advertisement, ProtocolError,
};
pub use provider::KappaStoreObjectProvider;
pub use refs::{delete_ref, list_refs, resolve_ref, set_symbolic_ref, update_ref, RefError};
