use std::collections::HashSet;
use std::io;

use kappa_store::error::StoreError;

use crate::envelope::EnvelopeError;
use crate::hooks::HookError;
use crate::ingest::IngestError;
use crate::packgen::PackGenError;
use crate::refs::RefError;

pub mod advertisement;
pub mod graph;
pub mod receive_pack;
pub mod upload_pack;

pub use advertisement::{write_ref_advertisement, write_v2_capability_advertisement};
pub use receive_pack::{
    ReceivePlan, RefOutcomes, apply_ref_updates, prepare_receive_pack, write_receive_report,
};
pub use upload_pack::{handle_upload_pack, handle_v2_upload_pack};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("ref error: {0}")]
    Ref(#[from] RefError),
    #[error("ingest error: {0}")]
    Ingest(#[from] IngestError),
    #[error("pack gen error: {0}")]
    PackGen(#[from] PackGenError),
    #[error("envelope error: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("hook error: {0}")]
    Hook(#[from] HookError),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("protocol error: {0}")]
    Protocol(String),
}

#[derive(Debug, Default)]
pub(crate) struct FetchOptions {
    pub deepen: Option<u32>,
    pub client_shallows: HashSet<String>,
    pub filter: Option<FilterSpec>,
}

#[derive(Debug, Clone)]
pub(crate) enum FilterSpec {
    BlobNone,
    BlobLimit(u64),
}
