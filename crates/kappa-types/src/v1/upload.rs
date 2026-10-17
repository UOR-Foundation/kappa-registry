use crate::kappa::Kappa;

/// Unique identifier for an in-progress upload session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UploadId(pub String);

impl std::fmt::Display for UploadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Receipt for a successfully uploaded part.
#[derive(Debug, Clone)]
pub struct PartReceipt {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
}

/// Result of completing an upload or a direct ingest.
#[non_exhaustive]
pub struct IngestResult {
    /// The content address of the stored content.
    pub kappa: Kappa,
    /// True if the blob was newly stored, false if it already existed.
    pub newly_stored: bool,
    /// Additional addresses computed by mandatory axes.
    pub additional_kappas: Vec<Kappa>,
    /// Composite `ETag` for multipart uploads. None for single-PUT objects.
    pub etag: Option<String>,
}

impl IngestResult {
    pub const fn new(kappa: Kappa, newly_stored: bool) -> Self {
        Self {
            kappa,
            newly_stored,
            additional_kappas: Vec::new(),
            etag: None,
        }
    }

    #[must_use]
    pub fn with_additional(mut self, additional: Vec<Kappa>) -> Self {
        self.additional_kappas = additional;
        self
    }

    #[must_use]
    pub fn with_etag(mut self, etag: String) -> Self {
        self.etag = Some(etag);
        self
    }
}
