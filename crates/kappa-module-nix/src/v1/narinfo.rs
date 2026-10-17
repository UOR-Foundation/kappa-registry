//! Nix narinfo text codec.
//!
//! Parses and generates the line-based key-value format used by Nix
//! binary caches for store-path metadata. Field order, hash format,
//! and mandatory-field rules match NarInfo::to_string() and the
//! NarInfo parser in NixOS/nix src/libstore/nar-info.cc.

use std::str::FromStr;

use nix_derivation::StorePath;
use nix_derivation::nixbase32;

/// Narinfo parse/serialize errors.
///
/// Each variant identifies a specific validation failure so callers
/// can produce precise HTTP error responses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NarInfoError {
    #[error("missing mandatory field: {0}")]
    MissingField(&'static str),

    #[error("invalid store path: {0}")]
    InvalidStorePath(String),

    #[error("invalid hash: {0}")]
    InvalidHash(String),

    #[error("invalid NarSize: {0}")]
    InvalidNarSize(String),

    #[error("invalid FileSize: {0}")]
    InvalidFileSize(String),

    #[error("duplicate field: {0}")]
    DuplicateField(&'static str),

    #[error("malformed line (no colon separator): {0}")]
    MalformedLine(String),
}

/// Parsed narinfo metadata for one store path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarInfo {
    pub store_path: StorePath,
    pub url: String,
    pub compression: String,
    pub file_hash: Option<String>,
    pub file_size: Option<u64>,
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: Vec<String>,
    pub deriver: Option<String>,
    pub signatures: Vec<String>,
    pub ca: Option<String>,
}

impl NarInfo {
    /// Parse narinfo text.
    ///
    /// Matches the parser in nar-info.cc:
    /// - separator is ": " (colon-space)
    /// - unknown fields silently ignored (forward compatibility)
    /// - duplicate References or CA produces an error
    /// - other duplicates: last value wins
    /// - Deriver "unknown-deriver" becomes None
    /// - empty/missing Compression defaults to "bzip2"
    /// - mandatory fields: StorePath, NarHash, URL, NarSize > 0
    ///
    /// # Errors
    ///
    /// Returns `NarInfoError` for missing mandatory fields, invalid
    /// hash formats, invalid numeric fields, duplicate References/CA,
    /// or lines without a colon separator.
    pub fn parse(text: &str) -> Result<Self, NarInfoError> {
        let mut store_path: Option<StorePath> = None;
        let mut url: Option<String> = None;
        let mut compression: Option<String> = None;
        let mut file_hash: Option<String> = None;
        let mut file_size: Option<u64> = None;
        let mut nar_hash: Option<String> = None;
        let mut nar_size: u64 = 0;
        let mut references: Option<Vec<String>> = None;
        let mut deriver: Option<String> = None;
        let mut signatures: Vec<String> = Vec::new();
        let mut ca: Option<String> = None;

        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let colon_pos = line
                .find(':')
                .ok_or_else(|| NarInfoError::MalformedLine(line.to_string()))?;
            let key = &line[..colon_pos];
            // One space conventionally follows the colon; a value written
            // without it starts immediately after the colon.
            let rest = &line[colon_pos + 1..];
            let value = rest.strip_prefix(' ').unwrap_or(rest);

            match key {
                "StorePath" => {
                    store_path = Some(
                        StorePath::from_str(value)
                            .map_err(|e| NarInfoError::InvalidStorePath(e.to_string()))?,
                    );
                }
                "URL" => {
                    url = Some(value.to_string());
                }
                "Compression" => {
                    compression = Some(if value.is_empty() {
                        "bzip2".to_string()
                    } else {
                        value.to_string()
                    });
                }
                "FileHash" => {
                    nix_derivation::NixHash::parse(value)
                        .map_err(|e| NarInfoError::InvalidHash(e.to_string()))?;
                    file_hash = Some(value.to_string());
                }
                "FileSize" => {
                    file_size = Some(
                        value
                            .parse::<u64>()
                            .map_err(|e| NarInfoError::InvalidFileSize(e.to_string()))?,
                    );
                }
                "NarHash" => {
                    nix_derivation::NixHash::parse(value)
                        .map_err(|e| NarInfoError::InvalidHash(e.to_string()))?;
                    nar_hash = Some(value.to_string());
                }
                "NarSize" => {
                    nar_size = value
                        .parse::<u64>()
                        .map_err(|e| NarInfoError::InvalidNarSize(e.to_string()))?;
                }
                "References" => {
                    if references.is_some() {
                        return Err(NarInfoError::DuplicateField("References"));
                    }
                    let refs: Vec<String> = if value.is_empty() {
                        Vec::new()
                    } else {
                        value.split(' ').map(|s| s.to_string()).collect()
                    };
                    references = Some(refs);
                }
                "Deriver" => {
                    deriver = if value == "unknown-deriver" {
                        None
                    } else {
                        Some(value.to_string())
                    };
                }
                "Sig" => {
                    signatures.push(value.to_string());
                }
                "CA" => {
                    if ca.is_some() {
                        return Err(NarInfoError::DuplicateField("CA"));
                    }
                    ca = Some(value.to_string());
                }
                _ => {}
            }
        }

        let compression = compression.unwrap_or_else(|| "bzip2".to_string());
        let references = references.unwrap_or_default();

        let store_path = store_path.ok_or(NarInfoError::MissingField("StorePath"))?;
        let nar_hash = nar_hash.ok_or(NarInfoError::MissingField("NarHash"))?;
        let url = url.ok_or(NarInfoError::MissingField("URL"))?;
        if url.is_empty() {
            return Err(NarInfoError::MissingField("URL"));
        }
        if nar_size == 0 {
            return Err(NarInfoError::MissingField("NarSize"));
        }

        Ok(NarInfo {
            store_path,
            url,
            compression,
            file_hash,
            file_size,
            nar_hash,
            nar_size,
            references,
            deriver,
            signatures,
            ca,
        })
    }

    /// Serialize to narinfo text.
    ///
    /// Field order matches NarInfo::to_string() in nar-info.cc:
    /// StorePath, URL, Compression, FileHash, FileSize, NarHash,
    /// NarSize, References (always emitted), Deriver, Sig (repeated),
    /// CA.
    pub fn to_narinfo_string(&self) -> String {
        let mut out = String::with_capacity(512);

        out.push_str("StorePath: ");
        out.push_str(&self.store_path.to_string());
        out.push('\n');

        out.push_str("URL: ");
        out.push_str(&self.url);
        out.push('\n');

        out.push_str("Compression: ");
        out.push_str(&self.compression);
        out.push('\n');

        if let Some(ref fh) = self.file_hash {
            out.push_str("FileHash: ");
            out.push_str(fh);
            out.push('\n');
        }

        if let Some(fs) = self.file_size {
            out.push_str("FileSize: ");
            out.push_str(&fs.to_string());
            out.push('\n');
        }

        out.push_str("NarHash: ");
        out.push_str(&self.nar_hash);
        out.push('\n');

        out.push_str("NarSize: ");
        out.push_str(&self.nar_size.to_string());
        out.push('\n');

        out.push_str("References: ");
        out.push_str(&self.references.join(" "));
        out.push('\n');

        if let Some(ref d) = self.deriver {
            out.push_str("Deriver: ");
            out.push_str(d);
            out.push('\n');
        }

        for sig in &self.signatures {
            out.push_str("Sig: ");
            out.push_str(sig);
            out.push('\n');
        }

        if let Some(ref ca_val) = self.ca {
            out.push_str("CA: ");
            out.push_str(ca_val);
            out.push('\n');
        }

        out
    }

    /// Construct the fingerprint string for Ed25519 signing/verification.
    ///
    /// Format: "1;{store_path};{nar_hash};{nar_size};{comma-separated full ref paths}"
    /// References are converted from basenames to full /nix/store/ paths.
    pub fn fingerprint(&self) -> String {
        let refs_full: Vec<String> = self
            .references
            .iter()
            .map(|basename| format!("/nix/store/{}", basename))
            .collect();

        format!(
            "1;{};{};{};{}",
            self.store_path,
            self.nar_hash,
            self.nar_size,
            refs_full.join(","),
        )
    }

    /// The 32-character nix-base32 hash part of the store path.
    /// This is the {hash} in GET /{hash}.narinfo.
    pub fn store_path_hash(&self) -> String {
        nixbase32::encode(self.store_path.digest())
    }
}
