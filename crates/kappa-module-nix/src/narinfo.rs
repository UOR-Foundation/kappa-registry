//! Nix narinfo text codec.
//!
//! Parses and generates the line-based key-value format used by Nix
//! binary caches for store-path metadata. Field order, hash format,
//! and mandatory-field rules match NarInfo::to_string() and the
//! NarInfo parser in NixOS/nix src/libstore/nar-info.cc.

use std::str::FromStr;

use nix_derivation::nixbase32;
use nix_derivation::StorePath;
use thiserror::Error;

#[derive(Debug, Error)]
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
    #[error("parse error: {0}")]
    Parse(String),
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
    /// Parse narinfo text. Matches the parser in nar-info.cc:
    /// - separator is ": " (colon-space)
    /// - unknown fields silently ignored
    /// - duplicate References or CA is an error
    /// - other duplicates: last wins
    /// - Deriver: "unknown-deriver" becomes None
    /// - empty/missing Compression defaults to "bzip2"
    /// - mandatory: StorePath, NarHash, URL, NarSize > 0
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
            let Some(colon_pos) = line.find(':') else {
                return Err(NarInfoError::Parse(format!("no colon in line: {}", line)));
            };
            let key = &line[..colon_pos];
            // Value starts at colon + 2 (skip ": "). If line is "Key: val",
            // value is "val". If line is "Key: " (trailing space), value is "".
            // If line is "Key:" (no space after colon), treat as empty value.
            let value = if line.len() > colon_pos + 2 {
                &line[colon_pos + 2..]
            } else if line.len() > colon_pos + 1 {
                // "Key: " with nothing after space, or "Key:X" (no space)
                &line[colon_pos + 1..].trim_start()
            } else {
                ""
            };

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
                    // Validate format by parsing with NixHash
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
                _ => {
                    // Unknown fields silently ignored
                }
            }
        }

        // Apply defaults
        let compression = compression.unwrap_or_else(|| "bzip2".to_string());
        let references = references.unwrap_or_default();

        // Mandatory field checks
        let store_path =
            store_path.ok_or(NarInfoError::MissingField("StorePath"))?;
        let nar_hash =
            nar_hash.ok_or(NarInfoError::MissingField("NarHash"))?;
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

    /// Serialize to narinfo text. Field order matches NarInfo::to_string()
    /// in nar-info.cc exactly.
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

        // References always emitted, even when empty
        out.push_str("References: ");
        out.push_str(&self.references.join(" "));
        out.push('\n');

        if let Some(ref d) = self.deriver {
            out.push_str("Deriver: ");
            out.push_str(d);
            out.push('\n');
        }

        // Signatures in insertion order (sorted by the caller if needed)
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

#[cfg(test)]
mod tests {
    use super::*;

    const LIBIDN2_NARINFO: &str = "\
StorePath: /nix/store/r5sjd57x0r07bwgipryaxqdkx1gglhiy-libidn2-2.3.2\n\
URL: nar/010zh5j819qyz6zai6h2hn3d7i406g00m2g4g62bq7m8g91553yb.nar.xz\n\
Compression: xz\n\
FileHash: sha256:010zh5j819qyz6zai6h2hn3d7i406g00m2g4g62bq7m8g91553yb\n\
FileSize: 63248\n\
NarHash: sha256:1npw0jz1cw4k9x25f2vsdhsa5cf9568j46bpz2768a1izqj5n9lf\n\
NarSize: 260816\n\
References: 0z7sqj4pilbqyp45ix5b0mdgn9xlb024-libunistring-0.9.10 r5sjd57x0r07bwgipryaxqdkx1gglhiy-libidn2-2.3.2\n\
Deriver: 0n91syjwrhmng41f8d23ad0sl4a6ic4g-libidn2-2.3.2.drv\n\
Sig: cache.nixos.org-1:G9PxMT0/nd9ELwL3BBeqWtb2ohMiqw4T4FUwFlAU9M0E45mKg77BzL9gJQ3wH4oYtsa61MV5uzNLPFvK8ZbyCA==\n";

    #[test]
    fn parse_roundtrip_libidn2() {
        let parsed = NarInfo::parse(LIBIDN2_NARINFO).unwrap();
        assert_eq!(parsed.store_path.name(), "libidn2-2.3.2");
        assert_eq!(parsed.compression, "xz");
        assert_eq!(parsed.references.len(), 2);
        assert_eq!(parsed.nar_size, 260816);
        assert!(parsed.deriver.is_some());
        assert_eq!(parsed.signatures.len(), 1);

        let serialized = parsed.to_narinfo_string();
        assert_eq!(serialized, LIBIDN2_NARINFO);
    }

    #[test]
    fn parse_empty_references() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
Compression: none\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n";
        let parsed = NarInfo::parse(text).unwrap();
        assert!(parsed.references.is_empty());
        let serialized = parsed.to_narinfo_string();
        assert!(serialized.contains("References: \n"));
    }

    #[test]
    fn parse_missing_store_path() {
        let text = "\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n";
        let err = NarInfo::parse(text).unwrap_err();
        assert!(err.to_string().contains("StorePath"));
    }

    #[test]
    fn parse_missing_nar_hash() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarSize: 100\n";
        let err = NarInfo::parse(text).unwrap_err();
        assert!(err.to_string().contains("NarHash"));
    }

    #[test]
    fn parse_missing_url() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n";
        let err = NarInfo::parse(text).unwrap_err();
        assert!(err.to_string().contains("URL"));
    }

    #[test]
    fn parse_zero_nar_size() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 0\n";
        let err = NarInfo::parse(text).unwrap_err();
        assert!(err.to_string().contains("NarSize"));
    }

    #[test]
    fn parse_duplicate_references_is_error() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: foo-bar\n\
References: baz-qux\n";
        let err = NarInfo::parse(text).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn parse_duplicate_ca_is_error() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n\
CA: fixed:r:sha256:0000000000000000000000000000000000000000000000000000\n\
CA: fixed:r:sha256:1111111111111111111111111111111111111111111111111111\n";
        let err = NarInfo::parse(text).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn parse_duplicate_store_path_last_wins() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-first\n\
StorePath: /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-second\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n";
        let parsed = NarInfo::parse(text).unwrap();
        assert_eq!(parsed.store_path.name(), "second");
    }

    #[test]
    fn parse_unknown_field_ignored() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
Compression: none\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n\
System: x86_64-linux\n\
UnknownField: whatever\n";
        let parsed = NarInfo::parse(text).unwrap();
        assert_eq!(parsed.compression, "none");
    }

    #[test]
    fn parse_unknown_deriver_becomes_none() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n\
Deriver: unknown-deriver\n";
        let parsed = NarInfo::parse(text).unwrap();
        assert!(parsed.deriver.is_none());
    }

    #[test]
    fn parse_missing_compression_defaults_bzip2() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n";
        let parsed = NarInfo::parse(text).unwrap();
        assert_eq!(parsed.compression, "bzip2");
    }

    #[test]
    fn fingerprint_format() {
        let parsed = NarInfo::parse(LIBIDN2_NARINFO).unwrap();
        let fp = parsed.fingerprint();
        assert!(fp.starts_with("1;/nix/store/r5sjd57x0r07bwgipryaxqdkx1gglhiy-libidn2-2.3.2;"));
        assert!(fp.contains(";260816;"));
        // References in fingerprint are full paths, comma-separated
        assert!(fp.contains("/nix/store/0z7sqj4pilbqyp45ix5b0mdgn9xlb024-libunistring-0.9.10"));
        assert!(fp.contains(",/nix/store/r5sjd57x0r07bwgipryaxqdkx1gglhiy-libidn2-2.3.2"));
    }

    #[test]
    fn store_path_hash_is_32_chars() {
        let parsed = NarInfo::parse(LIBIDN2_NARINFO).unwrap();
        let hash = parsed.store_path_hash();
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, "r5sjd57x0r07bwgipryaxqdkx1gglhiy");
    }

    #[test]
    fn parse_multiple_signatures() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n\
Sig: key1:AAAA\n\
Sig: key2:BBBB\n";
        let parsed = NarInfo::parse(text).unwrap();
        assert_eq!(parsed.signatures.len(), 2);
        assert_eq!(parsed.signatures[0], "key1:AAAA");
        assert_eq!(parsed.signatures[1], "key2:BBBB");
    }

    #[test]
    fn serialize_with_ca() {
        let text = "\
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test\n\
URL: nar/test.nar\n\
Compression: none\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 100\n\
References: \n\
CA: fixed:r:sha256:0000000000000000000000000000000000000000000000000000\n";
        let parsed = NarInfo::parse(text).unwrap();
        assert_eq!(parsed.ca.as_deref(), Some("fixed:r:sha256:0000000000000000000000000000000000000000000000000000"));
        let serialized = parsed.to_narinfo_string();
        assert_eq!(serialized, text);
    }
}
