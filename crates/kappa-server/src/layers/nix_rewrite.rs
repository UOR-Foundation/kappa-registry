//! Nix path rewrite: transform external Nix binary cache URLs into
//! internal routing paths that topcoat can dispatch.
//!
//! Topcoat's route syntax does not support mixed parameter + literal
//! in one segment (e.g. `{hash}.narinfo` is invalid). The rewrite
//! layer normalizes external paths into segment-clean internal paths
//! BEFORE routing, same pattern as git_rewrite.rs.
//!
//! External -> Internal path mapping (SSOT for route registration):
//!
//!   /nix/nix-cache-info             -> /_nix/nix-cache-info
//!   /nix/{hash}.narinfo             -> /_nix/narinfo/{hash}
//!   /nix/nar/{filehash}.nar.zst     -> /_nix/nar/{filehash}.nar.zst
//!   /nix/nar/{filehash}.nar.xz      -> /_nix/nar/{filehash}.nar.xz
//!   /nix/nar/{filehash}.nar         -> /_nix/nar/{filehash}.nar
//!
//! Route registration in main.rs MUST use the internal paths from
//! the right column. A route registered against the external path
//! format will panic at startup (topcoat rejects `{param}.suffix`).

/// Rewrite a /nix/ path to /_nix/ internal routing prefix, normalizing
/// path structure for topcoat route compatibility.
///
/// Returns Some(new_uri) if the path starts with /nix/,
/// None if it is not a Nix path (pass through unchanged).
pub fn rewrite_nix_path(uri: &http::Uri) -> Option<http::Uri> {
    let path = uri.path();
    if !path.starts_with("/nix/") {
        return None;
    }
    let rest = &path[5..]; // strip "/nix/"

    // /{hash}.narinfo -> /narinfo/{hash}
    // The hash is always 32 nix-base32 characters. Strip the .narinfo
    // suffix and move it to a path prefix so topcoat sees /_nix/narinfo/{hash}.
    let new_path = if let Some(hash) = rest.strip_suffix(".narinfo") {
        format!("/_nix/narinfo/{}", hash)
    } else {
        // All other paths (nix-cache-info, nar/*) pass through with prefix swap
        format!("/_nix/{}", rest)
    };

    let pq = match uri.query() {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    };
    http::Uri::try_from(&pq).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_info() {
        let uri: http::Uri = "/nix/nix-cache-info".parse().unwrap();
        assert_eq!(
            rewrite_nix_path(&uri).unwrap().path(),
            "/_nix/nix-cache-info"
        );
    }

    #[test]
    fn narinfo_rewritten_to_segment() {
        let uri: http::Uri = "/nix/r5sjd57x0r07bwgipryaxqdkx1gglhiy.narinfo"
            .parse()
            .unwrap();
        assert_eq!(
            rewrite_nix_path(&uri).unwrap().path(),
            "/_nix/narinfo/r5sjd57x0r07bwgipryaxqdkx1gglhiy"
        );
    }

    #[test]
    fn nar_file_zstd() {
        let uri: http::Uri = "/nix/nar/abc123.nar.zst".parse().unwrap();
        assert_eq!(
            rewrite_nix_path(&uri).unwrap().path(),
            "/_nix/nar/abc123.nar.zst"
        );
    }

    #[test]
    fn nar_file_xz() {
        let uri: http::Uri = "/nix/nar/abc123.nar.xz".parse().unwrap();
        assert_eq!(
            rewrite_nix_path(&uri).unwrap().path(),
            "/_nix/nar/abc123.nar.xz"
        );
    }

    #[test]
    fn nar_file_uncompressed() {
        let uri: http::Uri = "/nix/nar/abc123.nar".parse().unwrap();
        assert_eq!(
            rewrite_nix_path(&uri).unwrap().path(),
            "/_nix/nar/abc123.nar"
        );
    }

    #[test]
    fn non_nix_passthrough() {
        let uri: http::Uri = "/v2/test/blobs/sha256:abc".parse().unwrap();
        assert!(rewrite_nix_path(&uri).is_none());
    }

    #[test]
    fn preserves_query() {
        let uri: http::Uri = "/nix/nar/abc.nar?hash=xyz".parse().unwrap();
        let rewritten = rewrite_nix_path(&uri).unwrap();
        assert_eq!(rewritten.path(), "/_nix/nar/abc.nar");
        assert_eq!(rewritten.query(), Some("hash=xyz"));
    }

    #[test]
    fn bare_nix_no_trailing_slash() {
        let uri: http::Uri = "/nix".parse().unwrap();
        assert!(rewrite_nix_path(&uri).is_none());
    }

    #[test]
    fn nix_root_with_slash() {
        let uri: http::Uri = "/nix/".parse().unwrap();
        let rewritten = rewrite_nix_path(&uri).unwrap();
        assert_eq!(rewritten.path(), "/_nix/");
    }

    #[test]
    fn oci_path_not_rewritten() {
        let uri: http::Uri = "/v2/myrepo/manifests/latest".parse().unwrap();
        assert!(rewrite_nix_path(&uri).is_none());
    }

    #[test]
    fn s3_path_not_rewritten() {
        let uri: http::Uri = "/mybucket/mykey".parse().unwrap();
        assert!(rewrite_nix_path(&uri).is_none());
    }

    #[test]
    fn git_path_not_rewritten() {
        let uri: http::Uri = "/myrepo.git/info/refs".parse().unwrap();
        assert!(rewrite_nix_path(&uri).is_none());
    }

    #[test]
    fn narinfo_query_preserved() {
        let uri: http::Uri = "/nix/abc123.narinfo?foo=bar".parse().unwrap();
        let rewritten = rewrite_nix_path(&uri).unwrap();
        assert_eq!(rewritten.path(), "/_nix/narinfo/abc123");
        assert_eq!(rewritten.query(), Some("foo=bar"));
    }
}
