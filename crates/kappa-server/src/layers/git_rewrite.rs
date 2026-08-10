//! Git path rewrite: transform `.git/` URLs to `/_git/` internal routing prefix.
//!
//! Git clients send paths like `/myrepo.git/info/refs`. Topcoat's path
//! syntax does not support `{param}.git` (mixed param + literal in one
//! segment). This rewrite layer transforms the path before routing:
//!
//!   /myrepo.git/info/refs       -> /_git/myrepo/info/refs
//!   /org/team/repo.git/git-upload-pack -> /_git/org/team/repo/git-upload-pack
//!   /myrepo.git/info/lfs/objects/batch -> /_git/myrepo/info/lfs/objects/batch
//!
//! Non-git paths pass through unchanged. The `/_git/` prefix is an
//! internal routing namespace that never appears in user-facing URLs.
//!
//! Same pattern as s3_vhost::rewrite_uri.

/// Rewrite a git `.git/` path to `/_git/` internal routing prefix.
///
/// Returns Some(new_path_and_query) if the path contains `.git/`,
/// None if it's not a git path (pass through unchanged).
pub fn rewrite_git_path(uri: &http::Uri) -> Option<http::Uri> {
    let path = uri.path();

    // Find .git/ in the path
    let git_pos = path.find(".git/")?;

    // Extract repo (everything before .git) and sub-path (everything after .git/)
    let repo = &path[1..git_pos]; // skip leading /
    let sub_path = &path[git_pos + 5..]; // skip ".git/"

    // Normalize: git-upload-pack and git-receive-pack have hyphens
    // which are fine as static path segments in topcoat.
    // But the route registration uses underscores to avoid issues.
    // Rewrite the sub-path hyphens for the two known endpoints:
    let sub_path = sub_path
        .replace("git-upload-pack", "git_upload_pack")
        .replace("git-receive-pack", "git_receive_pack");

    // Build new path: /_git/{repo}/{sub_path}
    let new_path = if repo.is_empty() {
        format!("/_git/{}", sub_path)
    } else {
        format!("/_git/{}/{}", repo, sub_path)
    };

    // Preserve query string
    let new_path_and_query = match uri.query() {
        Some(q) => format!("{}?{}", new_path, q),
        None => new_path,
    };

    http::Uri::try_from(&new_path_and_query).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(path: &str) -> Option<String> {
        let uri: http::Uri = path.parse().unwrap();
        rewrite_git_path(&uri).map(|u| u.to_string())
    }

    #[test]
    fn info_refs() {
        assert_eq!(
            rewrite("/myrepo.git/info/refs?service=git-upload-pack"),
            Some("/_git/myrepo/info/refs?service=git-upload-pack".into()),
        );
    }

    #[test]
    fn upload_pack() {
        assert_eq!(
            rewrite("/myrepo.git/git-upload-pack"),
            Some("/_git/myrepo/git_upload_pack".into()),
        );
    }

    #[test]
    fn receive_pack() {
        assert_eq!(
            rewrite("/myrepo.git/git-receive-pack"),
            Some("/_git/myrepo/git_receive_pack".into()),
        );
    }

    #[test]
    fn lfs_batch() {
        assert_eq!(
            rewrite("/myrepo.git/info/lfs/objects/batch"),
            Some("/_git/myrepo/info/lfs/objects/batch".into()),
        );
    }

    #[test]
    fn nested_repo() {
        assert_eq!(
            rewrite("/org/team/myrepo.git/info/refs"),
            Some("/_git/org/team/myrepo/info/refs".into()),
        );
    }

    #[test]
    fn non_git_path_passes_through() {
        assert_eq!(rewrite("/mybucket/mykey"), None);
        assert_eq!(rewrite("/v2/myrepo/manifests/latest"), None);
    }

    #[test]
    fn bare_git_no_subpath() {
        // /myrepo.git without trailing / -- no .git/ match
        assert_eq!(rewrite("/myrepo.git"), None);
    }
}
