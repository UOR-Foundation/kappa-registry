//! Git end-to-end integration tests.
//!
//! These tests run real `git` CLI commands against a live kappa-server.
//! They prove the Git smart HTTP protocol works end-to-end:
//! - git clone
//! - git push
//! - git fetch (incremental)
//! - ref advertisement parsing
//! - pack generation and ingest
//!
//! Requires `git` on PATH (provided by the Nix devshell).

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

use std::process::Command;

/// Run a git command, return (success, stdout, stderr).
fn git(args: &[&str], dir: &std::path::Path) -> (bool, String, String) {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .output()
        .expect("failed to run git");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Initialize a local git repo with one commit containing a file.
fn init_repo_with_commit(dir: &std::path::Path, filename: &str, content: &str) {
    let (ok, _, err) = git(&["init"], dir);
    assert!(ok, "git init failed: {err}");
    let (ok, _, err) = git(&["checkout", "-b", "main"], dir);
    assert!(ok, "git checkout -b main failed: {err}");
    std::fs::write(dir.join(filename), content).unwrap();
    let (ok, _, err) = git(&["add", filename], dir);
    assert!(ok, "git add failed: {err}");
    let (ok, _, err) = git(&["commit", "-m", "initial commit"], dir);
    assert!(ok, "git commit failed: {err}");
}

#[test]
fn git_push_then_clone_roundtrip() {
    let (guard, base, _tmp) = start_server();
    let repo_url = format!("{}/myrepo.git", base);

    // Create a local repo with content
    let src_dir = tempfile::tempdir().unwrap();
    init_repo_with_commit(src_dir.path(), "hello.txt", "hello from kappa-registry\n");

    // Add remote and push
    let (ok, _, err) = git(&["remote", "add", "origin", &repo_url], src_dir.path());
    assert!(ok, "git remote add failed: {err}");
    let (ok, stdout, err) = git(&["push", "-u", "origin", "main"], src_dir.path());
    assert!(
        ok,
        "git push failed:\nstdout: {stdout}\nstderr: {err}"
    );

    // Clone into a new directory
    let clone_dir = tempfile::tempdir().unwrap();
    let clone_path = clone_dir.path().join("cloned");
    let (ok, stdout, err) = git(
        &["clone", &repo_url, clone_path.to_str().unwrap()],
        clone_dir.path(),
    );
    assert!(
        ok,
        "git clone failed:\nstdout: {stdout}\nstderr: {err}"
    );

    // Verify the cloned content matches
    let cloned_content = std::fs::read_to_string(clone_path.join("hello.txt")).unwrap();
    assert_eq!(
        cloned_content, "hello from kappa-registry\n",
        "cloned file content mismatch"
    );

    // Verify the commit history
    let (ok, log_out, err) = git(&["log", "--oneline"], &clone_path);
    assert!(ok, "git log failed: {err}");
    assert!(
        log_out.contains("initial commit"),
        "commit message not found in log: {log_out}"
    );

    drop(guard);
}

#[test]
fn git_push_multiple_commits_then_fetch() {
    let (guard, base, _tmp) = start_server();
    let repo_url = format!("{}/fetchtest.git", base);

    // Create repo with first commit and push
    let src_dir = tempfile::tempdir().unwrap();
    init_repo_with_commit(src_dir.path(), "file1.txt", "first file\n");
    let (ok, _, err) = git(&["remote", "add", "origin", &repo_url], src_dir.path());
    assert!(ok, "remote add: {err}");
    let (ok, _, err) = git(&["push", "-u", "origin", "main"], src_dir.path());
    assert!(ok, "first push: {err}");

    // Clone
    let clone_dir = tempfile::tempdir().unwrap();
    let clone_path = clone_dir.path().join("cloned");
    let (ok, _, err) = git(
        &["clone", &repo_url, clone_path.to_str().unwrap()],
        clone_dir.path(),
    );
    assert!(ok, "clone: {err}");

    // Add second commit to source and push
    std::fs::write(src_dir.path().join("file2.txt"), "second file\n").unwrap();
    let (ok, _, err) = git(&["add", "file2.txt"], src_dir.path());
    assert!(ok, "add file2: {err}");
    let (ok, _, err) = git(&["commit", "-m", "second commit"], src_dir.path());
    assert!(ok, "second commit: {err}");
    let (ok, _, err) = git(&["push"], src_dir.path());
    assert!(ok, "second push: {err}");

    // Fetch from clone and verify
    let (ok, _, err) = git(&["fetch", "origin"], &clone_path);
    assert!(ok, "fetch: {err}");
    let (ok, _, err) = git(&["merge", "origin/main"], &clone_path);
    assert!(ok, "merge: {err}");

    assert!(
        clone_path.join("file2.txt").exists(),
        "file2.txt should exist after fetch+merge"
    );
    let content = std::fs::read_to_string(clone_path.join("file2.txt")).unwrap();
    assert_eq!(content, "second file\n");

    drop(guard);
}

#[test]
fn git_ref_advertisement_parseable() {
    let (guard, base, _tmp) = start_server();
    let repo_url = format!("{}/reftest.git", base);

    // Push a repo so refs exist
    let src_dir = tempfile::tempdir().unwrap();
    init_repo_with_commit(src_dir.path(), "test.txt", "ref test\n");
    let (ok, _, err) = git(&["remote", "add", "origin", &repo_url], src_dir.path());
    assert!(ok, "remote add: {err}");
    let (ok, _, err) = git(&["push", "-u", "origin", "main"], src_dir.path());
    assert!(ok, "push: {err}");

    // Fetch info/refs via HTTP and verify it's parseable
    let c = client();
    let resp = c
        .get(format!(
            "{}/reftest.git/info/refs?service=git-upload-pack",
            base
        ))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "info/refs should return 200");
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        ct.contains("git-upload-pack-advertisement"),
        "wrong content-type: {ct}"
    );
    let body = resp.text().unwrap();
    assert!(
        body.contains("refs/heads/main"),
        "ref advertisement should contain refs/heads/main: {body}"
    );

    drop(guard);
}
