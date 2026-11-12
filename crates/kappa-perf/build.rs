//! Capture the toolchain, code-generation settings and source revision a
//! benchmark binary was built with. A measurement is attributable only to
//! the compiler, flags and source that produced the measured code
//! (KAPPA-PERF-001 section 2.4), which are known at build time and not at
//! run time.
//!
//! The source revision is `KAPPA_PERF_SOURCE_REVISION` when set (a Nix or
//! CI build passes the revision it is building, where no checkout exists
//! or git is not on the path), else `git rev-parse HEAD` with `-dirty`
//! when `git status --porcelain` reports a change, else empty when the
//! manifest is not inside a checkout. The build reruns when HEAD, the ref
//! HEAD resolves to, or the index changes; an unstaged edit changes none
//! of them, so `-dirty` reflects the tree at the last build that ran.
//!
//! The standard library source is `KAPPA_STD_SOURCE` as the build
//! environment states it (the flake's shells name the forked library's
//! revision, which `rustc --version` does not), else empty: the toolchain's
//! own library.

use std::path::{Path, PathBuf};
use std::process::Command;

fn git(manifest_dir: &Path, args: &[&str]) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let output = match Command::new("git")
        .args(args)
        .current_dir(manifest_dir)
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if output.status.success() {
        return Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("not a git repository") {
        return Ok(None);
    }
    Err(format!(
        "git {} exited with {}: {stderr}",
        args.join(" "),
        output.status
    )
    .into())
}

/// The revision and the files whose change invalidates it.
fn source_revision(
    manifest_dir: &Path,
) -> Result<(String, Vec<PathBuf>), Box<dyn std::error::Error>> {
    let Some(head) = git(manifest_dir, &["rev-parse", "HEAD"])? else {
        return Ok((String::new(), Vec::new()));
    };
    let Some(status) = git(manifest_dir, &["status", "--porcelain"])? else {
        return Ok((String::new(), Vec::new()));
    };
    let revision = if status.is_empty() {
        head
    } else {
        format!("{head}-dirty")
    };
    let mut watched = Vec::new();
    if let Some(git_dir) = git(manifest_dir, &["rev-parse", "--absolute-git-dir"])? {
        let git_dir = PathBuf::from(git_dir);
        watched.push(git_dir.join("HEAD"));
        watched.push(git_dir.join("index"));
        if let Some(reference) = git(manifest_dir, &["symbolic-ref", "-q", "HEAD"])? {
            watched.push(git_dir.join(reference));
            watched.push(git_dir.join("packed-refs"));
        }
    }
    Ok((revision, watched))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for var in [
        "RUSTC",
        "CARGO_ENCODED_RUSTFLAGS",
        "PROFILE",
        "OPT_LEVEL",
        "TARGET",
        "KAPPA_PERF_SOURCE_REVISION",
        "KAPPA_STD_SOURCE",
    ] {
        println!("cargo::rerun-if-env-changed={var}");
    }

    let rustc = std::env::var("RUSTC")?;
    let output = Command::new(&rustc).arg("--version").output()?;
    if !output.status.success() {
        return Err(format!("{rustc} --version exited with {}", output.status).into());
    }
    let version = String::from_utf8(output.stdout)?;
    println!(
        "cargo::rustc-env=KAPPA_PERF_RUSTC_VERSION={}",
        version.trim()
    );

    // CARGO_ENCODED_RUSTFLAGS separates flags with 0x1f.
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    println!(
        "cargo::rustc-env=KAPPA_PERF_RUSTFLAGS={}",
        flags
            .split('\x1f')
            .filter(|flag| !flag.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!(
        "cargo::rustc-env=KAPPA_PERF_PROFILE={}",
        std::env::var("PROFILE")?
    );
    println!(
        "cargo::rustc-env=KAPPA_PERF_OPT_LEVEL={}",
        std::env::var("OPT_LEVEL")?
    );
    println!(
        "cargo::rustc-env=KAPPA_PERF_TARGET={}",
        std::env::var("TARGET")?
    );
    let std_source = match std::env::var("KAPPA_STD_SOURCE") {
        Ok(source) => source,
        Err(std::env::VarError::NotPresent) => String::new(),
        Err(error) => return Err(format!("KAPPA_STD_SOURCE: {error}").into()),
    };
    println!("cargo::rustc-env=KAPPA_PERF_STD_SOURCE={std_source}");

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let revision = match std::env::var("KAPPA_PERF_SOURCE_REVISION") {
        Ok(given) if !given.is_empty() => given,
        _ => {
            let (revision, watched) = source_revision(&manifest_dir)?;
            for path in watched {
                println!("cargo::rerun-if-changed={}", path.display());
            }
            revision
        }
    };
    println!("cargo::rustc-env=KAPPA_PERF_SOURCE_REVISION={revision}");
    Ok(())
}
