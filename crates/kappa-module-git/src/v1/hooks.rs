use std::io::Write;
use std::time::Duration;

use kappa_store::axis::Axis;
use kappa_store::error::StoreError;
use kappa_store::namespace::NamespaceRef;
use kappa_store::tag::TagUpdate;
use kappa_store::traits::blob::BlobStore;
use kappa_store::traits::tag::TagStore;
use kappa_store::{ExecutionWrites, VerifiedContent};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HookError {
    #[error("hook rejected: {0}")]
    Rejected(String),
    #[error("hook timed out after {0} seconds")]
    Timeout(u64),
    #[error("hook not found: {0}")]
    NotFound(String),
    #[error("hook execution failed: {0}")]
    ExecutionFailed(String),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
}

#[derive(Debug, Clone)]
pub struct RefUpdate {
    pub old_oid: String,
    pub new_oid: String,
    pub ref_name: String,
}

/// Run a pre-receive hook if one exists in the namespace.
pub fn run_pre_receive<S: TagStore + BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    updates: &[RefUpdate],
    timeout_secs: u64,
) -> Result<(), HookError> {
    let hook_script = match load_hook(store, namespace, "pre-receive") {
        Ok(script) => script,
        Err(HookError::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
    };

    let script_path = write_temp_script("pre-receive", &hook_script)?;
    let stdin_data = build_stdin(updates);
    let result = execute_hook(&script_path, &stdin_data, namespace, timeout_secs);
    let _ = std::fs::remove_file(&script_path);
    result
}

/// Run post-receive hook asynchronously in a background thread.
pub fn spawn_post_receive<S: TagStore + BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    updates: &[RefUpdate],
    timeout_secs: u64,
) {
    let hook_script = match load_hook(store, namespace, "post-receive") {
        Ok(script) => script,
        Err(_) => return,
    };

    let ns = namespace.clone();
    let updates = updates.to_vec();
    std::thread::spawn(move || {
        let script_path = match write_temp_script("post-receive", &hook_script) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(ns = %ns.display_name(), error = %e, "post-receive script write failed");
                return;
            }
        };
        let stdin_data = build_stdin(&updates);
        match execute_hook(&script_path, &stdin_data, &ns, timeout_secs) {
            Ok(()) => {}
            Err(HookError::Rejected(msg)) => {
                tracing::warn!(ns = %ns.display_name(), "post-receive hook rejected: {}", msg);
            }
            Err(HookError::Timeout(secs)) => {
                tracing::warn!(ns = %ns.display_name(), "post-receive hook timed out after {}s", secs);
            }
            Err(e) => {
                tracing::warn!(ns = %ns.display_name(), error = %e, "post-receive hook error");
            }
        }
        let _ = std::fs::remove_file(&script_path);
    });
}

/// Store a hook script in the execution's repository. The script is a
/// record the execution holds in full; it and the tag naming it publish
/// together.
pub fn set_hook<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    hook_name: &str,
    script: &[u8],
) -> Result<(), HookError> {
    let content = VerifiedContent::compute(Axis::Sha256, script).map_err(StoreError::from)?;
    let kappa = content.kappa().clone();
    execution.blob_put(&content)?;
    execution.tag_put(&format!("_hooks/{hook_name}"), &TagUpdate::Set { kappa })?;
    Ok(())
}

/// Delete a hook from the execution's repository. An absent hook is
/// `NotFound` and leaves the execution usable.
pub fn delete_hook<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    hook_name: &str,
) -> Result<(), HookError> {
    let tag_name = format!("_hooks/{hook_name}");
    if execution.tag_get_raw(&tag_name)?.is_none() {
        return Err(HookError::NotFound(hook_name.to_string()));
    }
    execution.tag_delete(&tag_name)?;
    Ok(())
}

fn load_hook<S: TagStore + BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    hook_name: &str,
) -> Result<Vec<u8>, HookError> {
    let tag_name = format!("_hooks/{}", hook_name);
    let entry = store.tag_get(namespace, &tag_name).map_err(|e| match e {
        StoreError::NotFound(_) => HookError::NotFound(hook_name.to_string()),
        other => HookError::Store(other),
    })?;
    store
        .blob_get_in(namespace, &entry.kappa)
        .map_err(HookError::Store)
}

fn write_temp_script(name: &str, script: &[u8]) -> Result<std::path::PathBuf, HookError> {
    let tmp_dir = std::env::temp_dir().join("kappa-hooks");
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| HookError::ExecutionFailed(format!("temp dir creation: {e}")))?;
    let script_path = tmp_dir.join(format!("{}-{}", name, uuid::Uuid::new_v4()));
    std::fs::write(&script_path, script)
        .map_err(|e| HookError::ExecutionFailed(format!("script write: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| HookError::ExecutionFailed(format!("chmod: {e}")))?;
    }
    Ok(script_path)
}

fn build_stdin(updates: &[RefUpdate]) -> Vec<u8> {
    let mut buf = Vec::new();
    for update in updates {
        writeln!(
            buf,
            "{} {} {}",
            update.old_oid, update.new_oid, update.ref_name
        )
        .expect("Vec write is infallible");
    }
    buf
}

fn execute_hook(
    script_path: &std::path::Path,
    stdin_data: &[u8],
    namespace: &NamespaceRef,
    timeout_secs: u64,
) -> Result<(), HookError> {
    let mut child = std::process::Command::new(script_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("GIT_NAMESPACE", namespace.display_name())
        .spawn()
        .map_err(|e| HookError::ExecutionFailed(e.to_string()))?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(stdin_data)
            .map_err(|e| HookError::ExecutionFailed(format!("stdin write: {e}")))?;
    }
    drop(child.stdin.take());

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                let stderr = child
                    .stderr
                    .take()
                    .map(|mut s| {
                        let mut buf = String::new();
                        use std::io::Read;
                        if let Err(e) = s.read_to_string(&mut buf) {
                            tracing::warn!(error = %e, "failed to read hook stderr");
                        }
                        buf
                    })
                    .unwrap_or_default();
                return Err(HookError::Rejected(if stderr.is_empty() {
                    format!("hook exited with status {}", status)
                } else {
                    stderr
                }));
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    if let Err(e) = child.kill() {
                        tracing::warn!(error = %e, "failed to kill timed-out hook");
                    }
                    return Err(HookError::Timeout(timeout_secs));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(HookError::ExecutionFailed(e.to_string())),
        }
    }
}
