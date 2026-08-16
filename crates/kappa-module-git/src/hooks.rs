//! Server-side Git hooks: pre-receive, post-receive, update.
//!
//! Hook scripts are stored as blobs tagged under _hooks/{hook_name} in
//! the namespace. Execution is sandboxed via std::process::Command with
//! a configurable timeout.
//!
//! pre-receive stdin format (one line per ref update):
//!   {old_oid} {new_oid} {ref_name}\n
//!
//! Exit 0 = accept. Non-zero = reject with stderr as the error message.

use std::io::Write;
use std::time::Duration;

use kappa_core::store::KappaStore;
use kappa_core::types::NamespaceRef;

/// Errors from hook execution.
#[derive(Debug, thiserror::Error)]
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
    Store(#[from] kappa_core::types::StoreError),
}

/// A single ref update for hook stdin.
#[derive(Debug, Clone)]
pub struct RefUpdate {
    pub old_oid: String,
    pub new_oid: String,
    pub ref_name: String,
}

/// Run a pre-receive hook if one exists in the namespace.
///
/// Returns Ok(()) if no hook exists or if the hook exits 0.
/// Returns Err(HookError::Rejected) if the hook exits non-zero.
/// Returns Err(HookError::Timeout) if the hook exceeds timeout_secs.
pub fn run_pre_receive(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    updates: &[RefUpdate],
    timeout_secs: u64,
) -> Result<(), HookError> {
    let hook_script = match load_hook(store, namespace, "pre-receive") {
        Ok(script) => script,
        Err(HookError::NotFound(_)) => return Ok(()), // no hook = accept
        Err(e) => return Err(e),
    };

    // Write script to a temp file
    let tmp_dir = std::env::temp_dir().join("kappa-hooks");
    let _ = std::fs::create_dir_all(&tmp_dir);
    let script_path = tmp_dir.join(format!("pre-receive-{}", uuid::Uuid::new_v4()));

    std::fs::write(&script_path, &hook_script)
        .map_err(|e| HookError::ExecutionFailed(e.to_string()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o700));
    }

    // Build stdin: old_oid new_oid ref_name\n per update
    let mut stdin_data = Vec::new();
    for update in updates {
        writeln!(stdin_data, "{} {} {}", update.old_oid, update.new_oid, update.ref_name)
            .map_err(|e| HookError::ExecutionFailed(e.to_string()))?;
    }

    // Execute with timeout
    let mut child = std::process::Command::new(&script_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("GIT_NAMESPACE", namespace.as_str())
        .spawn()
        .map_err(|e| HookError::ExecutionFailed(e.to_string()))?;

    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(&stdin_data);
    }
    drop(child.stdin.take());

    let result = match child.wait_timeout(Duration::from_secs(timeout_secs)) {
        Ok(Some(status)) => {
            if status.success() {
                Ok(())
            } else {
                let stderr = child.stderr.take()
                    .map(|mut s| {
                        let mut buf = String::new();
                        use std::io::Read;
                        let _ = s.read_to_string(&mut buf);
                        buf
                    })
                    .unwrap_or_default();
                Err(HookError::Rejected(if stderr.is_empty() {
                    format!("hook exited with status {}", status)
                } else {
                    stderr
                }))
            }
        }
        Ok(None) => {
            let _ = child.kill();
            Err(HookError::Timeout(timeout_secs))
        }
        Err(e) => Err(HookError::ExecutionFailed(e.to_string())),
    };

    let _ = std::fs::remove_file(&script_path);
    result
}

/// Run a post-receive hook asynchronously (fire-and-forget).
///
/// Returns immediately. The hook runs in a background thread.
/// Errors are logged, not returned.
pub fn spawn_post_receive(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    updates: &[RefUpdate],
    timeout_secs: u64,
) {
    let hook_script = match load_hook(store, namespace, "post-receive") {
        Ok(script) => script,
        Err(_) => return, // no hook = nothing to do
    };

    let ns = namespace.clone();
    let updates = updates.to_vec();
    std::thread::spawn(move || {
        let tmp_dir = std::env::temp_dir().join("kappa-hooks");
        let _ = std::fs::create_dir_all(&tmp_dir);
        let script_path = tmp_dir.join(format!("post-receive-{}", uuid::Uuid::new_v4()));
        if std::fs::write(&script_path, &hook_script).is_err() { return; }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o700));
        }

        let mut stdin_data = Vec::new();
        for update in &updates {
            let _ = writeln!(stdin_data, "{} {} {}", update.old_oid, update.new_oid, update.ref_name);
        }

        let mut child = match std::process::Command::new(&script_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .env("GIT_NAMESPACE", ns.as_str())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => { let _ = std::fs::remove_file(&script_path); return; }
        };

        if let Some(ref mut stdin) = child.stdin {
            let _ = stdin.write_all(&stdin_data);
        }
        drop(child.stdin.take());

        match child.wait_timeout(Duration::from_secs(timeout_secs)) {
            Ok(Some(status)) => {
                if !status.success() {
                    tracing::warn!(ns = %ns, "post-receive hook failed: {}", status);
                }
            }
            Ok(None) => {
                let _ = child.kill();
                tracing::warn!(ns = %ns, "post-receive hook timed out");
            }
            Err(e) => {
                tracing::warn!(ns = %ns, "post-receive hook error: {}", e);
            }
        }
        let _ = std::fs::remove_file(&script_path);
    });
}

/// Load a hook script from the store.
fn load_hook(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    hook_name: &str,
) -> Result<Vec<u8>, HookError> {
    let tag_name = format!("_hooks/{}", hook_name);
    let entry = store.tag_get(namespace, &tag_name)
        .map_err(|_| HookError::NotFound(hook_name.to_string()))?;
    store.blob_get(&entry.kappa)
        .map_err(|e| HookError::Store(e))
}

/// Store a hook script in the namespace.
pub fn set_hook(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    hook_name: &str,
    script: &[u8],
) -> Result<(), HookError> {
    let kappa = kappa_core::kappa::kappa_from_bytes(script);
    store.ingest_verified(&kappa, script)
        .map_err(HookError::Store)?;
    let tag_name = format!("_hooks/{}", hook_name);
    store.tag_set(namespace, &tag_name, &kappa)
        .map_err(HookError::Store)?;
    Ok(())
}

/// Delete a hook from the namespace.
pub fn delete_hook(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    hook_name: &str,
) -> Result<(), HookError> {
    let tag_name = format!("_hooks/{}", hook_name);
    store.tag_delete(namespace, &tag_name)
        .map_err(HookError::Store)?;
    Ok(())
}

/// Trait extension for wait_timeout on Child (std doesn't have it natively).
trait WaitTimeout {
    fn wait_timeout(&mut self, dur: Duration) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl WaitTimeout for std::process::Child {
    fn wait_timeout(&mut self, dur: Duration) -> std::io::Result<Option<std::process::ExitStatus>> {
        let start = std::time::Instant::now();
        loop {
            match self.try_wait()? {
                Some(status) => return Ok(Some(status)),
                None => {
                    if start.elapsed() >= dur {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}
