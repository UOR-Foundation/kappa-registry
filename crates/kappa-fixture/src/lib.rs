//! Filesystem scopes for test and benchmark fixtures, shared by every
//! crate that places files: key stores, memory and persistent stores,
//! transaction managers and encryption domains.
//!
//! A [`FixtureRoot`] is one temporary directory owned jointly by every
//! holder. Fixture acquisition hands [`FixtureRoot::owner`] to each resource
//! it places in the scope, so every independently escaping handle keeps the
//! directory alive; the directory is removed with its last holder or by an
//! explicit [`FixtureRoot::close`] that refuses while any other holder
//! remains.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// Error from fixture acquisition: authority construction, scope
/// acquisition, path validation and resource initialization.
pub type SetupError = Box<dyn std::error::Error>;

/// A filesystem scope owned jointly by every resource that retains it.
#[derive(Clone)]
pub struct FixtureRoot(Arc<tempfile::TempDir>);

impl FixtureRoot {
    /// A fresh scope in the system temporary directory.
    pub fn temporary() -> Result<Self, SetupError> {
        Ok(Self(Arc::new(tempfile::tempdir()?)))
    }

    /// A fresh scope inside `parent`, named with `prefix`. Benchmarks place
    /// their stores on the calibrated device this way.
    pub fn within(parent: &Path, prefix: &str) -> Result<Self, SetupError> {
        Ok(Self(Arc::new(
            tempfile::Builder::new().prefix(prefix).tempdir_in(parent)?,
        )))
    }

    pub fn path(&self) -> &Path {
        self.0.path()
    }

    /// Opaque owner for a resource that must keep this scope alive.
    pub fn owner(&self) -> Arc<dyn Send + Sync> {
        self.0.clone()
    }

    /// Resolve `relative` inside this scope. Rooted paths, drive prefixes
    /// and `..` components are rejected, so a resource placed through the
    /// scope cannot be addressed outside it lexically. Symbolic links inside
    /// the scope are the caller's own construction and are not resolved.
    pub fn resolve(&self, relative: &Path) -> Result<PathBuf, SetupError> {
        if relative.as_os_str().is_empty() {
            return Err("fixture path must name a location inside the scope".into());
        }
        for component in relative.components() {
            match component {
                Component::Normal(_) | Component::CurDir => {}
                Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                    return Err(
                        format!("fixture path {} leaves its scope", relative.display()).into(),
                    );
                }
            }
        }
        Ok(self.path().join(relative))
    }

    /// Remove the scope. Refuses while any other holder (a store, reader,
    /// manager, key store, or another clone) still shares it: the directory
    /// is never removed beneath a live resource. A refusal returns the root
    /// inside [`CloseError::InUse`] so the caller can release the holder and
    /// retry.
    pub fn close(self) -> Result<(), CloseError> {
        match Arc::try_unwrap(self.0) {
            Ok(directory) => directory.close().map_err(CloseError::Io),
            Err(shared) => Err(CloseError::InUse(Self(shared))),
        }
    }
}

/// Why [`FixtureRoot::close`] did not remove the scope.
pub enum CloseError {
    /// Another holder still shares the scope; the root is returned intact.
    InUse(FixtureRoot),
    /// Removal failed.
    Io(std::io::Error),
}

impl CloseError {
    /// The root, when closing was refused because it is still shared.
    pub fn into_root(self) -> Option<FixtureRoot> {
        match self {
            Self::InUse(root) => Some(root),
            Self::Io(_) => None,
        }
    }
}

impl std::fmt::Debug for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InUse(root) => write!(
                f,
                "fixture root {} is still shared by another owner",
                root.path().display()
            ),
            Self::Io(error) => write!(f, "fixture root removal: {error}"),
        }
    }
}

impl std::error::Error for CloseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InUse(_) => None,
            Self::Io(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_resolution_rejects_escapes_and_close_waits_for_every_holder() -> Result<(), SetupError>
    {
        let root = FixtureRoot::temporary()?;
        let path = root.path().to_path_buf();
        assert_eq!(root.resolve(Path::new("a/b"))?, path.join("a/b"));
        assert_eq!(root.resolve(Path::new("."))?, path.join("."));
        for escape in ["", "/etc", "../outside", "a/../../b"] {
            assert!(
                root.resolve(Path::new(escape)).is_err(),
                "{escape:?} accepted"
            );
        }
        let holder = root.owner();
        let root = match root.close() {
            Err(CloseError::InUse(root)) => root,
            other => return Err(format!("closed beneath a holder: {other:?}").into()),
        };
        assert!(path.is_dir());
        drop(holder);
        root.close()?;
        assert!(!path.exists());
        Ok(())
    }
}
