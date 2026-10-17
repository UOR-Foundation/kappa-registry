use kappa_types::{StoreError, TagEntry};
use std::collections::HashSet;

/// Resolve symbolic references using raw reads from one retained tag view.
/// The caller owns that view for the entire traversal.
pub fn resolve_tag(
    name: &str,
    mut read_raw: impl FnMut(&str) -> Result<TagEntry, StoreError>,
) -> Result<TagEntry, StoreError> {
    let mut visited = HashSet::new();
    visited.insert(name.to_owned());
    let mut entry = read_raw(name)?;
    let mut hops = 0;
    while let Some(target) = entry.symref.as_deref() {
        if !visited.insert(target.to_owned()) {
            return Err(StoreError::Rejected(format!(
                "symbolic reference cycle from {name}"
            )));
        }
        if hops == 10 {
            return Err(StoreError::CapacityExceeded(format!(
                "symbolic reference exceeds 10 hops from {name}"
            )));
        }
        entry = read_raw(target)?;
        hops += 1;
    }
    name.clone_into(&mut entry.name);
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_types::Kappa;

    fn entry(name: &str, target: Option<String>) -> TagEntry {
        TagEntry {
            name: name.into(),
            kappa: Kappa::sha256(name.as_bytes()),
            version: 1,
            created_at_ms: 1,
            updated_at_ms: 1,
            symref: target,
        }
    }

    #[test]
    fn cycle_is_rejected_before_rereading_a_record() {
        let mut reads = Vec::new();
        let result = resolve_tag("a", |name| {
            reads.push(name.to_owned());
            Ok(entry(
                name,
                Some(if name == "a" { "b" } else { "a" }.into()),
            ))
        });
        assert!(matches!(result, Err(StoreError::Rejected(_))));
        assert_eq!(reads, ["a", "b"]);
    }

    #[test]
    fn ten_hops_resolve_and_preserve_requested_name() -> Result<(), StoreError> {
        let resolved = resolve_tag("0", |name| {
            let index: usize = name
                .parse()
                .map_err(|error| StoreError::Rejected(format!("numeric fixture: {error}")))?;
            Ok(entry(name, (index < 10).then(|| (index + 1).to_string())))
        })?;
        assert_eq!(resolved.name, "0");
        assert_eq!(resolved.kappa, Kappa::sha256(b"10"));
        assert!(resolved.symref.is_none());
        Ok(())
    }

    #[test]
    fn depth_exhaustion_does_not_read_an_eleventh_target() {
        let mut reads = 0;
        let result = resolve_tag("0", |name| {
            reads += 1;
            let index: usize = name
                .parse()
                .map_err(|error| StoreError::Rejected(format!("numeric fixture: {error}")))?;
            Ok(entry(name, Some((index + 1).to_string())))
        });
        assert!(matches!(result, Err(StoreError::CapacityExceeded(_))));
        assert_eq!(reads, 11);
    }

    #[test]
    fn read_failure_is_preserved() {
        let result = resolve_tag("missing", |_| {
            Err(StoreError::Io(std::io::Error::from_raw_os_error(5)))
        });
        assert!(matches!(result, Err(StoreError::Io(error)) if error.raw_os_error() == Some(5)));
    }
}
