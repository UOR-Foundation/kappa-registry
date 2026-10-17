use kappa_types::{ClockMs, Kappa, NamespaceRef, StoreError, TagEntry, TagUpdate};

/// Evaluate a tag mutation against the record held by the backend transaction.
///
/// This evaluates record policy only; the backend must publish the result,
/// indexes, digest and ledger within its storage transaction.
pub fn prepare_tag_update(
    ns: &NamespaceRef,
    name: &str,
    existing: Option<&TagEntry>,
    update: &TagUpdate,
    now: ClockMs,
) -> Result<TagEntry, StoreError> {
    let current_version = existing.map_or(0, |entry| entry.version);
    match update {
        TagUpdate::CompareAndSwap {
            expected_version, ..
        } if *expected_version != current_version => {
            return Err(StoreError::VersionMismatch {
                expected: *expected_version,
                found: current_version,
                current: existing.cloned().map(Box::new),
            });
        }
        TagUpdate::CreateIfAbsent { .. } if existing.is_some() => {
            return Err(StoreError::AlreadyExists(format!("{ns}/{name}")));
        }
        _ => {}
    }
    let version = current_version
        .checked_add(1)
        .ok_or_else(|| StoreError::Conflict("tag version exhausted".into()))?;
    let (kappa, symref) = match update {
        TagUpdate::Set { kappa }
        | TagUpdate::CompareAndSwap { kappa, .. }
        | TagUpdate::CreateIfAbsent { kappa } => (kappa.clone(), None),
        TagUpdate::SetSymref { target } => (Kappa::sha256(b""), Some(target.clone())),
    };
    Ok(TagEntry {
        name: name.to_owned(),
        kappa,
        version,
        created_at_ms: existing.map_or(now.as_i64(), |entry| entry.created_at_ms),
        updated_at_ms: now.as_i64(),
        symref,
    })
}

/// Reject repeated names before backend reads or writes begin.
pub fn validate_tag_batch(updates: &[(String, TagUpdate)]) -> Result<(), StoreError> {
    let mut names = std::collections::HashSet::with_capacity(updates.len());
    for (name, _) in updates {
        if !names.insert(name.as_str()) {
            return Err(StoreError::Conflict(format!(
                "duplicate tag in batch: {name}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_version_cannot_wrap_or_override_a_failed_precondition()
    -> Result<(), Box<dyn std::error::Error>> {
        let ns = NamespaceRef::generate("test", ClockMs::from_raw(0))?;
        let existing = TagEntry {
            name: "HEAD".into(),
            kappa: Kappa::sha256(b"old"),
            version: u64::MAX,
            created_at_ms: 7,
            updated_at_ms: 8,
            symref: None,
        };
        let now = ClockMs::from_raw(9);
        assert!(matches!(
            prepare_tag_update(
                &ns,
                "HEAD",
                Some(&existing),
                &TagUpdate::Set {
                    kappa: Kappa::sha256(b"new")
                },
                now
            ),
            Err(StoreError::Conflict(_))
        ));
        assert!(matches!(
            prepare_tag_update(
                &ns,
                "HEAD",
                Some(&existing),
                &TagUpdate::CompareAndSwap {
                    kappa: Kappa::sha256(b"new"),
                    expected_version: 0
                },
                now
            ),
            Err(StoreError::VersionMismatch {
                expected: 0,
                found: u64::MAX,
                ..
            })
        ));
        assert!(matches!(prepare_tag_update(&ns, "HEAD", Some(&existing),
            &TagUpdate::CreateIfAbsent { kappa: Kappa::sha256(b"new") }, now),
            Err(StoreError::AlreadyExists(message)) if message == format!("{ns}/HEAD")));
        Ok(())
    }

    #[test]
    fn symbolic_replacement_preserves_creation_and_advances_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let ns = NamespaceRef::generate("test", ClockMs::from_raw(0))?;
        let existing = TagEntry {
            name: "HEAD".into(),
            kappa: Kappa::sha256(b"old"),
            version: 42,
            created_at_ms: 7,
            updated_at_ms: 8,
            symref: None,
        };
        let entry = prepare_tag_update(
            &ns,
            "HEAD",
            Some(&existing),
            &TagUpdate::SetSymref {
                target: "refs/heads/main".into(),
            },
            ClockMs::from_raw(9),
        )?;
        assert_eq!(entry.created_at_ms, 7);
        assert_eq!(entry.updated_at_ms, 9);
        assert_eq!(entry.version, 43);
        assert_eq!(entry.symref.as_deref(), Some("refs/heads/main"));
        Ok(())
    }

    #[test]
    fn separated_duplicate_names_are_rejected() {
        let update = TagUpdate::Set {
            kappa: Kappa::sha256(b"content"),
        };
        assert!(matches!(
            validate_tag_batch(&[
                ("a".into(), update.clone()),
                ("b".into(), update.clone()),
                ("a".into(), update),
            ]),
            Err(StoreError::Conflict(_))
        ));
    }
}
