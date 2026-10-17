//! Bounded decoded-content verification before publication. Containerd's
//! writer verifies before commit and its diff processors compose readers.
use kappa_types::{Kappa, StoreError, kappa_streaming::IncrementalHasher};
use std::io::{ErrorKind, Read};

pub fn secondary_content(
    primary: &kappa_types::VerifiedContent,
    axes: impl IntoIterator<Item = kappa_types::Axis>,
) -> Result<Vec<kappa_types::VerifiedContent>, StoreError> {
    let mut content = Vec::new();
    for axis in axes {
        if axis != primary.kappa().axis()
            && !content
                .iter()
                .any(|value: &kappa_types::VerifiedContent| value.kappa().axis() == axis)
        {
            content.push(kappa_types::VerifiedContent::compute(
                axis,
                primary.content(),
            )?);
        }
    }
    Ok(content)
}

pub fn verify_decoded(
    identity: &Kappa,
    expected_size: u64,
    decoded: &mut dyn Read,
) -> Result<(), StoreError> {
    let mut hasher = IncrementalHasher::new(identity.axis());
    let mut remaining = expected_size;
    let mut buffer = [0u8; 16384];
    loop {
        let bound = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| {
                StoreError::CapacityExceeded("decoded read bound exceeds address space".into())
            })?
            .max(1);
        let count = match decoded.read(&mut buffer[..bound]) {
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(StoreError::Io(error)),
        };
        if count == 0 {
            if remaining != 0 {
                return Err(StoreError::Rejected(
                    "decoded content shorter than declared size".into(),
                ));
            }
            break;
        }
        if count as u64 > remaining {
            return Err(StoreError::Rejected(
                "decoded content exceeds declared size".into(),
            ));
        }
        remaining -= count as u64;
        hasher.update(&buffer[..count]);
    }
    if hasher.finalize()? != *identity {
        return Err(StoreError::Rejected(
            "decoded content identity mismatch".into(),
        ));
    }
    Ok(())
}
