//! Directory labels.

/// Directory label of (subject, facet).
///
/// The subject's length as eight big-endian bytes, the subject, then the
/// facet. The length prefix keeps
/// subjects and facets containing `/` from colliding, and the framing is
/// injective, so two distinct pairs never share a label.
pub fn label(subject: &str, facet: &str) -> Vec<u8> {
    let length = subject.len() as u64;
    let mut bytes = Vec::with_capacity(8 + subject.len() + facet.len());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(subject.as_bytes());
    bytes.extend_from_slice(facet.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::label;

    #[test]
    fn framing_is_injective_across_the_separator() {
        assert_ne!(label("a/b", "c"), label("a", "b/c"));
        assert_ne!(label("ab", ""), label("a", "b"));
        assert_eq!(label("s", "f"), label("s", "f"));
    }
}
