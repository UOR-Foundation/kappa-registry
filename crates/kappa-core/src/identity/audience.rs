//! Audience derivation: unlinkable pseudonyms via BLAKE3.
//!
//! Derives a per-audience label so the same subject can be identified
//! differently by different verifiers. Prevents cross-audience
//! correlation without requiring BBS+ or zero-knowledge proofs.

/// Derive an audience-specific label for a subject.
///
/// audience_label = blake3(subject + ":" + audience_id)
///
/// The same (subject, audience_id) pair always produces the same label.
/// Different audience_ids produce different labels. An audience cannot
/// derive another audience's label without knowing the subject.
pub fn derive_audience_label(subject: &str, audience_id: &str) -> String {
    let input = format!("{}:{}", subject, audience_id);
    let hash = blake3::hash(input.as_bytes());
    hex::encode(hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let l1 = derive_audience_label("alice", "hospital-a");
        let l2 = derive_audience_label("alice", "hospital-a");
        assert_eq!(l1, l2);
    }

    #[test]
    fn different_audiences_different_labels() {
        let l1 = derive_audience_label("alice", "hospital-a");
        let l2 = derive_audience_label("alice", "hospital-b");
        assert_ne!(l1, l2);
    }

    #[test]
    fn different_subjects_different_labels() {
        let l1 = derive_audience_label("alice", "audience");
        let l2 = derive_audience_label("bob", "audience");
        assert_ne!(l1, l2);
    }

    #[test]
    fn label_is_64_hex_chars() {
        let l = derive_audience_label("s", "a");
        assert_eq!(l.len(), 64);
        assert!(l.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
