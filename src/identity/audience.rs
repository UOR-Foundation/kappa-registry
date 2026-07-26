//! Audience-scoped pseudonym derivation.
//!
//! A subject can have different identifiers for different audiences.
//! The derivation is deterministic, unlinkable across audiences,
//! verifiable, and non-reversible without the derivation key.
//!
//! The audience label goes into the AKD tree key alongside subject
//! and facet, so two audience-scoped assertions on the same
//! subject+facet do not collide.

pub const AUDIENCE_CONTEXT: &str = "kappa-identity/audience-pseudonym/v1";

/// Derive an audience-scoped pseudonym label.
///
/// Uses blake3 key derivation with a fixed context string to produce
/// a 32-byte label that is:
/// - Deterministic: same inputs always produce same pseudonym
/// - Unlinkable: different audiences produce different pseudonyms
/// - Non-reversible: cannot recover subject from pseudonym without seed
///
/// Input is length-prefixed to prevent injection:
/// `("ab","c")` and `("a","bc")` must not collide.
///
/// Format: seed + u16(subject.len) BE + subject + u16(audience.len) BE + audience
pub fn derive_audience_label(seed: &[u8; 32], subject: &str, audience: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 4 + subject.len() + audience.len());
    input.extend_from_slice(seed);
    input.extend_from_slice(&(subject.len() as u16).to_be_bytes());
    input.extend_from_slice(subject.as_bytes());
    input.extend_from_slice(&(audience.len() as u16).to_be_bytes());
    input.extend_from_slice(audience.as_bytes());
    blake3::derive_key(AUDIENCE_CONTEXT, &input)
}

/// Format an audience-scoped AKD label from subject, facet, and audience.
///
/// The label is: `audience_pseudonym_hex / facet`
/// This ensures two assertions on the same subject+facet for different
/// audiences occupy different positions in the AKD tree.
pub fn audience_akd_label(seed: &[u8; 32], subject: &str, facet: &str, audience: &str) -> String {
    let pseudonym = derive_audience_label(seed, subject, audience);
    format!("{}/{}", hex::encode(pseudonym), facet)
}

/// Format a public (non-audience-scoped) AKD label.
///
/// The label is: `subject / facet`
/// Used when no audience scoping is needed.
pub fn public_akd_label(subject: &str, facet: &str) -> String {
    format!("{}/{}", subject, facet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let seed = [42u8; 32];
        let l1 = derive_audience_label(&seed, "sha256:subject", "sha256:audience");
        let l2 = derive_audience_label(&seed, "sha256:subject", "sha256:audience");
        assert_eq!(l1, l2);
    }

    #[test]
    fn different_audiences_unlinkable() {
        let seed = [42u8; 32];
        let l1 = derive_audience_label(&seed, "sha256:subject", "sha256:audience_a");
        let l2 = derive_audience_label(&seed, "sha256:subject", "sha256:audience_b");
        assert_ne!(l1, l2);
    }

    #[test]
    fn different_subjects_unlinkable() {
        let seed = [42u8; 32];
        let l1 = derive_audience_label(&seed, "sha256:subject_a", "sha256:audience");
        let l2 = derive_audience_label(&seed, "sha256:subject_b", "sha256:audience");
        assert_ne!(l1, l2);
    }

    #[test]
    fn different_seeds_unlinkable() {
        let s1 = [1u8; 32];
        let s2 = [2u8; 32];
        let l1 = derive_audience_label(&s1, "sha256:subject", "sha256:audience");
        let l2 = derive_audience_label(&s2, "sha256:subject", "sha256:audience");
        assert_ne!(l1, l2);
    }

    #[test]
    fn length_prefix_prevents_injection() {
        let seed = [42u8; 32];
        let l1 = derive_audience_label(&seed, "ab", "c");
        let l2 = derive_audience_label(&seed, "a", "bc");
        assert_ne!(l1, l2);
    }

    #[test]
    fn audience_akd_label_includes_facet() {
        let seed = [42u8; 32];
        let label = audience_akd_label(&seed, "sha256:sub", "key/signing", "sha256:aud");
        assert!(label.contains("key/signing"));
        assert!(label.contains('/'));
    }

    #[test]
    fn public_akd_label_format() {
        let label = public_akd_label("sha256:sub", "key/signing");
        assert_eq!(label, "sha256:sub/key/signing");
    }
}
