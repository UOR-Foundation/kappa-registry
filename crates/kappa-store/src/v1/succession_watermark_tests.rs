use super::*;
use kappa_crypto::Signer;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_types::SignedPayload;

fn succession(
    reason: SuccessionReason,
    signer: &dyn Signer,
) -> Result<Succession, kappa_types::kappa::KappaParseError> {
    Ok(Succession {
        old_anchor: Kappa::from_key(signer.algorithm(), signer.public_key())?,
        new_anchor: Kappa::from_key("ed25519", &[2; 32])?,
        reason,
        effective_at_ms: 42,
        chain_anchor: None,
        prev_identifier: None,
        old_cose_signature: SignedPayload::empty(),
        new_cose_signature: SignedPayload::empty(),
    })
}

#[test]
fn default_watermarks_are_signed_and_bind_the_invalidation_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_bytes(&[1; 32])?;
    for (reason, cutoff) in [
        (SuccessionReason::Rotation, 42),
        (SuccessionReason::Administrative, 42),
        (SuccessionReason::KeyCompromise, i64::MAX),
    ] {
        let record = succession(reason, &signer)?;
        let mut watermark =
            default_watermark_for_succession(&record, ClockMs::from_raw(100), &signer)?;
        assert_eq!(watermark.invalidate_before_ms, cutoff);
        kappa_crypto::signed_types::verify_watermark(&watermark, signer.public_key())?;
        watermark.invalidate_before_ms = cutoff - 1;
        assert!(
            kappa_crypto::signed_types::verify_watermark(&watermark, signer.public_key()).is_err()
        );
    }
    Ok(())
}

#[test]
fn another_signer_cannot_issue_the_old_anchors_default_watermark()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_bytes(&[1; 32])?;
    let unrelated = Ed25519Signer::from_bytes(&[3; 32])?;
    assert!(
        default_watermark_for_succession(
            &succession(SuccessionReason::Rotation, &signer)?,
            ClockMs::from_raw(100),
            &unrelated,
        )
        .is_err()
    );
    Ok(())
}
