use kappa_handler::{base64url_decode, base64url_sha256};

use super::SessionError;

/// Maximum decoded size for JWT header and payload.
/// DPoP headers are typically ~200 bytes. 4 KB is generous.
/// Rejects before allocating to prevent memory exhaustion
/// from attacker-crafted oversized JWTs.
const MAX_DECODED_PART_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct DpopClaims {
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: u64,
    pub ath: Option<String>,
    pub jkt: String,
}

fn decode_bounded(input: &str) -> Result<Vec<u8>, SessionError> {
    let estimated = input.len() * 3 / 4;
    if estimated > MAX_DECODED_PART_BYTES {
        return Err(SessionError::InvalidToken);
    }
    base64url_decode(input).map_err(|_| SessionError::InvalidToken)
}

/// Parse and verify a DPoP proof JWT.
///
/// Algorithm dispatch: ES256 (P-256), EdDSA (Ed25519), ES256K (K-256).
/// JWK extraction dispatches on (alg, kty, crv) to produce the
/// correct public key bytes for the corresponding verifier.
pub fn parse_and_verify_dpop_proof(proof_jwt: &str) -> Result<DpopClaims, SessionError> {
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(SessionError::InvalidToken);
    }

    let header_bytes = decode_bounded(parts[0])?;
    let payload_bytes = decode_bounded(parts[1])?;
    let signature_bytes = base64url_decode(parts[2]).map_err(|_| SessionError::InvalidToken)?;

    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| SessionError::InvalidToken)?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| SessionError::InvalidToken)?;

    let typ = header
        .get("typ")
        .and_then(|v| v.as_str())
        .ok_or(SessionError::InvalidToken)?;
    if typ != "dpop+jwt" {
        return Err(SessionError::InvalidToken);
    }

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or(SessionError::InvalidToken)?;
    let jwk = header.get("jwk").ok_or(SessionError::InvalidToken)?;
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or(SessionError::InvalidToken)?;
    let crv = jwk
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or(SessionError::InvalidToken)?;

    let (verifier_alg, public_key, jkt) = match (alg, kty, crv) {
        ("ES256", "EC", "P-256") => {
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or(SessionError::InvalidToken)?;
            let y = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or(SessionError::InvalidToken)?;
            let x_bytes = decode_bounded(x)?;
            let y_bytes = decode_bounded(y)?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return Err(SessionError::InvalidToken);
            }
            let mut pk = Vec::with_capacity(65);
            pk.push(0x04);
            pk.extend_from_slice(&x_bytes);
            pk.extend_from_slice(&y_bytes);
            let thumbprint = jwk_thumbprint_ec(crv, x, y);
            ("p256", pk, thumbprint)
        }
        ("EdDSA", "OKP", "Ed25519") => {
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or(SessionError::InvalidToken)?;
            let x_bytes = decode_bounded(x)?;
            if x_bytes.len() != 32 {
                return Err(SessionError::InvalidToken);
            }
            let thumbprint = jwk_thumbprint_okp(crv, x);
            ("ed25519", x_bytes, thumbprint)
        }
        ("ES256K", "EC", "secp256k1") => {
            let x = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or(SessionError::InvalidToken)?;
            let y = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or(SessionError::InvalidToken)?;
            let x_bytes = decode_bounded(x)?;
            let y_bytes = decode_bounded(y)?;
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return Err(SessionError::InvalidToken);
            }
            let mut pk = Vec::with_capacity(65);
            pk.push(0x04);
            pk.extend_from_slice(&x_bytes);
            pk.extend_from_slice(&y_bytes);
            let thumbprint = jwk_thumbprint_ec(crv, x, y);
            ("k256", pk, thumbprint)
        }
        _ => return Err(SessionError::InvalidToken),
    };

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let verifier =
        kappa_crypto::verifier_for(verifier_alg).map_err(|_| SessionError::InvalidToken)?;
    let valid = verifier
        .verify(&public_key, signing_input.as_bytes(), &signature_bytes)
        .map_err(|_| SessionError::InvalidToken)?;
    if !valid {
        return Err(SessionError::InvalidToken);
    }

    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or(SessionError::InvalidToken)?
        .to_string();
    let htm = payload
        .get("htm")
        .and_then(|v| v.as_str())
        .ok_or(SessionError::InvalidToken)?
        .to_string();
    let htu = payload
        .get("htu")
        .and_then(|v| v.as_str())
        .ok_or(SessionError::InvalidToken)?
        .to_string();
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or(SessionError::InvalidToken)?;
    let ath = payload
        .get("ath")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(DpopClaims {
        jti,
        htm,
        htu,
        iat,
        ath,
        jkt,
    })
}

/// RFC 7638 JWK Thumbprint for EC keys (P-256, secp256k1).
/// Canonical JSON with lexicographic key order: crv, kty, x, y.
fn jwk_thumbprint_ec(crv: &str, x_b64url: &str, y_b64url: &str) -> String {
    let canonical = format!(
        r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
        crv, x_b64url, y_b64url,
    );
    base64url_sha256(canonical.as_bytes())
}

/// RFC 7638 JWK Thumbprint for OKP keys (Ed25519).
/// Canonical JSON with lexicographic key order: crv, kty, x.
fn jwk_thumbprint_okp(crv: &str, x_b64url: &str) -> String {
    let canonical = format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, crv, x_b64url,);
    base64url_sha256(canonical.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_jwt_no_dots() {
        assert!(matches!(
            parse_and_verify_dpop_proof("nodots"),
            Err(SessionError::InvalidToken),
        ));
    }

    #[test]
    fn rejects_jwt_with_two_dots() {
        assert!(matches!(
            parse_and_verify_dpop_proof("a.b"),
            Err(SessionError::InvalidToken),
        ));
    }

    #[test]
    fn rejects_jwt_with_four_dots() {
        assert!(matches!(
            parse_and_verify_dpop_proof("a.b.c.d"),
            Err(SessionError::InvalidToken),
        ));
    }

    #[test]
    fn rejects_invalid_base64url_header() {
        assert!(matches!(
            parse_and_verify_dpop_proof("!!!.YQ.YQ"),
            Err(SessionError::InvalidToken),
        ));
    }

    #[test]
    fn rejects_non_json_header() {
        let header = kappa_handler::base64url_encode(b"not json");
        let proof = format!("{}.YQ.YQ", header);
        assert!(matches!(
            parse_and_verify_dpop_proof(&proof),
            Err(SessionError::InvalidToken),
        ));
    }

    #[test]
    fn rejects_wrong_typ() {
        let header = kappa_handler::base64url_encode(
            br#"{"typ":"JWT","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}}"#,
        );
        let payload = kappa_handler::base64url_encode(
            br#"{"jti":"1","htm":"POST","htu":"https://x","iat":1}"#,
        );
        let proof = format!("{}.{}.AA", header, payload);
        assert!(matches!(
            parse_and_verify_dpop_proof(&proof),
            Err(SessionError::InvalidToken),
        ));
    }

    #[test]
    fn rejects_unsupported_algorithm() {
        let header = kappa_handler::base64url_encode(
            br#"{"typ":"dpop+jwt","alg":"RS256","jwk":{"kty":"RSA","n":"AA","e":"AA"}}"#,
        );
        let payload = kappa_handler::base64url_encode(
            br#"{"jti":"1","htm":"POST","htu":"https://x","iat":1}"#,
        );
        let proof = format!("{}.{}.AA", header, payload);
        assert!(matches!(
            parse_and_verify_dpop_proof(&proof),
            Err(SessionError::InvalidToken),
        ));
    }

    #[test]
    fn rejects_oversized_header() {
        let large = vec![b'A'; MAX_DECODED_PART_BYTES * 2];
        let large_b64 = kappa_handler::base64url_encode(&large);
        let proof = format!("{}.YQ.YQ", large_b64);
        assert!(matches!(
            parse_and_verify_dpop_proof(&proof),
            Err(SessionError::InvalidToken),
        ));
    }

    #[test]
    fn jwk_thumbprint_ec_deterministic() {
        let t1 = jwk_thumbprint_ec("P-256", "x_value", "y_value");
        let t2 = jwk_thumbprint_ec("P-256", "x_value", "y_value");
        assert_eq!(t1, t2);
        assert!(!t1.is_empty());
    }

    #[test]
    fn jwk_thumbprint_okp_deterministic() {
        let t1 = jwk_thumbprint_okp("Ed25519", "x_value");
        let t2 = jwk_thumbprint_okp("Ed25519", "x_value");
        assert_eq!(t1, t2);
        assert!(!t1.is_empty());
    }

    #[test]
    fn jwk_thumbprint_ec_different_keys_different_thumbprints() {
        let t1 = jwk_thumbprint_ec("P-256", "x1", "y1");
        let t2 = jwk_thumbprint_ec("P-256", "x2", "y2");
        assert_ne!(t1, t2);
    }

    #[test]
    fn jwk_thumbprint_different_curves_different_thumbprints() {
        let t1 = jwk_thumbprint_ec("P-256", "x", "y");
        let t2 = jwk_thumbprint_ec("secp256k1", "x", "y");
        assert_ne!(t1, t2);
    }
}
