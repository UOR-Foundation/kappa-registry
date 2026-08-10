//! Integration tests for the Nix binary cache protocol.
//!
//! Exercises the full HTTP surface: nix-cache-info, narinfo PUT/GET/HEAD,
//! NAR PUT/GET, upload ordering enforcement, and NarHash verification.

mod helpers;
use helpers::*;

fn nix_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap()
}

/// Construct a minimal valid NAR for a regular file.
/// Format: str("nix-archive-1") str("(") str("type") str("regular") str("contents") str(data) str(")")
/// Each str is: 8-byte LE length + bytes + zero-pad to 8-byte alignment.
fn make_nar(file_content: &[u8]) -> Vec<u8> {
    let mut nar = Vec::new();

    fn write_str(buf: &mut Vec<u8>, s: &[u8]) {
        let len = s.len() as u64;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s);
        let pad = (8 - (s.len() % 8)) % 8;
        buf.extend_from_slice(&vec![0u8; pad]);
    }

    write_str(&mut nar, b"nix-archive-1");
    write_str(&mut nar, b"(");
    write_str(&mut nar, b"type");
    write_str(&mut nar, b"regular");
    write_str(&mut nar, b"contents");
    write_str(&mut nar, file_content);
    write_str(&mut nar, b")");
    nar
}

/// Compute nix-base32 encoded SHA-256 hash with "sha256:" prefix.
fn nix_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    format!("sha256:{}", nix_derivation::nixbase32::encode(&hash))
}

/// Compute bare nix-base32 SHA-256 (no prefix) for NAR URLs.
fn nix_sha256_bare(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    nix_derivation::nixbase32::encode(&hash)
}

#[test]
fn nix_cache_info_returns_correct_format() {
    let (_guard, base, _tmp) = start_server();
    let c = nix_client();
    let resp = c.get(format!("{}/nix/nix-cache-info", base)).send().unwrap();
    assert_eq!(resp.status(), 200, "nix-cache-info should return 200");
    let ct = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/x-nix-cache-info"), "content-type: {ct}");
    let body = resp.text().unwrap();
    assert!(body.contains("StoreDir: /nix/store"), "body: {body}");
    assert!(body.contains("WantMassQuery: 1"), "body: {body}");
    assert!(body.contains("Priority:"), "body: {body}");
}

#[test]
fn nar_put_then_narinfo_put_then_get_roundtrip() {
    let (_guard, base, _tmp) = start_server();
    let c = nix_client();

    let file_content = b"hello from kappa nix cache test";
    let nar = make_nar(file_content);

    // Compress with zstd
    let compressed = zstd::encode_all(std::io::Cursor::new(&nar), 3).unwrap();

    // Compute hashes
    let nar_hash = nix_sha256(&nar);
    let file_hash = nix_sha256(&compressed);
    let file_hash_bare = nix_sha256_bare(&compressed);

    // Build a fake store path hash (32 nix-base32 chars)
    // Use first 20 bytes of SHA-256 of nar as the store path digest
    let store_hash = {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(&nar);
        nix_derivation::nixbase32::encode(&h[..20])
    };
    let store_path = format!("/nix/store/{}-test-pkg", store_hash);

    let nar_url = format!("nar/{}.nar.zst", file_hash_bare);

    // Step 1: PUT the compressed NAR
    let resp = c.put(format!("{}/nix/{}", base, nar_url))
        .header("content-type", "application/x-nix-nar")
        .body(compressed.clone())
        .send()
        .unwrap();
    assert_eq!(resp.status(), 201, "NAR PUT failed: {}", resp.text().unwrap_or_default());

    // Step 2: PUT the narinfo (after NAR exists)
    let narinfo_text = format!(
        "StorePath: {store_path}\n\
         URL: {nar_url}\n\
         Compression: zstd\n\
         FileHash: {file_hash}\n\
         FileSize: {file_size}\n\
         NarHash: {nar_hash}\n\
         NarSize: {nar_size}\n\
         References: \n",
        store_path = store_path,
        nar_url = nar_url,
        file_hash = file_hash,
        file_size = compressed.len(),
        nar_hash = nar_hash,
        nar_size = nar.len(),
    );

    let resp = c.put(format!("{}/nix/{}.narinfo", base, store_hash))
        .header("content-type", "text/x-nix-narinfo")
        .body(narinfo_text.clone())
        .send()
        .unwrap();
    assert_eq!(resp.status(), 201, "narinfo PUT failed: {}", resp.text().unwrap_or_default());

    // Step 3: GET the narinfo back
    let resp = c.get(format!("{}/nix/{}.narinfo", base, store_hash))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "narinfo GET failed");
    let ct = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/x-nix-narinfo"), "content-type: {ct}");
    let body = resp.text().unwrap();
    assert!(body.contains(&nar_hash), "body missing NarHash: {body}");
    assert!(body.contains(&store_path), "body missing StorePath: {body}");

    // Step 4: GET the NAR back
    let resp = c.get(format!("{}/nix/{}", base, nar_url))
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "NAR GET failed");
    let nar_bytes = resp.bytes().unwrap();
    assert_eq!(nar_bytes.as_ref(), compressed.as_slice(), "NAR content mismatch");
}

#[test]
fn head_narinfo_returns_200_for_existing() {
    let (_guard, base, _tmp) = start_server();
    let c = nix_client();

    let file_content = b"head test content";
    let nar = make_nar(file_content);
    let compressed = zstd::encode_all(std::io::Cursor::new(&nar), 3).unwrap();
    let nar_hash = nix_sha256(&nar);
    let file_hash = nix_sha256(&compressed);
    let file_hash_bare = nix_sha256_bare(&compressed);
    let store_hash = {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(&nar);
        nix_derivation::nixbase32::encode(&h[..20])
    };
    let store_path = format!("/nix/store/{}-head-test", store_hash);
    let nar_url = format!("nar/{}.nar.zst", file_hash_bare);

    // PUT NAR then narinfo
    c.put(format!("{}/nix/{}", base, nar_url))
        .body(compressed.clone())
        .send().unwrap();
    let narinfo_text = format!(
        "StorePath: {store_path}\nURL: {nar_url}\nCompression: zstd\n\
         FileHash: {file_hash}\nFileSize: {}\nNarHash: {nar_hash}\n\
         NarSize: {}\nReferences: \n",
        compressed.len(), nar.len(),
    );
    c.put(format!("{}/nix/{}.narinfo", base, store_hash))
        .body(narinfo_text)
        .send().unwrap();

    // HEAD should return 200
    let resp = c.head(format!("{}/nix/{}.narinfo", base, store_hash))
        .send().unwrap();
    assert_eq!(resp.status(), 200, "HEAD existing narinfo should be 200");
}

#[test]
fn head_narinfo_returns_404_for_missing() {
    let (_guard, base, _tmp) = start_server();
    let c = nix_client();
    let resp = c.head(format!("{}/nix/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.narinfo", base))
        .send().unwrap();
    assert_eq!(resp.status(), 404, "HEAD missing narinfo should be 404");
}

#[test]
fn narinfo_put_before_nar_accepted() {
    // The Nix client uploads narinfo BEFORE the NAR. The server must accept
    // narinfo without the NAR present. Verification is deferred to NAR PUT time.
    let (_guard, base, _tmp) = start_server();
    let c = nix_client();

    let file_content = b"deferred verification test";
    let nar = make_nar(file_content);
    let compressed = zstd::encode_all(std::io::Cursor::new(&nar), 3).unwrap();
    let nar_hash = nix_sha256(&nar);
    let file_hash = nix_sha256(&compressed);
    let file_hash_bare = nix_sha256_bare(&compressed);
    let store_hash = {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(&nar);
        nix_derivation::nixbase32::encode(&h[..20])
    };
    let store_path = format!("/nix/store/{}-deferred", store_hash);
    let nar_url = format!("nar/{}.nar.zst", file_hash_bare);

    // Step 1: PUT narinfo FIRST (before NAR exists)
    let narinfo_text = format!(
        "StorePath: {store_path}\nURL: {nar_url}\nCompression: zstd\n\
         FileHash: {file_hash}\nFileSize: {}\nNarHash: {nar_hash}\n\
         NarSize: {}\nReferences: \n",
        compressed.len(), nar.len(),
    );
    let resp = c.put(format!("{}/nix/{}.narinfo", base, store_hash))
        .body(narinfo_text)
        .send().unwrap();
    assert_eq!(resp.status(), 201, "narinfo PUT before NAR should succeed: {}", resp.text().unwrap_or_default());

    // Step 2: PUT the NAR (triggers deferred verification)
    let resp = c.put(format!("{}/nix/{}", base, nar_url))
        .body(compressed)
        .send().unwrap();
    assert_eq!(resp.status(), 201, "NAR PUT should succeed");

    // Step 3: GET narinfo still works (verification passed)
    let resp = c.get(format!("{}/nix/{}.narinfo", base, store_hash))
        .send().unwrap();
    assert_eq!(resp.status(), 200, "narinfo should still be accessible after NAR upload");
}

#[test]
fn narinfo_put_with_wrong_hash_returns_400() {
    let (_guard, base, _tmp) = start_server();
    let c = nix_client();

    let file_content = b"wrong hash test";
    let nar = make_nar(file_content);
    let compressed = zstd::encode_all(std::io::Cursor::new(&nar), 3).unwrap();
    let nar_hash = nix_sha256(&nar);
    let file_hash = nix_sha256(&compressed);
    let file_hash_bare = nix_sha256_bare(&compressed);
    let store_hash = {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(&nar);
        nix_derivation::nixbase32::encode(&h[..20])
    };
    let store_path = format!("/nix/store/{}-wrong-hash", store_hash);
    let nar_url = format!("nar/{}.nar.zst", file_hash_bare);

    // PUT the NAR
    c.put(format!("{}/nix/{}", base, nar_url))
        .body(compressed.clone())
        .send().unwrap();

    // PUT narinfo with WRONG URL hash (different store hash in URL vs body)
    let wrong_hash = "cccccccccccccccccccccccccccccccc";
    let narinfo_text = format!(
        "StorePath: {store_path}\nURL: {nar_url}\nCompression: zstd\n\
         FileHash: {file_hash}\nFileSize: {}\nNarHash: {nar_hash}\n\
         NarSize: {}\nReferences: \n",
        compressed.len(), nar.len(),
    );
    let resp = c.put(format!("{}/nix/{}.narinfo", base, wrong_hash))
        .body(narinfo_text)
        .send().unwrap();
    assert_eq!(resp.status(), 400, "narinfo PUT with wrong hash should be 400");
}

#[test]
fn nar_put_is_idempotent() {
    let (_guard, base, _tmp) = start_server();
    let c = nix_client();

    let nar = make_nar(b"idempotent");
    let compressed = zstd::encode_all(std::io::Cursor::new(&nar), 3).unwrap();
    let file_hash_bare = nix_sha256_bare(&compressed);
    let nar_url = format!("nar/{}.nar.zst", file_hash_bare);

    let resp1 = c.put(format!("{}/nix/{}", base, nar_url))
        .body(compressed.clone())
        .send().unwrap();
    assert_eq!(resp1.status(), 201);

    let resp2 = c.put(format!("{}/nix/{}", base, nar_url))
        .body(compressed)
        .send().unwrap();
    assert_eq!(resp2.status(), 201, "second PUT should also succeed (idempotent)");
}

#[test]
fn get_missing_nar_returns_404() {
    let (_guard, base, _tmp) = start_server();
    let c = nix_client();
    let resp = c.get(format!("{}/nix/nar/nonexistent.nar.zst", base))
        .send().unwrap();
    assert_eq!(resp.status(), 404);
}

#[test]
fn nix_paths_do_not_get_warning_header() {
    let (_guard, base, _tmp) = start_server();
    let c = nix_client();
    let resp = c.get(format!("{}/nix/nix-cache-info", base)).send().unwrap();
    assert_eq!(resp.status(), 200);
    // Nix responses should NOT have the OCI Warning: 299 header
    let warning = resp.headers().get("warning");
    assert!(warning.is_none(), "Nix response should not have Warning header, got: {:?}", warning);
}
