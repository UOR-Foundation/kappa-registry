//! Disk pressure tests: prove the server rejects writes when disk space
//! is below threshold, allows reads during pressure, and returns 503 on
//! the ready probe.
//!
//! FAILS UNTIL: DiskPressure is implemented with:
//! - KAPPA_DISK_PRESSURE_THRESHOLD_MB and KAPPA_DISK_PRESSURE_CHECK_INTERVAL_SECS
//!   env vars added to Config::from_env()
//! - Periodic statvfs check in main.rs setting an AtomicBool
//! - Per-write 507 check in blob PUT handler
//! - 503 on /v2/_health/ready when pressure flag is set
//!
//! Note on tag operations: redb writes to a database FILE on the filesystem
//! (redb/src/db.rs:1349-1365). When the disk is truly full, redb
//! WriteTransaction::commit() will also fail. The disk pressure check
//! applies to blob PUT handlers specifically -- whether it also gates
//! redb writes is an implementation decision.

#[path = "helpers/mod.rs"]
#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::*;

use std::time::Duration;

// =============================================================================
// Core pressure tests
// =============================================================================

#[test]
fn disk_pressure_rejects_blob_put() {
    // FAILS UNTIL: KAPPA_DISK_PRESSURE_THRESHOLD_MB implemented
    // Set threshold to 100 TB -- no real system has this much free space
    let (guard, base, _tmp) = start_server_with_env(&[
        ("KAPPA_DISK_PRESSURE_THRESHOLD_MB", "100000000"),
        ("KAPPA_DISK_PRESSURE_CHECK_INTERVAL_SECS", "1"),
    ]);
    let c = client();

    // Wait for at least one pressure check cycle
    std::thread::sleep(Duration::from_secs(2));

    let content = b"should-be-rejected-under-pressure";
    let digest = sha256_digest(content);
    let resp = c
        .put(format!("{}/v2/pressure/blobs/{}", base, digest))
        .body(content.to_vec())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        507,
        "blob PUT under pressure should return 507, got {}",
        resp.status()
    );
    // Verify OCI error envelope
    let body = resp.text().unwrap();
    assert_oci_error(&body, "INSUFFICIENT_STORAGE");
    drop(guard);
}

#[test]
fn disk_pressure_allows_reads() {
    // Push a blob while NOT under pressure (1 MB threshold),
    // then verify GET still works.
    let (guard, base, _tmp) = start_server_with_env(&[
        ("KAPPA_DISK_PRESSURE_THRESHOLD_MB", "1"),
        ("KAPPA_DISK_PRESSURE_CHECK_INTERVAL_SECS", "1"),
    ]);
    let c = client();

    let content = b"readable-under-pressure";
    let digest = sha256_digest(content);
    let resp = c
        .put(format!("{}/v2/pressure-read/blobs/{}", base, digest))
        .body(content.to_vec())
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 201 || status == 200,
        "initial push should succeed with 1MB threshold"
    );

    // GET should always work regardless of pressure state
    let get = c
        .get(format!("{}/v2/pressure-read/blobs/{}", base, digest))
        .send()
        .unwrap();
    assert_eq!(
        get.status(),
        200,
        "GET should succeed under any pressure state"
    );
    assert_eq!(get.bytes().unwrap().as_ref(), content);
    drop(guard);
}

#[test]
fn disk_pressure_health_returns_503() {
    // FAILS UNTIL: ready probe checks disk pressure flag
    let (guard, base, _tmp) = start_server_with_env(&[
        ("KAPPA_DISK_PRESSURE_THRESHOLD_MB", "100000000"),
        ("KAPPA_DISK_PRESSURE_CHECK_INTERVAL_SECS", "1"),
    ]);
    let c = client();
    std::thread::sleep(Duration::from_secs(2));

    let resp = c.get(format!("{}/v2/_health/ready", base)).send().unwrap();
    assert_eq!(
        resp.status(),
        503,
        "ready probe should return 503 under pressure, got {}",
        resp.status()
    );
    drop(guard);
}

#[test]
fn disk_pressure_manifest_put_blocked() {
    // FAILS UNTIL: manifest PUT path checks pressure (it stores a blob)
    let (guard, base, _tmp) = start_server_with_env(&[
        ("KAPPA_DISK_PRESSURE_THRESHOLD_MB", "100000000"),
        ("KAPPA_DISK_PRESSURE_CHECK_INTERVAL_SECS", "1"),
    ]);
    let c = client();
    std::thread::sleep(Duration::from_secs(2));

    let resp = c
        .put(format!("{}/v2/pressure-manifest/manifests/latest", base))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(br#"{"schemaVersion":2}"#.to_vec())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        507,
        "manifest PUT should be blocked under pressure, got {}",
        resp.status()
    );
    drop(guard);
}

#[test]
fn disk_pressure_interval_configurable() {
    // FAILS UNTIL: check interval is configurable
    let (guard, base, _tmp) = start_server_with_env(&[
        ("KAPPA_DISK_PRESSURE_THRESHOLD_MB", "100000000"),
        ("KAPPA_DISK_PRESSURE_CHECK_INTERVAL_SECS", "1"),
    ]);
    let c = client();

    // After 2 seconds with 1s interval, at least one check must have run
    std::thread::sleep(Duration::from_secs(2));

    let content = b"interval-test";
    let digest = sha256_digest(content);
    let resp = c
        .put(format!("{}/v2/interval/blobs/{}", base, digest))
        .body(content.to_vec())
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        507,
        "pressure should be detected within 2s with 1s interval"
    );
    drop(guard);
}

#[test]
fn disk_pressure_clears_when_space_available() {
    // With 1 MB threshold, most systems have enough space
    let (guard, base, _tmp) = start_server_with_env(&[
        ("KAPPA_DISK_PRESSURE_THRESHOLD_MB", "1"),
        ("KAPPA_DISK_PRESSURE_CHECK_INTERVAL_SECS", "1"),
    ]);
    let c = client();
    std::thread::sleep(Duration::from_secs(2));

    let content = b"not-under-pressure";
    let digest = sha256_digest(content);
    let resp = c
        .put(format!("{}/v2/clear/blobs/{}", base, digest))
        .body(content.to_vec())
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 201 || status == 200,
        "should not be under pressure with 1 MB threshold, got {}",
        status
    );
    drop(guard);
}

// =============================================================================
// statvfs primitive test (unix only)
// =============================================================================

#[test]
fn available_bytes_returns_positive_on_tmpdir() {
    #[cfg(unix)]
    {
        let tmp = tempfile::tempdir().unwrap();
        let c_path = std::ffi::CString::new(tmp.path().to_str().unwrap()).unwrap();
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        assert_eq!(ret, 0, "statvfs should succeed on tmpdir");
        let available = stat.f_bavail as u64 * stat.f_frsize as u64;
        assert!(available > 0, "available bytes should be > 0");
    }
}
