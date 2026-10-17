use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub struct DiskPressure(pub AtomicBool);

pub async fn run_disk_pressure_monitor(
    pressure: Arc<DiskPressure>,
    store_root: std::path::PathBuf,
    threshold_bytes: u64,
    check_interval_secs: u64,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(check_interval_secs));
    loop {
        interval.tick().await;
        let under = available_bytes(&store_root)
            .map(|avail| avail < threshold_bytes)
            .unwrap_or(false);
        pressure.0.store(under, Ordering::Relaxed);
    }
}

#[cfg(unix)]
fn available_bytes(path: &std::path::Path) -> Option<u64> {
    let c_path = std::ffi::CString::new(path.to_str()?).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c_path is a valid null-terminated string, stat is zeroed
    let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return None;
    }
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(not(unix))]
fn available_bytes(_path: &std::path::Path) -> Option<u64> {
    None
}
