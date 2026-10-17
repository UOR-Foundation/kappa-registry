//! Host provenance attached to every calibration record.
//!
//! Everything here is detected, never typed in: CPU identity and microcode,
//! ISA features that change digest and AEAD dispatch, topology, cache
//! geometry, memory, the frequency, SMT, huge-page and isolation state that
//! KAPPA-PERF-001 PERF-DOC-015 requires to be recorded, CPU vulnerability
//! mitigations, the toolchain and flags the binary was built with, and the
//! filesystem under the storage path being measured. A field the platform
//! does not expose is `None`, never a fabricated default.

use std::collections::BTreeSet;
use std::path::Path;

/// ISA features whose presence changes dispatch in the measured code.
const DISPATCH_FLAGS: &[&str] = &[
    "sse4_2",
    "avx",
    "avx2",
    "avx512f",
    "avx512bw",
    "avx512vl",
    "bmi2",
    "adx",
    "aes",
    "vaes",
    "pclmulqdq",
    "vpclmulqdq",
    "sha_ni",
];

/// CPU tier of KAPPA-PERF-001 section 2.1. GPU (H3) and RDMA (H4) are
/// orthogonal capabilities reported separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HostClass {
    /// No SHA-NI/VAES, single socket.
    H0,
    /// AVX-512 without SHA-NI/VAES, two or more sockets.
    H1,
    /// SHA-NI and VAES present.
    H2,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CacheLevel {
    pub level: u8,
    /// `Data`, `Instruction` or `Unified`.
    pub kind: String,
    pub size_bytes: u64,
    pub shared_cpu_list: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Toolchain {
    pub rustc: String,
    pub rustflags: String,
    pub profile: String,
    pub opt_level: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StorageInfo {
    pub path: String,
    pub mount_point: String,
    pub fs_type: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlatformInfo {
    pub hostname: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_family: Option<String>,
    pub cpu_model_number: Option<String>,
    pub stepping: Option<String>,
    pub microcode: Option<String>,
    pub dispatch_flags: Vec<String>,
    pub sockets: Option<u32>,
    pub physical_cores: Option<u32>,
    pub logical_cpus: u32,
    pub numa_nodes: Option<u32>,
    pub caches: Vec<CacheLevel>,
    pub memory_bytes: Option<u64>,
    pub kernel: Option<String>,
    pub governor: Option<String>,
    pub turbo_enabled: Option<bool>,
    pub smt_active: Option<bool>,
    pub transparent_hugepages: Option<String>,
    pub isolated_cpus: Option<String>,
    pub mitigations: Vec<(String, String)>,
    pub gpus: u32,
    pub rdma_devices: u32,
    pub toolchain: Toolchain,
    pub host_class: HostClass,
}

impl PlatformInfo {
    pub fn detect() -> Self {
        let cpuinfo = read("/proc/cpuinfo").unwrap_or_default();
        let first = cpuinfo.split("\n\n").next().unwrap_or_default();
        let field = |name: &str| cpuinfo_field(first, name);
        let flag_line = field("flags").unwrap_or_default();
        let flags: BTreeSet<&str> = flag_line.split_whitespace().collect();
        let dispatch_flags: Vec<String> = DISPATCH_FLAGS
            .iter()
            .filter(|flag| flags.contains(*flag))
            .map(|flag| (*flag).to_owned())
            .collect();
        let (sockets, physical_cores) = topology(&cpuinfo);
        let conditions = RunConditions::detect();
        let has = |flag: &str| dispatch_flags.iter().any(|f| f == flag);
        let host_class = if has("sha_ni") && has("vaes") {
            HostClass::H2
        } else if has("avx512f") && sockets.is_some_and(|sockets| sockets >= 2) {
            HostClass::H1
        } else {
            HostClass::H0
        };
        Self {
            hostname: read_trim("/proc/sys/kernel/hostname"),
            cpu_model: field("model name"),
            cpu_family: field("cpu family"),
            cpu_model_number: field("model"),
            stepping: field("stepping"),
            microcode: field("microcode"),
            dispatch_flags,
            sockets,
            physical_cores,
            logical_cpus: std::thread::available_parallelism()
                .ok()
                .and_then(|count| u32::try_from(count.get()).ok())
                .unwrap_or(1),
            numa_nodes: count_entries("/sys/devices/system/node", |name| {
                name.strip_prefix("node")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            }),
            caches: caches(),
            memory_bytes: memory_bytes(),
            kernel: read_trim("/proc/sys/kernel/osrelease"),
            governor: conditions.governor,
            turbo_enabled: conditions.turbo_enabled,
            smt_active: conditions.smt_active,
            transparent_hugepages: read_trim("/sys/kernel/mm/transparent_hugepage/enabled")
                .and_then(|modes| selected_mode(&modes)),
            isolated_cpus: conditions.isolated_cpus,
            mitigations: mitigations(),
            gpus: gpus(),
            rdma_devices: count_entries("/sys/class/infiniband", |_| true).unwrap_or(0),
            toolchain: Toolchain::compiled(),
            host_class,
        }
    }

    /// The run conditions this record states.
    pub fn run_conditions(&self) -> RunConditions {
        RunConditions {
            governor: self.governor.clone(),
            turbo_enabled: self.turbo_enabled,
            smt_active: self.smt_active,
            isolated_cpus: self.isolated_cpus.clone(),
        }
    }

    /// Two records come from the same host when CPU identity, microcode,
    /// kernel and toolchain agree. Hostname alone is not identity.
    pub fn same_host(&self, other: &Self) -> bool {
        self.hostname == other.hostname
            && self.cpu_model == other.cpu_model
            && self.microcode == other.microcode
            && self.kernel == other.kernel
            && self.toolchain == other.toolchain
    }
}

/// Run conditions an operator can change while a session runs.
///
/// PERF-DOC-015 requires these recorded: frequency governor, turbo, SMT
/// and CPU isolation. A session reads them again at every measurement, so
/// no record states a condition it was not measured under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunConditions {
    /// The governor of every CPU, or each governor with its CPU count when
    /// they differ (`mixed: performance x15, powersave x1`).
    pub governor: Option<String>,
    pub turbo_enabled: Option<bool>,
    pub smt_active: Option<bool>,
    pub isolated_cpus: Option<String>,
}

impl RunConditions {
    pub fn detect() -> Self {
        Self {
            governor: governor(),
            turbo_enabled: turbo_enabled(),
            smt_active: read_trim("/sys/devices/system/cpu/smt/active").map(|v| v == "1"),
            isolated_cpus: read_trim("/sys/devices/system/cpu/isolated"),
        }
    }

    /// Each condition that differs from `self` in `now`, as `name: was ->
    /// now`.
    pub fn changes(&self, now: &Self) -> Vec<String> {
        fn shown<T: std::fmt::Debug>(value: Option<&T>) -> String {
            value.map_or_else(|| "not exposed".into(), |v| format!("{v:?}"))
        }
        let mut changes = Vec::new();
        let mut compare = |name: &str, was: String, is: String| {
            if was != is {
                changes.push(format!("{name}: {was} -> {is}"));
            }
        };
        compare(
            "governor",
            shown(self.governor.as_ref()),
            shown(now.governor.as_ref()),
        );
        compare(
            "turbo",
            shown(self.turbo_enabled.as_ref()),
            shown(now.turbo_enabled.as_ref()),
        );
        compare(
            "smt",
            shown(self.smt_active.as_ref()),
            shown(now.smt_active.as_ref()),
        );
        compare(
            "isolated cpus",
            shown(self.isolated_cpus.as_ref()),
            shown(now.isolated_cpus.as_ref()),
        );
        changes
    }
}

/// The scaling governor of every CPU that exposes one: the single governor
/// when all agree, otherwise each with its CPU count.
fn governor() -> Option<String> {
    let entries = std::fs::read_dir("/sys/devices/system/cpu").ok()?;
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        let is_cpu = name.to_str().is_some_and(|n| {
            n.strip_prefix("cpu")
                .is_some_and(|i| !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit()))
        });
        if !is_cpu {
            continue;
        }
        if let Ok(value) = std::fs::read_to_string(entry.path().join("cpufreq/scaling_governor")) {
            *counts.entry(value.trim().to_owned()).or_default() += 1;
        }
    }
    summarize_governors(&counts)
}

fn summarize_governors(counts: &std::collections::BTreeMap<String, usize>) -> Option<String> {
    match counts.len() {
        0 => None,
        1 => counts.keys().next().cloned(),
        _ => Some(format!(
            "mixed: {}",
            counts
                .iter()
                .map(|(governor, cpus)| format!("{governor} x{cpus}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

impl Toolchain {
    #[allow(
        clippy::manual_string_new,
        reason = "env! expands to an empty literal when the build had no RUSTFLAGS"
    )]
    pub fn compiled() -> Self {
        Self {
            rustc: env!("KAPPA_PERF_RUSTC_VERSION").to_owned(),
            rustflags: env!("KAPPA_PERF_RUSTFLAGS").to_owned(),
            profile: env!("KAPPA_PERF_PROFILE").to_owned(),
            opt_level: env!("KAPPA_PERF_OPT_LEVEL").to_owned(),
            target: env!("KAPPA_PERF_TARGET").to_owned(),
        }
    }

    /// Whether the binary was built for the host CPU (the hardware-specific
    /// ceiling of PERF-CAL-040) rather than the shipping profile.
    pub fn native(&self) -> bool {
        self.rustflags.contains("target-cpu=native")
    }
}

impl StorageInfo {
    /// The mount holding `path`: the longest mount point that is a path
    /// prefix of it, from `/proc/self/mounts`.
    pub fn for_path(path: &Path) -> Option<Self> {
        let resolved = path.canonicalize().ok()?;
        let mounts = read("/proc/self/mounts")?;
        mounts
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let source = fields.next()?;
                let mount_point = unescape_mount(fields.next()?);
                let fs_type = fields.next()?;
                resolved
                    .starts_with(&mount_point)
                    .then(|| (mount_point, fs_type.to_owned(), source.to_owned()))
            })
            .max_by_key(|(mount_point, _, _)| mount_point.len())
            .map(|(mount_point, fs_type, source)| Self {
                path: resolved.display().to_string(),
                mount_point,
                fs_type,
                source,
            })
    }
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn read_trim(path: &str) -> Option<String> {
    read(path)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn cpuinfo_field(block: &str, name: &str) -> Option<String> {
    block.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name).then(|| value.trim().to_owned())
    })
}

/// Distinct `physical id` values and `(physical id, core id)` pairs.
fn topology(cpuinfo: &str) -> (Option<u32>, Option<u32>) {
    let mut sockets = BTreeSet::new();
    let mut cores = BTreeSet::new();
    for block in cpuinfo.split("\n\n") {
        if let (Some(socket), Some(core)) = (
            cpuinfo_field(block, "physical id"),
            cpuinfo_field(block, "core id"),
        ) {
            sockets.insert(socket.clone());
            cores.insert((socket, core));
        }
    }
    let count = |n: usize| (n > 0).then(|| u32::try_from(n).ok()).flatten();
    (count(sockets.len()), count(cores.len()))
}

fn count_entries(dir: &str, keep: impl Fn(&str) -> bool) -> Option<u32> {
    let entries = std::fs::read_dir(dir).ok()?;
    let count = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_str().is_some_and(&keep))
        .count();
    u32::try_from(count).ok()
}

fn caches() -> Vec<CacheLevel> {
    let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu/cpu0/cache") else {
        return Vec::new();
    };
    let mut caches: Vec<CacheLevel> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("index"))
        })
        .filter_map(|entry| {
            let base = entry.path();
            let get = |file: &str| {
                std::fs::read_to_string(base.join(file))
                    .ok()
                    .map(|value| value.trim().to_owned())
            };
            Some(CacheLevel {
                level: get("level")?.parse().ok()?,
                kind: get("type")?,
                size_bytes: parse_cache_size(&get("size")?)?,
                shared_cpu_list: get("shared_cpu_list"),
            })
        })
        .collect();
    caches.sort_by(|a, b| (a.level, &a.kind).cmp(&(b.level, &b.kind)));
    caches
}

/// sysfs cache sizes: `32K`, `1024K`, `16M`.
fn parse_cache_size(raw: &str) -> Option<u64> {
    let (digits, shift) = match raw.as_bytes().last()? {
        b'K' => (&raw[..raw.len() - 1], 10),
        b'M' => (&raw[..raw.len() - 1], 20),
        b'G' => (&raw[..raw.len() - 1], 30),
        _ => (raw, 0),
    };
    digits.parse::<u64>().ok()?.checked_mul(1 << shift)
}

fn memory_bytes() -> Option<u64> {
    let meminfo = read("/proc/meminfo")?;
    let line = meminfo.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

/// `intel_pstate/no_turbo` (0 = turbo on) or `cpufreq/boost` (1 = on).
fn turbo_enabled() -> Option<bool> {
    read_trim("/sys/devices/system/cpu/intel_pstate/no_turbo")
        .map(|value| value == "0")
        .or_else(|| read_trim("/sys/devices/system/cpu/cpufreq/boost").map(|value| value == "1"))
}

/// The bracketed selection in `always [madvise] never`.
fn selected_mode(modes: &str) -> Option<String> {
    let start = modes.find('[')? + 1;
    let end = start + modes[start..].find(']')?;
    Some(modes[start..end].to_owned())
}

fn mitigations() -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu/vulnerabilities") else {
        return Vec::new();
    };
    let mut found: Vec<(String, String)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_owned();
            let status = std::fs::read_to_string(entry.path())
                .ok()?
                .trim()
                .to_owned();
            Some((name, status))
        })
        .collect();
    found.sort();
    found
}

/// PCI display controllers (class 0x03xxxx) from NVIDIA or AMD.
fn gpus() -> u32 {
    let Ok(entries) = std::fs::read_dir("/sys/bus/pci/devices") else {
        return 0;
    };
    let count = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            let get = |file: &str| {
                std::fs::read_to_string(entry.path().join(file))
                    .map(|value| value.trim().to_owned())
                    .unwrap_or_default()
            };
            get("class").starts_with("0x03")
                && matches!(get("vendor").as_str(), "0x10de" | "0x1002")
        })
        .count();
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// `/proc/self/mounts` escapes space, tab, newline and backslash as octal.
fn unescape_mount(raw: &str) -> String {
    raw.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn detects_the_running_host() {
        let info = PlatformInfo::detect();
        assert!(info.logical_cpus >= 1);
        assert!(
            info.toolchain.rustc.starts_with("rustc "),
            "{}",
            info.toolchain.rustc
        );
        assert!(!info.toolchain.profile.is_empty());
        if cfg!(target_os = "linux") {
            assert!(info.kernel.is_some());
            assert!(info.memory_bytes.is_some_and(|bytes| bytes > 0));
            assert!(info.cpu_model.is_some());
        }
        assert!(info.same_host(&info.clone()));
    }

    #[test]
    fn host_class_follows_dispatch_flags() {
        let info = PlatformInfo::detect();
        let has = |flag: &str| info.dispatch_flags.iter().any(|f| f == flag);
        if has("sha_ni") && has("vaes") {
            assert_eq!(info.host_class, HostClass::H2);
        } else if info.host_class == HostClass::H1 {
            assert!(has("avx512f") && info.sockets.is_some_and(|s| s >= 2));
        }
    }

    #[test]
    fn parsers_handle_sysfs_formats() {
        assert_eq!(parse_cache_size("32K"), Some(32 << 10));
        assert_eq!(parse_cache_size("16M"), Some(16 << 20));
        assert_eq!(parse_cache_size("bogus"), None);
        assert_eq!(
            selected_mode("always [madvise] never").as_deref(),
            Some("madvise")
        );
        assert_eq!(selected_mode("none"), None);
        assert_eq!(unescape_mount("/mnt/my\\040disk"), "/mnt/my disk");
    }

    #[test]
    fn run_condition_changes_name_each_condition_and_governors_summarize() {
        let start = RunConditions {
            governor: Some("powersave".into()),
            turbo_enabled: Some(true),
            smt_active: Some(true),
            isolated_cpus: None,
        };
        assert!(start.changes(&start.clone()).is_empty());
        let now = RunConditions {
            governor: Some("performance".into()),
            isolated_cpus: Some("2-7".into()),
            ..start
        };
        assert_eq!(
            start.changes(&now),
            [
                "governor: \"powersave\" -> \"performance\"",
                "isolated cpus: not exposed -> \"2-7\"",
            ]
        );
        let mut counts = std::collections::BTreeMap::new();
        assert_eq!(summarize_governors(&counts), None);
        counts.insert("performance".to_owned(), 15);
        assert_eq!(summarize_governors(&counts).as_deref(), Some("performance"));
        counts.insert("powersave".to_owned(), 1);
        assert_eq!(
            summarize_governors(&counts).as_deref(),
            Some("mixed: performance x15, powersave x1")
        );
    }

    #[test]
    fn topology_counts_sockets_and_cores() {
        let cpuinfo = "processor\t: 0\nphysical id\t: 0\ncore id\t: 0\n\n\
                       processor\t: 1\nphysical id\t: 0\ncore id\t: 0\n\n\
                       processor\t: 2\nphysical id\t: 1\ncore id\t: 0\n";
        assert_eq!(topology(cpuinfo), (Some(2), Some(2)));
        assert_eq!(topology(""), (None, None));
    }

    #[test]
    fn storage_info_resolves_the_mount_of_a_path() -> TestResult {
        if !cfg!(target_os = "linux") {
            return Ok(());
        }
        let dir = tempfile::tempdir()?;
        let info = StorageInfo::for_path(dir.path()).ok_or("no mount for tempdir")?;
        assert!(Path::new(&info.path).starts_with(&info.mount_point));
        assert!(!info.fs_type.is_empty());
        Ok(())
    }
}
