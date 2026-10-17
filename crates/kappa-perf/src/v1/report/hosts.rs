//! Host calibration attached to the report.
//!
//! Records are grouped by host identity as the baseline groups them
//! (`PlatformInfo::same_host`): numbers from different hosts are never
//! compared, and each host's group carries its recorded run conditions
//! (governor, turbo, SMT, CPU isolation) and build profile, with every
//! condition that disqualifies a gated grade.

use super::datasets::Dataset;
use crate::calibrate::platform::PlatformInfo;

/// One host and what was measured on it.
#[derive(Debug)]
pub struct Host<'a> {
    pub platform: &'a PlatformInfo,
    /// Measured records per session on this host.
    pub sessions: Vec<(&'a str, usize)>,
}

impl Host<'_> {
    /// Conditions under which this host's grades may not gate a merge.
    pub fn findings(&self) -> Vec<String> {
        let platform = self.platform;
        let mut findings = Vec::new();
        match platform.governor.as_deref() {
            Some("performance") => {}
            Some(governor) => findings.push(format!(
                "CPU frequency governor is '{governor}', not 'performance'"
            )),
            None => findings.push("CPU frequency governor not exposed".into()),
        }
        if platform.turbo_enabled.is_none() {
            findings.push("turbo state not exposed".into());
        }
        if platform.smt_active.is_none() {
            findings.push("SMT state not exposed".into());
        }
        if platform.isolated_cpus.as_deref().is_none_or(str::is_empty) {
            findings.push("no isolated CPUs: measurements share cores with the system".into());
        }
        if platform.toolchain.native() {
            findings.push(
                "built with target-cpu=native: the hardware-specific ceiling, not the shipping profile"
                    .into(),
            );
        }
        findings
    }
}

/// Every host the datasets were measured on, in first-seen order.
pub fn hosts(datasets: &[Dataset]) -> Vec<Host<'_>> {
    let mut hosts: Vec<Host<'_>> = Vec::new();
    for dataset in datasets {
        for point in dataset.measured() {
            let found = hosts
                .iter()
                .position(|host| host.platform.same_host(&point.platform));
            let index = found.unwrap_or_else(|| {
                hosts.push(Host {
                    platform: &point.platform,
                    sessions: Vec::new(),
                });
                hosts.len() - 1
            });
            let sessions = &mut hosts[index].sessions;
            match sessions
                .iter_mut()
                .find(|(name, _)| *name == dataset.name.as_str())
            {
                Some((_, count)) => *count += 1,
                None => sessions.push((dataset.name.as_str(), 1)),
            }
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibrate::grammar::OscId;
    use crate::calibrate::profile::Profile;
    use crate::calibrate::record::{CalibrationPoint, Source};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn records_group_by_host_and_findings_name_disqualifying_conditions() -> TestResult {
        let id: OscId = "osc:lat/device.fsync?size=4k".parse()?;
        let mut here = PlatformInfo::detect();
        here.governor = Some("powersave".into());
        here.isolated_cpus = None;
        here.toolchain.rustflags = "-C target-cpu=native".into();
        let mut other = here.clone();
        other.microcode = Some("0xother".into());
        let measured = |platform: &PlatformInfo| {
            let mut point = CalibrationPoint::pending(
                &id,
                Profile::L6Graded,
                Source::Direct,
                None,
                platform.clone(),
            );
            point.value = Some(1.0);
            point
        };
        let datasets = vec![Dataset {
            name: "floors".into(),
            path: "calibration_floors.jsonl".into(),
            points: vec![measured(&here), measured(&here), measured(&other)],
        }];
        let hosts = hosts(&datasets);
        assert_eq!(hosts.len(), 2, "a different microcode is a different host");
        assert_eq!(hosts[0].sessions, [("floors", 2)]);
        let findings = hosts[0].findings().join("\n");
        assert!(findings.contains("'powersave'"), "{findings}");
        assert!(findings.contains("no isolated CPUs"), "{findings}");
        assert!(findings.contains("target-cpu=native"), "{findings}");
        here.governor = Some("performance".into());
        here.isolated_cpus = Some("2-7".into());
        here.toolchain.rustflags = String::new();
        here.turbo_enabled = Some(false);
        here.smt_active = Some(false);
        let clean = Host {
            platform: &here,
            sessions: Vec::new(),
        };
        assert!(clean.findings().is_empty(), "{:?}", clean.findings());
        Ok(())
    }
}
