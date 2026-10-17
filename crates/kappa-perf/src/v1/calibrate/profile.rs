//! Conformance profiles: each level is a strict superset of the one below.

/// What a calibration session enforces and emits.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Profile {
    /// Registered quantity and operation; canonical form.
    L0Core,
    /// Condition typing, domain applicability, required conditions.
    L1Conditions,
    /// Substrate populated on every emitted record.
    L2Substrate,
    /// Composite measurements skip until their dependencies are established.
    L3Accumulation,
    /// Physics-derived validation; violations mark records untrusted.
    L4Validation,
    /// Full provenance: platform, toolchain, criterion estimates, histograms.
    L5Provenance,
    /// Roofline fraction and grade per KAPPA-PERF-001 sections 1.2 and 1.3.
    L6Graded,
}

impl Profile {
    pub const fn name(self) -> &'static str {
        match self {
            Self::L0Core => "L0 core",
            Self::L1Conditions => "L1 conditions",
            Self::L2Substrate => "L2 substrate",
            Self::L3Accumulation => "L3 accumulation",
            Self::L4Validation => "L4 validation",
            Self::L5Provenance => "L5 provenance",
            Self::L6Graded => "L6 graded",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_monotone_with_distinct_names() {
        let levels = [
            Profile::L0Core,
            Profile::L1Conditions,
            Profile::L2Substrate,
            Profile::L3Accumulation,
            Profile::L4Validation,
            Profile::L5Provenance,
            Profile::L6Graded,
        ];
        for pair in levels.windows(2) {
            assert!(pair[0] < pair[1]);
            assert_ne!(pair[0].name(), pair[1].name());
        }
    }
}
