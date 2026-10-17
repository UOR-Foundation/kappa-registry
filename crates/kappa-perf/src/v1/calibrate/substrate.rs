//! Substrate: the `arch.os.runtime` portability class of a measurement.
//!
//! Exact machine identity (CPU, microcode, kernel, governor) is provenance
//! and lives in the record, not here.

use std::fmt;

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Substrate {
    arch: String,
    os: String,
    runtime: String,
}

impl Substrate {
    /// Parse `arch.os.runtime`; each part is `[a-z0-9_]+`.
    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.split('.');
        let (arch, os, runtime) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let valid = |part: &str| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        };
        (valid(arch) && valid(os) && valid(runtime)).then(|| Self {
            arch: arch.to_owned(),
            os: os.to_owned(),
            runtime: runtime.to_owned(),
        })
    }

    /// The compiled target with the given execution runtime (`std` for
    /// plain threads, `tokio` for the async runtime).
    pub fn detect(runtime: &str) -> Option<Self> {
        Self::parse(&format!(
            "{}.{}.{runtime}",
            std::env::consts::ARCH,
            std::env::consts::OS
        ))
    }

    pub fn arch(&self) -> &str {
        &self.arch
    }

    pub fn os(&self) -> &str {
        &self.os
    }

    pub fn runtime(&self) -> &str {
        &self.runtime
    }
}

impl fmt::Display for Substrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.arch, self.os, self.runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_roundtrip() {
        let substrate = Substrate::parse("x86_64.linux.std");
        assert_eq!(
            substrate.as_ref().map(ToString::to_string).as_deref(),
            Some("x86_64.linux.std")
        );
        assert_eq!(substrate.as_ref().map(Substrate::runtime), Some("std"));
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "x86_64.linux",
            "x86_64.linux.std.extra",
            "X86.linux.std",
            "x86..std",
        ] {
            assert!(Substrate::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn detect_matches_compiled_target() {
        let substrate = Substrate::detect("tokio");
        assert_eq!(
            substrate.as_ref().map(Substrate::arch),
            Some(std::env::consts::ARCH)
        );
        assert_eq!(
            substrate.as_ref().map(Substrate::os),
            Some(std::env::consts::OS)
        );
        assert!(Substrate::detect("Bad Runtime").is_none());
    }
}
