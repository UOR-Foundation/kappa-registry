//! Physical quantities and the conversion from a timed iteration to a value
//! in the quantity's canonical unit.
//!
//! Every record carries its value in the unit its quantity names. Criterion
//! measures nanoseconds per iteration; the work an iteration performs
//! (bytes, elements, or both) converts that into bandwidth, rate, latency per
//! element, or cost per byte. Quantities that are not derived from time
//! (`ratio`, `size`) are recorded directly and refuse conversion.

use std::fmt;

/// Physical dimension of a calibration measurement.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Quantity {
    /// Bytes per second. Higher is better.
    Bw,
    /// Nanoseconds per operation (or per element when the work names
    /// elements). Lower is better.
    Lat,
    /// Operations per second. Higher is better.
    Ops,
    /// Resource per unit of work, named by the `res` condition. Lower is
    /// better.
    Cost,
    /// Dimensionless ratio (roofline fraction, peer ratio). Higher is better.
    Ratio,
    /// Bytes (serialized size, bytes per key). Lower is better.
    Size,
}

/// Work performed by one timed iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Work {
    Bytes(u64),
    Bits(u64),
    Elements(u64),
    ElementsAndBytes { elements: u64, bytes: u64 },
}

impl Work {
    pub const fn bytes(self) -> Option<u64> {
        match self {
            Self::Bytes(bytes) | Self::ElementsAndBytes { bytes, .. } => Some(bytes),
            Self::Bits(bits) => Some(bits / 8),
            Self::Elements(_) => None,
        }
    }

    pub const fn elements(self) -> Option<u64> {
        match self {
            Self::Elements(elements) | Self::ElementsAndBytes { elements, .. } => Some(elements),
            Self::Bytes(_) | Self::Bits(_) => None,
        }
    }
}

/// Why a timed value cannot be expressed in a quantity's unit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConversionError {
    #[error("{quantity} is recorded directly and is not derived from iteration time")]
    NotTimeDerived { quantity: Quantity },
    #[error("{quantity} requires the iteration to declare {needed} of work")]
    MissingWork {
        quantity: Quantity,
        needed: &'static str,
    },
    #[error(
        "cost resource '{res}' is not derived from iteration time (valid: ns_per_byte, ns_per_element)"
    )]
    UnsupportedCostResource { res: String },
    #[error("iteration time must be finite and positive, got {ns}")]
    InvalidTime { ns: String },
    #[error("declared work must be non-zero")]
    ZeroWork,
}

impl Quantity {
    pub const ALL: [Self; 6] = [
        Self::Bw,
        Self::Lat,
        Self::Ops,
        Self::Cost,
        Self::Ratio,
        Self::Size,
    ];

    pub const fn token(self) -> &'static str {
        match self {
            Self::Bw => "bw",
            Self::Lat => "lat",
            Self::Ops => "ops",
            Self::Cost => "cost",
            Self::Ratio => "ratio",
            Self::Size => "size",
        }
    }

    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|quantity| quantity.token() == token)
    }

    pub const fn unit(self) -> &'static str {
        match self {
            Self::Bw => "bytes/s",
            Self::Lat => "ns",
            Self::Ops => "ops/s",
            Self::Cost => "resource/unit",
            Self::Ratio => "ratio",
            Self::Size => "bytes",
        }
    }

    pub const fn higher_is_better(self) -> bool {
        matches!(self, Self::Bw | Self::Ops | Self::Ratio)
    }

    /// Whether values of this quantity come from iteration time.
    pub const fn is_time_derived(self) -> bool {
        matches!(self, Self::Bw | Self::Lat | Self::Ops | Self::Cost)
    }

    /// Condition keys a measurement of this quantity must carry.
    pub const fn required_conditions(self) -> &'static [&'static str] {
        match self {
            Self::Cost => &["res"],
            _ => &[],
        }
    }

    /// Convert nanoseconds per iteration into this quantity's unit.
    ///
    /// `res` is the `cost` resource condition; it is ignored for every other
    /// quantity.
    #[allow(
        clippy::cast_precision_loss,
        reason = "work counts above 2^53 lose integer precision, far below measurement noise"
    )]
    pub fn from_ns(
        self,
        ns_per_iter: f64,
        work: Option<Work>,
        res: Option<&str>,
    ) -> Result<f64, ConversionError> {
        if !ns_per_iter.is_finite() || ns_per_iter <= 0.0 {
            return Err(ConversionError::InvalidTime {
                ns: ns_per_iter.to_string(),
            });
        }
        let nonzero = |value: u64| {
            if value == 0 {
                Err(ConversionError::ZeroWork)
            } else {
                Ok(value as f64)
            }
        };
        match self {
            Self::Lat => match work.and_then(Work::elements) {
                Some(elements) => Ok(ns_per_iter / nonzero(elements)?),
                None => Ok(ns_per_iter),
            },
            Self::Bw => {
                let bytes = work
                    .and_then(Work::bytes)
                    .ok_or(ConversionError::MissingWork {
                        quantity: self,
                        needed: "bytes",
                    })?;
                Ok(nonzero(bytes)? * 1e9 / ns_per_iter)
            }
            Self::Ops => {
                let elements = match work.and_then(Work::elements) {
                    Some(elements) => nonzero(elements)?,
                    None => 1.0,
                };
                Ok(elements * 1e9 / ns_per_iter)
            }
            Self::Cost => match res {
                Some("ns_per_byte") => {
                    let bytes = work
                        .and_then(Work::bytes)
                        .ok_or(ConversionError::MissingWork {
                            quantity: self,
                            needed: "bytes",
                        })?;
                    Ok(ns_per_iter / nonzero(bytes)?)
                }
                Some("ns_per_element") => {
                    let elements =
                        work.and_then(Work::elements)
                            .ok_or(ConversionError::MissingWork {
                                quantity: self,
                                needed: "elements",
                            })?;
                    Ok(ns_per_iter / nonzero(elements)?)
                }
                other => Err(ConversionError::UnsupportedCostResource {
                    res: other.unwrap_or("").to_owned(),
                }),
            },
            Self::Ratio | Self::Size => Err(ConversionError::NotTimeDerived { quantity: self }),
        }
    }

    /// Fraction of `bound` achieved by `value`, oriented so that 1.0 means
    /// the measurement reached the bound and smaller is worse.
    pub fn achieved_fraction(self, value: f64, bound: f64) -> Option<f64> {
        if !(value.is_finite() && bound.is_finite()) || value <= 0.0 || bound <= 0.0 {
            return None;
        }
        Some(if self.higher_is_better() {
            value / bound
        } else {
            bound / value
        })
    }
}

impl fmt::Display for Quantity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn tokens_roundtrip_and_are_distinct() {
        for quantity in Quantity::ALL {
            assert_eq!(Quantity::from_token(quantity.token()), Some(quantity));
        }
        let mut tokens: Vec<_> = Quantity::ALL.iter().map(|q| q.token()).collect();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), Quantity::ALL.len());
        assert_eq!(Quantity::from_token("xyz"), None);
    }

    #[test]
    fn bandwidth_from_bytes_per_iteration() -> TestResult {
        // 64 KiB in 16 microseconds is 4.096e9 bytes per second.
        let bw = Quantity::Bw.from_ns(16_000.0, Some(Work::Bytes(65_536)), None)?;
        assert!((bw - 4.096e9).abs() < 1.0, "bw {bw}");
        let bits = Quantity::Bw.from_ns(16_000.0, Some(Work::Bits(65_536 * 8)), None)?;
        assert!((bits - bw).abs() < 1.0);
        Ok(())
    }

    #[test]
    fn bandwidth_without_bytes_is_refused() {
        assert_eq!(
            Quantity::Bw.from_ns(10.0, Some(Work::Elements(4)), None),
            Err(ConversionError::MissingWork {
                quantity: Quantity::Bw,
                needed: "bytes"
            })
        );
        assert!(Quantity::Bw.from_ns(10.0, None, None).is_err());
    }

    #[test]
    fn latency_is_per_element_when_elements_are_declared() -> TestResult {
        assert!((Quantity::Lat.from_ns(800.0, None, None)? - 800.0).abs() < f64::EPSILON);
        let per = Quantity::Lat.from_ns(800.0, Some(Work::Elements(100)), None)?;
        assert!((per - 8.0).abs() < f64::EPSILON);
        Ok(())
    }

    #[test]
    fn rate_counts_elements_per_second() -> TestResult {
        let single = Quantity::Ops.from_ns(1_000.0, None, None)?;
        assert!((single - 1e6).abs() < 1e-6);
        let batch = Quantity::Ops.from_ns(1_000.0, Some(Work::Elements(64)), None)?;
        assert!((batch - 64e6).abs() < 1e-3);
        Ok(())
    }

    #[test]
    fn cost_requires_a_time_derived_resource() -> TestResult {
        let per_byte =
            Quantity::Cost.from_ns(4_096.0, Some(Work::Bytes(1_024)), Some("ns_per_byte"))?;
        assert!((per_byte - 4.0).abs() < f64::EPSILON);
        assert!(matches!(
            Quantity::Cost.from_ns(1.0, Some(Work::Bytes(1)), Some("cycles")),
            Err(ConversionError::UnsupportedCostResource { .. })
        ));
        assert_eq!(Quantity::Cost.required_conditions(), &["res"]);
        Ok(())
    }

    #[test]
    fn direct_quantities_refuse_time_conversion() {
        for quantity in [Quantity::Ratio, Quantity::Size] {
            assert_eq!(
                quantity.from_ns(1.0, None, None),
                Err(ConversionError::NotTimeDerived { quantity })
            );
            assert!(!quantity.is_time_derived());
        }
    }

    #[test]
    fn invalid_time_and_zero_work_are_refused() {
        for ns in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(matches!(
                Quantity::Lat.from_ns(ns, None, None),
                Err(ConversionError::InvalidTime { .. })
            ));
        }
        assert_eq!(
            Quantity::Bw.from_ns(1.0, Some(Work::Bytes(0)), None),
            Err(ConversionError::ZeroWork)
        );
    }

    #[test]
    fn achieved_fraction_is_direction_aware() {
        // Bandwidth: 80 of a 100 bound is 0.8.
        assert_eq!(Quantity::Bw.achieved_fraction(80.0, 100.0), Some(0.8));
        // Latency: 125 ns against a 100 ns floor is 0.8.
        assert_eq!(Quantity::Lat.achieved_fraction(125.0, 100.0), Some(0.8));
        assert_eq!(Quantity::Lat.achieved_fraction(0.0, 100.0), None);
        assert_eq!(Quantity::Bw.achieved_fraction(f64::NAN, 100.0), None);
    }
}
