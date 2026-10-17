//! Latency distributions in `HdrHistogram` form.
//!
//! KAPPA-PERF-001 PERF-DOC-011 requires p50, p90, p99, p99.9 and max with
//! sample count for every latency; PERF-DOC-012 requires coordinated-omission
//! correction for open-loop load; PERF-DOC-013 requires `HdrHistogram` encoding
//! with three significant digits so runs merge across hosts. The histogram
//! tracks 1 ns to one hour at three significant digits. Out-of-range values
//! are an error, never clamped: a clamp would hide exactly the tail outliers
//! a latency distribution exists to show.

use std::time::Duration;

use hdrhistogram::Histogram;
use hdrhistogram::serialization::{Deserializer, Serializer, V2DeflateSerializer};

/// Highest trackable latency: one hour in nanoseconds.
pub const MAX_TRACKABLE_NS: u64 = 3_600_000_000_000;
/// Significant decimal digits preserved (PERF-DOC-013).
pub const SIGNIFICANT_DIGITS: u8 = 3;

#[derive(Debug, thiserror::Error)]
pub enum HistogramError {
    #[error("histogram creation: {0}")]
    Creation(#[from] hdrhistogram::CreationError),
    #[error("recording {value} ns: {source}")]
    Record {
        value: u64,
        source: hdrhistogram::RecordError,
    },
    #[error("merging histograms: {0}")]
    Addition(#[from] hdrhistogram::AdditionError),
    #[error("encoding histogram: {0}")]
    Encode(String),
    #[error("decoding histogram: {0}")]
    Decode(String),
    #[error("histogram is not hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("duration {0:?} exceeds u64 nanoseconds")]
    DurationOverflow(Duration),
}

/// Summary of a latency distribution in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Percentiles {
    pub count: u64,
    pub min_ns: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
    pub stdev_ns: f64,
}

/// A latency distribution.
#[derive(Debug, Clone)]
pub struct LatencyHistogram {
    inner: Histogram<u64>,
}

impl LatencyHistogram {
    pub fn new() -> Result<Self, HistogramError> {
        Ok(Self {
            inner: Histogram::new_with_bounds(1, MAX_TRACKABLE_NS, SIGNIFICANT_DIGITS)?,
        })
    }

    pub fn record(&mut self, value_ns: u64) -> Result<(), HistogramError> {
        self.inner
            .record(value_ns)
            .map_err(|source| HistogramError::Record {
                value: value_ns,
                source,
            })
    }

    pub fn record_duration(&mut self, duration: Duration) -> Result<(), HistogramError> {
        self.record(duration_ns(duration)?)
    }

    /// Record a latency observed under a constant arrival rate whose
    /// expected interval is `interval_ns`. When a response outlasts the
    /// interval, the requests a closed-loop client would have failed to
    /// issue are recorded as decreasing synthetic latencies (the wrk2
    /// method). Only open-loop runs may use this; closed-loop data is
    /// recorded with [`Self::record`].
    pub fn record_corrected(
        &mut self,
        value_ns: u64,
        interval_ns: u64,
    ) -> Result<(), HistogramError> {
        self.inner
            .record_correct(value_ns, interval_ns)
            .map_err(|source| HistogramError::Record {
                value: value_ns,
                source,
            })
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), HistogramError> {
        self.inner.add(&other.inner)?;
        Ok(())
    }

    pub fn len(&self) -> u64 {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// `None` when nothing was recorded: an empty distribution has no
    /// percentiles, and zeros would read as measurements.
    pub fn percentiles(&self) -> Option<Percentiles> {
        if self.inner.is_empty() {
            return None;
        }
        let mut quantiles = self.inner.value_at_quantiles([0.5, 0.9, 0.99, 0.999]);
        Some(Percentiles {
            count: self.inner.len(),
            min_ns: self.inner.min(),
            p50_ns: quantiles.next()?,
            p90_ns: quantiles.next()?,
            p99_ns: quantiles.next()?,
            p999_ns: quantiles.next()?,
            max_ns: self.inner.max(),
            mean_ns: self.inner.mean(),
            stdev_ns: self.inner.stdev(),
        })
    }

    /// V2 + DEFLATE encoding, hex in the JSONL record.
    pub fn encode(&self) -> Result<String, HistogramError> {
        let mut bytes = Vec::new();
        V2DeflateSerializer::new()
            .serialize(&self.inner, &mut bytes)
            .map_err(|error| HistogramError::Encode(error.to_string()))?;
        Ok(hex::encode(bytes))
    }

    pub fn decode(encoded: &str) -> Result<Self, HistogramError> {
        let bytes = hex::decode(encoded)?;
        let inner: Histogram<u64> = Deserializer::new()
            .deserialize(&mut bytes.as_slice())
            .map_err(|error| HistogramError::Decode(error.to_string()))?;
        Ok(Self { inner })
    }
}

pub fn duration_ns(duration: Duration) -> Result<u64, HistogramError> {
    u64::try_from(duration.as_nanos()).map_err(|_| HistogramError::DurationOverflow(duration))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn uniform_1_to_10000() -> Result<LatencyHistogram, HistogramError> {
        let mut histogram = LatencyHistogram::new()?;
        for value in 1..=10_000 {
            histogram.record(value)?;
        }
        Ok(histogram)
    }

    #[test]
    fn percentiles_match_the_distribution_within_three_digits() -> TestResult {
        let p = uniform_1_to_10000()?.percentiles().ok_or("empty")?;
        assert_eq!(p.count, 10_000);
        assert_eq!(p.min_ns, 1);
        // Three significant digits: values are exact to within 0.1%.
        let close = |actual: u64, expected: u64| actual.abs_diff(expected) * 1000 <= expected;
        assert!(close(p.p50_ns, 5_000), "p50 {}", p.p50_ns);
        assert!(close(p.p90_ns, 9_000), "p90 {}", p.p90_ns);
        assert!(close(p.p99_ns, 9_900), "p99 {}", p.p99_ns);
        assert!(close(p.p999_ns, 9_990), "p99.9 {}", p.p999_ns);
        assert!(close(p.max_ns, 10_000), "max {}", p.max_ns);
        assert!((p.mean_ns - 5_000.5).abs() < 10.0, "mean {}", p.mean_ns);
        assert!(p.p50_ns <= p.p90_ns && p.p90_ns <= p.p99_ns && p.p99_ns <= p.p999_ns);
        Ok(())
    }

    #[test]
    fn empty_histogram_has_no_percentiles() -> TestResult {
        let histogram = LatencyHistogram::new()?;
        assert!(histogram.is_empty());
        assert_eq!(histogram.percentiles(), None);
        Ok(())
    }

    #[test]
    fn out_of_range_values_fail_instead_of_clamping() -> TestResult {
        let mut histogram = LatencyHistogram::new()?;
        assert!(matches!(
            histogram.record(MAX_TRACKABLE_NS * 4),
            Err(HistogramError::Record { .. })
        ));
        assert!(histogram.is_empty());
        Ok(())
    }

    #[test]
    fn coordinated_omission_correction_fills_the_stall() -> TestResult {
        // One 1 ms stall in a stream expecting a request every 100 us:
        // a closed-loop client saw one sample; the corrected histogram
        // records the nine requests that should have been issued.
        let mut closed = LatencyHistogram::new()?;
        closed.record(1_000_000)?;
        let mut open = LatencyHistogram::new()?;
        open.record_corrected(1_000_000, 100_000)?;
        assert_eq!(closed.len(), 1);
        assert_eq!(open.len(), 10);
        let p = open.percentiles().ok_or("empty")?;
        assert!(
            p.p50_ns < 1_000_000,
            "corrected median must fall below the stall"
        );
        Ok(())
    }

    #[test]
    fn encoding_roundtrips_and_merges() -> TestResult {
        let original = uniform_1_to_10000()?;
        let decoded = LatencyHistogram::decode(&original.encode()?)?;
        assert_eq!(decoded.percentiles(), original.percentiles());

        let mut merged = decoded;
        merged.merge(&original)?;
        assert_eq!(merged.len(), 20_000);
        assert!(LatencyHistogram::decode("zz").is_err());
        assert!(LatencyHistogram::decode("00010203").is_err());
        Ok(())
    }

    #[test]
    fn durations_convert_within_resolution() -> TestResult {
        assert_eq!(duration_ns(Duration::from_micros(250))?, 250_000);
        assert!(duration_ns(Duration::MAX).is_err());
        let mut histogram = LatencyHistogram::new()?;
        histogram.record_duration(Duration::from_micros(250))?;
        // `max` is the highest value equivalent to the recorded one at three
        // significant digits: within 0.1%, never below the recorded value.
        let max = histogram.percentiles().ok_or("empty")?.max_ns;
        assert!((250_000..=250_250).contains(&max), "max {max}");
        Ok(())
    }
}
