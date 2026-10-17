//! Human-readable values in each quantity's unit.
//!
//! Formatting never changes a number's meaning: bandwidth stays bytes per
//! second (IEC prefixes),
//! latency stays time, rates stay per second, and anything unrecognized is
//! printed with its own unit.

#[allow(
    clippy::cast_precision_loss,
    reason = "display formatting; 2^53 ns is 104 days"
)]
pub fn ns(value: u64) -> String {
    duration(value as f64)
}

/// Nanoseconds as the largest unit keeping the number at or above one.
pub fn duration(ns: f64) -> String {
    if !ns.is_finite() {
        return format!("{ns} ns");
    }
    let magnitude = ns.abs();
    if magnitude >= 1e9 {
        format!("{:.3} s", ns / 1e9)
    } else if magnitude >= 1e6 {
        format!("{:.3} ms", ns / 1e6)
    } else if magnitude >= 1e3 {
        format!("{:.3} us", ns / 1e3)
    } else {
        format!("{ns:.1} ns")
    }
}

fn iec(bytes: f64, suffix: &str) -> String {
    const UNITS: [(f64, &str); 4] = [
        (1_099_511_627_776.0, "Ti"),
        (1_073_741_824.0, "Gi"),
        (1_048_576.0, "Mi"),
        (1_024.0, "Ki"),
    ];
    for (scale, prefix) in UNITS {
        if bytes.abs() >= scale {
            return format!("{:.3} {prefix}B{suffix}", bytes / scale);
        }
    }
    format!("{bytes:.0} B{suffix}")
}

fn rate(ops: f64) -> String {
    if ops.abs() >= 1e9 {
        format!("{:.3} G ops/s", ops / 1e9)
    } else if ops.abs() >= 1e6 {
        format!("{:.3} M ops/s", ops / 1e6)
    } else if ops.abs() >= 1e3 {
        format!("{:.3} k ops/s", ops / 1e3)
    } else {
        format!("{ops:.3} ops/s")
    }
}

/// A recorded value in its record's unit.
pub fn value(value: f64, unit: &str) -> String {
    match unit {
        "bytes/s" => iec(value, "/s"),
        "ns" => duration(value),
        "ops/s" => rate(value),
        "bytes" => iec(value, ""),
        "ratio" => format!("{value:.4}"),
        other => format!("{value} {other}"),
    }
}

/// `|` would end a markdown table cell.
pub fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_render_in_their_units() {
        assert_eq!(value(78.0 * 1_073_741_824.0, "bytes/s"), "78.000 GiB/s");
        assert_eq!(value(1_169_407.0, "ns"), "1.169 ms");
        assert_eq!(value(950.0, "ns"), "950.0 ns");
        assert_eq!(value(2_500_000.0, "ops/s"), "2.500 M ops/s");
        assert_eq!(value(35_636.0 * 1024.0, "bytes"), "34.801 MiB");
        assert_eq!(value(0.8681, "ratio"), "0.8681");
        assert_eq!(value(3.0, "widgets"), "3 widgets");
        assert_eq!(ns(26_242), "26.242 us");
        assert_eq!(cell("a|b\nc"), "a\\|b c");
    }
}
