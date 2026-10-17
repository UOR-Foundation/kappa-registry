//! Open-loop, constant-rate load: the wrk2 method.
//!
//! Requests are scheduled at a fixed rate whatever the server does: request
//! `i` is due at `start + i / rate`. They are spread round-robin over
//! exactly `connections` TCP connections, one per load task, each opened
//! before the first slot and sending its requests in order. A request is
//! prepared (its body built and digested) before its slot, then sent when
//! the slot arrives, and its latency is measured from the slot, not from
//! the moment it was sent. A server that stalls therefore cannot hide the
//! requests that queued behind the stall: each one is charged the time it
//! waited past its slot (no coordinated omission). The first failed request
//! or connection fails the whole run; a sample that did not do its work is
//! never recorded.

use std::net::SocketAddr;
use std::time::Duration;

use kappa_perf::calibrate::LatencyHistogram;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::requests::{Call, Connection};

/// Offered load.
#[derive(Debug, Clone, Copy)]
pub struct Plan {
    /// Requests per second offered.
    pub rate: u64,
    /// TCP connections the requests are spread over.
    pub connections: u64,
    /// How long requests are offered.
    pub duration: Duration,
}

impl Plan {
    /// Requests the plan offers in total.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "rates and durations are small positive values; whole requests"
    )]
    pub fn total(&self) -> u64 {
        (self.rate as f64 * self.duration.as_secs_f64()) as u64
    }
}

/// What a run measured.
pub struct Outcome {
    /// Latency of every request, from its slot to its complete response.
    pub latency: LatencyHistogram,
    pub completed: u64,
    /// From the first slot to the last completion.
    pub elapsed: Duration,
}

impl Outcome {
    /// Requests completed per second.
    #[allow(clippy::cast_precision_loss, reason = "request counts far below 2^53")]
    pub fn achieved_rate(&self) -> f64 {
        self.completed as f64 / self.elapsed.as_secs_f64()
    }
}

/// Offer `plan` to the server at `addr`. `prepare(i)` builds request `i`
/// ahead of its slot.
///
/// # Errors
///
/// The first connection or request failure, or a latency the histogram
/// cannot hold.
pub async fn run<P>(addr: SocketAddr, plan: Plan, prepare: P) -> Result<Outcome, String>
where
    P: Fn(u64) -> Result<Call, String> + Clone + Send + Sync + 'static,
{
    if plan.rate == 0 || plan.connections == 0 {
        return Err(format!("load plan offers nothing: {plan:?}"));
    }
    let total = plan.total();
    let interval = Duration::from_secs(1).as_nanos() / u128::from(plan.rate);
    // Establishing a connection is no request's latency: every connection
    // is open before the first slot.
    let mut opened = Vec::new();
    for _ in 0..plan.connections {
        opened.push(Connection::open(addr).await?);
    }
    // Every connection task is spawned before the first slot.
    let start = Instant::now() + Duration::from_millis(20);
    let mut tasks = JoinSet::new();
    for (first, mut connection) in (0..plan.connections).zip(opened) {
        let prepare = prepare.clone();
        tasks.spawn(async move {
            let mut latency = LatencyHistogram::new().map_err(|e| e.to_string())?;
            let mut completed = 0u64;
            let mut request = first;
            while request < total {
                let offset = u64::try_from(interval * u128::from(request))
                    .map_err(|_| format!("request {request}'s slot overflows"))?;
                let slot = start + Duration::from_nanos(offset);
                let call = prepare(request)?;
                tokio::time::sleep_until(slot).await;
                connection
                    .call(call)
                    .await
                    .map_err(|error| format!("request {request}: {error}"))?;
                latency
                    .record_duration(slot.elapsed())
                    .map_err(|e| e.to_string())?;
                completed += 1;
                request += plan.connections;
            }
            connection.close().await?;
            Ok::<_, String>((latency, completed))
        });
    }
    let mut merged = LatencyHistogram::new().map_err(|e| e.to_string())?;
    let mut completed = 0;
    while let Some(joined) = tasks.join_next().await {
        let (latency, count) = joined.map_err(|error| format!("connection task: {error}"))??;
        merged.merge(&latency).map_err(|e| e.to_string())?;
        completed += count;
    }
    let elapsed = start.elapsed();
    if completed != total {
        return Err(format!("completed {completed} of {total} offered requests"));
    }
    Ok(Outcome {
        latency: merged,
        completed,
        elapsed,
    })
}
