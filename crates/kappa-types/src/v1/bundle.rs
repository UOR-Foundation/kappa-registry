use std::cmp::Reverse;
use std::collections::HashMap;
use std::str;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::delta::{self, DeltaBudget, DeltaReservation};
use crate::kappa::verify_kappa;

const MAGIC: &[u8; 4] = b"KBND";
const VERSION: u8 = 1;
const ENTRY_TYPE_FULL: u8 = 0x01;
const ENTRY_TYPE_DELTA: u8 = 0x02;
const FLAG_HAS_DELTAS: u8 = 0x01;
const DELTA_WINDOW_SIZE: usize = 10;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BundleError {
    #[error("bundle truncated: {0}")]
    Truncated(&'static str),
    #[error("bundle trailer SHA-256 mismatch")]
    TrailerMismatch,
    #[error("bundle kappa mismatch: {0}")]
    KappaMismatch(String),
    #[error("delta entry in non-delta bundle")]
    DeltaInNoDeltaBundle,
    #[error("bundle decode limit of {limit} bytes exceeded")]
    DecodeLimitExceeded { limit: usize },
    #[error("unsupported entry type: 0x{0:02x}")]
    UnsupportedEntryType(u8),
    #[error("unresolvable delta base: {0}")]
    UnresolvableBase(String),
    #[error("delta error: {0}")]
    Delta(#[from] delta::DeltaError),
    #[error("kappa label error: {0}")]
    Label(#[from] crate::kappa::KappaParseError),
    #[error("bad bundle: {0}")]
    Invalid(String),
}

pub struct BundleEntry {
    pub kappa: String,
    pub content: Vec<u8>,
}

/// A decoded bundle and the budget its entries hold until it is dropped.
pub struct DecodedBundle {
    pub entries: Vec<BundleEntry>,
    pub reservation: DeltaReservation,
}

type BaseResolver<'a> = Option<&'a dyn Fn(&str) -> Option<Vec<u8>>>;

struct EntryPlan<'a> {
    kappa: &'a str,
    content: &'a [u8],
    delta_base: Option<(usize, Vec<u8>)>,
}

pub fn encode(objects: &[(&str, &[u8])], use_deltas: bool) -> Result<Vec<u8>, BundleError> {
    let count = u32::try_from(objects.len())
        .map_err(|_| BundleError::Invalid("too many entries".into()))?;
    for (label, _) in objects {
        u16::try_from(label.len())
            .map_err(|_| BundleError::Invalid("kappa label exceeds wire length".into()))?;
    }
    if !use_deltas || objects.len() < 2 {
        return encode_full_only(objects);
    }

    let mut indexed: Vec<(usize, &str, &[u8])> = objects
        .iter()
        .enumerate()
        .map(|(i, (k, c))| (i, *k, *c))
        .collect();
    indexed.sort_by_key(|b| Reverse(b.2.len()));

    let mut plans: Vec<EntryPlan<'_>> = Vec::with_capacity(indexed.len());
    for (idx, &(_, kappa, content)) in indexed.iter().enumerate() {
        let window_start = idx.saturating_sub(DELTA_WINDOW_SIZE);
        let mut best: Option<(usize, Vec<u8>)> = None;
        for (ci, &(_, _, base)) in indexed.iter().enumerate().take(idx).skip(window_start) {
            if let Some(d) = delta::compute_delta(base, content)
                && best.as_ref().is_none_or(|(_, prev)| d.len() < prev.len())
            {
                best = Some((ci, d));
            }
        }
        plans.push(EntryPlan {
            kappa,
            content,
            delta_base: best,
        });
    }

    let (order, emitted) = emission_order(&plans);

    let has_any_delta = plans.iter().any(|p| p.delta_base.is_some());
    let flags = if has_any_delta { FLAG_HAS_DELTAS } else { 0x00 };
    encode_plans(&plans, &order, &emitted, count, flags)
}

fn emission_order(plans: &[EntryPlan<'_>]) -> (Vec<usize>, Vec<bool>) {
    let mut emitted = vec![false; plans.len()];
    let mut order: Vec<usize> = Vec::with_capacity(plans.len());
    for (i, plan) in plans.iter().enumerate() {
        if plan.delta_base.is_none() {
            order.push(i);
            emitted[i] = true;
        }
    }
    for _ in 0..plans.len() {
        let mut progress = false;
        for i in 0..plans.len() {
            if emitted[i] {
                continue;
            }
            if let Some((base_idx, _)) = &plans[i].delta_base
                && emitted[*base_idx]
            {
                order.push(i);
                emitted[i] = true;
                progress = true;
            }
        }
        if !progress {
            break;
        }
    }
    for (i, e) in emitted.iter().enumerate() {
        if !e {
            order.push(i);
        }
    }

    (order, emitted)
}

fn push_label(out: &mut Vec<u8>, label: &str, what: &str) -> Result<(), BundleError> {
    let bytes = label.as_bytes();
    let length = u16::try_from(bytes.len())
        .map_err(|_| BundleError::Invalid(format!("{what} exceeds wire length")))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_content(out: &mut Vec<u8>, content: &[u8]) {
    out.extend_from_slice(&(content.len() as u64).to_be_bytes());
    out.extend_from_slice(content);
}

fn encode_plans(
    plans: &[EntryPlan<'_>],
    order: &[usize],
    emitted: &[bool],
    count: u32,
    flags: u8,
) -> Result<Vec<u8>, BundleError> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(flags);
    out.extend_from_slice(&count.to_be_bytes());

    for &idx in order {
        let plan = &plans[idx];
        if let Some((base_idx, ref delta_bytes)) = plan.delta_base
            && emitted[base_idx]
        {
            out.push(ENTRY_TYPE_DELTA);
            push_label(&mut out, plan.kappa, "kappa label")?;
            push_label(&mut out, plans[base_idx].kappa, "base label")?;
            push_content(&mut out, delta_bytes);
            continue;
        }
        out.push(ENTRY_TYPE_FULL);
        push_label(&mut out, plan.kappa, "kappa label")?;
        push_content(&mut out, plan.content);
    }

    let hash = Sha256::digest(&out);
    out.extend_from_slice(&hash);
    Ok(out)
}

fn encode_full_only(objects: &[(&str, &[u8])]) -> Result<Vec<u8>, BundleError> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(0x00);
    out.extend_from_slice(
        &u32::try_from(objects.len())
            .map_err(|_| BundleError::Invalid("too many entries".into()))?
            .to_be_bytes(),
    );
    for (kappa, content) in objects {
        out.push(ENTRY_TYPE_FULL);
        push_label(&mut out, kappa, "kappa label")?;
        push_content(&mut out, content);
    }
    let hash = Sha256::digest(&out);
    out.extend_from_slice(&hash);
    Ok(out)
}

/// Decode a bundle, admitting at most `max_bytes` of decoded content in
/// total, every byte reserved against `budget` as it is decoded and held
/// by the returned reservation.
pub fn decode(
    data: &[u8],
    resolve_base: BaseResolver<'_>,
    max_bytes: usize,
    budget: &Arc<DeltaBudget>,
) -> Result<DecodedBundle, BundleError> {
    if data.len() < 10 + 32 {
        return Err(BundleError::Truncated("header+trailer"));
    }

    let payload = &data[..data.len() - 32];
    let trailer = &data[data.len() - 32..];
    if Sha256::digest(payload).as_slice() != trailer {
        return Err(BundleError::TrailerMismatch);
    }
    if &data[..4] != MAGIC {
        return Err(BundleError::Invalid("bad bundle magic".into()));
    }
    if data[4] != VERSION {
        return Err(BundleError::Invalid("unsupported bundle version".into()));
    }
    let flags = data[5];
    let entry_count = u32::from_be_bytes([data[6], data[7], data[8], data[9]]) as usize;
    let max_entries = payload.len() / 56;
    let clamped = entry_count.min(max_entries);

    let mut pos = 10;
    let mut entries = Vec::with_capacity(clamped);
    let mut index: HashMap<String, Vec<u8>> = HashMap::new();
    let mut admitted = Admitted {
        total: 0,
        max: max_bytes,
        reservation: budget.reserve(0)?,
    };

    for _ in 0..entry_count {
        if pos >= payload.len() {
            return Err(BundleError::Truncated("entry"));
        }
        let entry_type = payload[pos];
        pos += 1;

        match entry_type {
            ENTRY_TYPE_FULL => {
                let kappa = parse_kappa_field(payload, &mut pos)?;
                let length = parse_content_length(payload, &mut pos)?;
                // Admitted before the bytes are copied out of the payload.
                admitted.admit(length)?;
                let content = parse_content_bytes(payload, &mut pos, length)?;
                verify_entry_kappa(&kappa, &content)?;
                index.insert(kappa.clone(), content.clone());
                entries.push(BundleEntry { kappa, content });
            }
            ENTRY_TYPE_DELTA => {
                if flags & FLAG_HAS_DELTAS == 0 {
                    return Err(BundleError::DeltaInNoDeltaBundle);
                }
                let kappa = parse_kappa_field(payload, &mut pos)?;
                let base_kappa = parse_kappa_field(payload, &mut pos)?;
                let length = parse_content_length(payload, &mut pos)?;
                let delta_bytes = parse_content_bytes(payload, &mut pos, length)?;
                let base = index
                    .get(&base_kappa)
                    .cloned()
                    .or_else(|| resolve_base.as_ref().and_then(|f| f(&base_kappa)))
                    .ok_or(BundleError::UnresolvableBase(base_kappa))?;
                // The delta's declared result is admitted against the
                // remaining total before it is reserved and decoded; the
                // result's reservation is then carried by the bundle's.
                let (content, held) =
                    delta::apply_delta(&base, &delta_bytes, admitted.remaining(), budget)?;
                admitted.carry(held)?;
                verify_entry_kappa(&kappa, &content)?;
                index.insert(kappa.clone(), content.clone());
                entries.push(BundleEntry { kappa, content });
            }
            t => return Err(BundleError::UnsupportedEntryType(t)),
        }
    }

    Ok(DecodedBundle {
        entries,
        reservation: admitted.reservation,
    })
}

/// The decoded bytes a bundle has been admitted so far, against the
/// caller's total and the shared budget.
struct Admitted {
    total: usize,
    max: usize,
    reservation: DeltaReservation,
}

impl Admitted {
    const fn remaining(&self) -> usize {
        self.max - self.total
    }

    /// Admit `bytes` more decoded content.
    fn admit(&mut self, bytes: usize) -> Result<(), BundleError> {
        if bytes > self.remaining() {
            return Err(BundleError::DecodeLimitExceeded { limit: self.max });
        }
        self.reservation.grow(bytes)?;
        self.total += bytes;
        Ok(())
    }

    /// Carry a decode's own reservation, already within `remaining`,
    /// onto the bundle's.
    fn carry(&mut self, held: DeltaReservation) -> Result<(), BundleError> {
        let bytes = held.bytes();
        if bytes > self.remaining() {
            return Err(BundleError::DecodeLimitExceeded { limit: self.max });
        }
        // Release the decode's reservation first so the budget never holds
        // the same bytes twice, then take them onto the bundle's.
        drop(held);
        self.reservation.grow(bytes)?;
        self.total += bytes;
        Ok(())
    }
}

fn parse_kappa_field(p: &[u8], pos: &mut usize) -> Result<String, BundleError> {
    if *pos + 2 > p.len() {
        return Err(BundleError::Truncated("kappa length"));
    }
    let kl = u16::from_be_bytes([p[*pos], p[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + kl > p.len() {
        return Err(BundleError::Truncated("kappa"));
    }
    let k = str::from_utf8(&p[*pos..*pos + kl])
        .map_err(|_| BundleError::Invalid("kappa not UTF-8".into()))?
        .to_string();
    *pos += kl;
    Ok(k)
}

/// The declared length of a content field, checked against the payload
/// that remains so it is admitted before any copy.
fn parse_content_length(p: &[u8], pos: &mut usize) -> Result<usize, BundleError> {
    if *pos + 8 > p.len() {
        return Err(BundleError::Truncated("content length"));
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&p[*pos..*pos + 8]);
    *pos += 8;
    let length =
        usize::try_from(u64::from_be_bytes(raw)).map_err(|_| BundleError::Truncated("content"))?;
    if length > p.len().saturating_sub(*pos) {
        return Err(BundleError::Truncated("content"));
    }
    Ok(length)
}

fn parse_content_bytes(p: &[u8], pos: &mut usize, length: usize) -> Result<Vec<u8>, BundleError> {
    if length > p.len().saturating_sub(*pos) {
        return Err(BundleError::Truncated("content"));
    }
    let c = p[*pos..*pos + length].to_vec();
    *pos += length;
    Ok(c)
}

fn verify_entry_kappa(kappa: &str, content: &[u8]) -> Result<(), BundleError> {
    match verify_kappa(kappa, content) {
        Ok(true) => Ok(()),
        Ok(false) => Err(BundleError::KappaMismatch(kappa.to_string())),
        Err(e) => Err(BundleError::Label(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kappa::Kappa;

    fn budget(limit: usize) -> Arc<DeltaBudget> {
        Arc::new(DeltaBudget::new(limit))
    }

    #[test]
    fn delta_bundles_round_trip_under_the_budget_and_refuse_past_it() -> Result<(), BundleError> {
        let first = vec![7u8; 4096];
        let mut second = first.clone();
        second.extend_from_slice(b"appended");
        let labels = [
            Kappa::sha256(&first).to_string(),
            Kappa::sha256(&second).to_string(),
        ];
        let objects: [(&str, &[u8]); 2] = [(&labels[0], &first), (&labels[1], &second)];
        let encoded = encode(&objects, true)?;
        let shared = budget(usize::MAX);
        let decoded = decode(&encoded, None, usize::MAX, &shared)?;
        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.reservation.bytes(), first.len() + second.len());
        assert_eq!(shared.used(), first.len() + second.len());
        drop(decoded);
        assert_eq!(shared.used(), 0);
        assert!(matches!(
            decode(&encoded, None, first.len(), &budget(usize::MAX)),
            Err(BundleError::DecodeLimitExceeded { .. })
        ));
        assert!(matches!(
            decode(&encoded, None, usize::MAX, &budget(first.len())),
            Err(BundleError::Delta(
                delta::DeltaError::BudgetExhausted { .. }
            ))
        ));
        Ok(())
    }

    #[test]
    fn a_declared_length_past_the_payload_is_refused_before_any_copy() {
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(VERSION);
        data.push(0);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.push(ENTRY_TYPE_FULL);
        data.extend_from_slice(&1u16.to_be_bytes());
        data.push(b'k');
        data.extend_from_slice(&u64::MAX.to_be_bytes());
        let hash = Sha256::digest(&data);
        data.extend_from_slice(&hash);
        assert!(matches!(
            decode(&data, None, usize::MAX, &budget(usize::MAX)),
            Err(BundleError::Truncated("content"))
        ));
    }
}
