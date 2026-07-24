//! Bundle wire format for bulk object transfer.
//!
//! All multi-byte integers in the KBND format are big-endian (network byte
//! order). Delta instruction offset/size bytes within the delta stream are
//! little-endian per the Git wire format. See `delta.rs` for details.
//!
//! Wire format:
//!   HEADER: magic "KBND" (4B) + version u8 + flags u8 + entry_count u32 BE
//!   ENTRY (full):  0x01 + kappa_len u16 BE + kappa + content_len u64 BE + content
//!   ENTRY (delta): 0x02 + kappa_len u16 BE + kappa + base_len u16 BE + base_kappa
//!                  + delta_len u64 BE + delta_instructions
//!   TRAILER: SHA-256 of all preceding bytes (32B)

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::delta;
use crate::kappa::verify_kappa;
use crate::store::StoreError;

const MAGIC: &[u8; 4] = b"KBND";
const VERSION: u8 = 1;
const ENTRY_TYPE_FULL: u8 = 0x01;
const ENTRY_TYPE_DELTA: u8 = 0x02;
const FLAG_HAS_DELTAS: u8 = 0x01;
const DELTA_WINDOW_SIZE: usize = 10;
/// Maximum cumulative resolved content bytes during decode (256 MiB).
const DECODE_MAX_BYTES: usize = 268_435_456;

/// A resolved base resolver type alias.
type BaseResolver<'a> = Option<&'a dyn Fn(&str) -> Option<Vec<u8>>>;

/// Encode a bundle from a list of (kappa, content) pairs.
pub fn encode(objects: &[(&str, &[u8])], use_deltas: bool) -> Vec<u8> {
    if !use_deltas || objects.len() < 2 {
        return encode_full_only(objects);
    }

    // Sort by size descending for sliding window delta selection
    let mut indexed: Vec<(usize, &str, &[u8])> = objects
        .iter()
        .enumerate()
        .map(|(i, (k, c))| (i, *k, *c))
        .collect();
    indexed.sort_by(|a, b| b.2.len().cmp(&a.2.len()));

    struct EntryPlan<'a> {
        kappa: &'a str,
        content: &'a [u8],
        delta_base: Option<(usize, Vec<u8>)>,
    }
    let mut plans: Vec<EntryPlan<'_>> = Vec::with_capacity(indexed.len());
    for (idx, &(_, kappa, content)) in indexed.iter().enumerate() {
        let window_start = idx.saturating_sub(DELTA_WINDOW_SIZE);
        let mut best: Option<(usize, Vec<u8>)> = None;
        for (ci, &(_, _, base)) in indexed.iter().enumerate().take(idx).skip(window_start) {
            if let Some(d) = delta::compute_delta(base, content) {
                if best.as_ref().is_none_or(|(_, prev)| d.len() < prev.len()) {
                    best = Some((ci, d));
                }
            }
        }
        plans.push(EntryPlan {
            kappa,
            content,
            delta_base: best,
        });
    }

    // Topological sort: bases before deltas
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
            if let Some((base_idx, _)) = &plans[i].delta_base {
                if emitted[*base_idx] {
                    order.push(i);
                    emitted[i] = true;
                    progress = true;
                }
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

    let has_any_delta = plans.iter().any(|p| p.delta_base.is_some());
    let flags = if has_any_delta { FLAG_HAS_DELTAS } else { 0x00 };

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(flags);
    out.extend_from_slice(&(plans.len() as u32).to_be_bytes());

    for &idx in &order {
        let plan = &plans[idx];
        if let Some((base_idx, ref delta_bytes)) = plan.delta_base {
            if emitted[base_idx] {
                out.push(ENTRY_TYPE_DELTA);
                let kb = plan.kappa.as_bytes();
                out.extend_from_slice(&(kb.len() as u16).to_be_bytes());
                out.extend_from_slice(kb);
                let bk = plans[base_idx].kappa.as_bytes();
                out.extend_from_slice(&(bk.len() as u16).to_be_bytes());
                out.extend_from_slice(bk);
                out.extend_from_slice(&(delta_bytes.len() as u64).to_be_bytes());
                out.extend_from_slice(delta_bytes);
                continue;
            }
        }
        out.push(ENTRY_TYPE_FULL);
        let kb = plan.kappa.as_bytes();
        out.extend_from_slice(&(kb.len() as u16).to_be_bytes());
        out.extend_from_slice(kb);
        out.extend_from_slice(&(plan.content.len() as u64).to_be_bytes());
        out.extend_from_slice(plan.content);
    }

    let hash = Sha256::digest(&out);
    out.extend_from_slice(&hash);
    out
}

fn encode_full_only(objects: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(0x00);
    out.extend_from_slice(&(objects.len() as u32).to_be_bytes());
    for (kappa, content) in objects {
        out.push(ENTRY_TYPE_FULL);
        let kb = kappa.as_bytes();
        out.extend_from_slice(&(kb.len() as u16).to_be_bytes());
        out.extend_from_slice(kb);
        out.extend_from_slice(&(content.len() as u64).to_be_bytes());
        out.extend_from_slice(content);
    }
    let hash = Sha256::digest(&out);
    out.extend_from_slice(&hash);
    out
}

/// A parsed bundle entry.
pub struct BundleEntry {
    pub kappa: String,
    pub content: Vec<u8>,
}

/// Decode and verify a bundle.
pub fn decode(data: &[u8], resolve_base: BaseResolver<'_>) -> Result<Vec<BundleEntry>, StoreError> {
    if data.len() < 10 + 32 {
        return Err(StoreError::BundleTruncated("header+trailer"));
    }

    let payload = &data[..data.len() - 32];
    let trailer = &data[data.len() - 32..];
    if Sha256::digest(payload).as_slice() != trailer {
        return Err(StoreError::BundleTrailerMismatch);
    }

    if &data[..4] != MAGIC {
        return Err(StoreError::Conflict("bad bundle magic".into()));
    }
    if data[4] != VERSION {
        return Err(StoreError::Conflict("unsupported bundle version".into()));
    }
    let flags = data[5];
    let entry_count = u32::from_be_bytes([data[6], data[7], data[8], data[9]]) as usize;

    let mut pos = 10;
    let mut entries = Vec::with_capacity(entry_count);
    let mut index: HashMap<String, Vec<u8>> = HashMap::new();
    let mut total_bytes: usize = 0;

    for _ in 0..entry_count {
        if pos >= payload.len() {
            return Err(StoreError::BundleTruncated("entry"));
        }
        let entry_type = payload[pos];
        pos += 1;

        match entry_type {
            ENTRY_TYPE_FULL => {
                let (kappa, content) = parse_full_entry(payload, &mut pos)?;
                total_bytes = total_bytes.saturating_add(content.len());
                if total_bytes > DECODE_MAX_BYTES {
                    return Err(StoreError::BundleDecodeLimitExceeded);
                }
                verify_entry_kappa(&kappa, &content)?;
                index.insert(kappa.clone(), content.clone());
                entries.push(BundleEntry { kappa, content });
            }
            ENTRY_TYPE_DELTA => {
                if flags & FLAG_HAS_DELTAS == 0 {
                    return Err(StoreError::BundleDeltaInNoDeltaBundle);
                }
                let (kappa, base_kappa, delta_bytes) = parse_delta_entry(payload, &mut pos)?;
                let base = index
                    .get(&base_kappa)
                    .cloned()
                    .or_else(|| resolve_base.as_ref().and_then(|f| f(&base_kappa)))
                    .ok_or(StoreError::DeltaUnresolvableBase(base_kappa))?;
                let content = delta::apply_delta(&base, &delta_bytes)?;
                total_bytes = total_bytes.saturating_add(content.len());
                if total_bytes > DECODE_MAX_BYTES {
                    return Err(StoreError::BundleDecodeLimitExceeded);
                }
                verify_entry_kappa(&kappa, &content)?;
                index.insert(kappa.clone(), content.clone());
                entries.push(BundleEntry { kappa, content });
            }
            t => return Err(StoreError::BundleUnsupportedEntryType(t)),
        }
    }

    Ok(entries)
}

fn parse_full_entry(p: &[u8], pos: &mut usize) -> Result<(String, Vec<u8>), StoreError> {
    let kappa = parse_kappa_field(p, pos)?;
    let content = parse_content_field(p, pos)?;
    Ok((kappa, content))
}

fn parse_delta_entry(p: &[u8], pos: &mut usize) -> Result<(String, String, Vec<u8>), StoreError> {
    let kappa = parse_kappa_field(p, pos)?;
    let base_kappa = parse_kappa_field(p, pos)?;
    let delta_bytes = parse_content_field(p, pos)?;
    Ok((kappa, base_kappa, delta_bytes))
}

fn parse_kappa_field(p: &[u8], pos: &mut usize) -> Result<String, StoreError> {
    if *pos + 2 > p.len() {
        return Err(StoreError::BundleTruncated("kappa length"));
    }
    let kl = u16::from_be_bytes([p[*pos], p[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + kl > p.len() {
        return Err(StoreError::BundleTruncated("kappa"));
    }
    let k = std::str::from_utf8(&p[*pos..*pos + kl])
        .map_err(|_| StoreError::Conflict("kappa not UTF-8".into()))?
        .to_string();
    *pos += kl;
    Ok(k)
}

fn parse_content_field(p: &[u8], pos: &mut usize) -> Result<Vec<u8>, StoreError> {
    if *pos + 8 > p.len() {
        return Err(StoreError::BundleTruncated("content length"));
    }
    let cl = u64::from_be_bytes([
        p[*pos],
        p[*pos + 1],
        p[*pos + 2],
        p[*pos + 3],
        p[*pos + 4],
        p[*pos + 5],
        p[*pos + 6],
        p[*pos + 7],
    ]) as usize;
    *pos += 8;
    if *pos + cl > p.len() {
        return Err(StoreError::BundleTruncated("content"));
    }
    let c = p[*pos..*pos + cl].to_vec();
    *pos += cl;
    Ok(c)
}

fn verify_entry_kappa(kappa: &str, content: &[u8]) -> Result<(), StoreError> {
    match verify_kappa(kappa, content) {
        Ok(true) => Ok(()),
        Ok(false) => Err(StoreError::BundleKappaMismatch(kappa.to_string())),
        Err(e) => Err(StoreError::Conflict(format!("bundle kappa invalid: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kappa::KappaLabel;

    #[test]
    fn encode_decode_roundtrip() {
        let ca = b"bundle-test-alpha";
        let cb = b"bundle-test-beta";
        let ka = KappaLabel::sha256(ca);
        let kb = KappaLabel::sha256(cb);
        let bundle = encode(
            &[(ka.as_str(), ca.as_slice()), (kb.as_str(), cb.as_slice())],
            false,
        );
        let entries = decode(&bundle, None).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].content, ca);
        assert_eq!(entries[1].content, cb);
    }

    #[test]
    fn decode_rejects_corrupted_trailer() {
        let c = b"corruption-test";
        let k = KappaLabel::sha256(c);
        let mut b = encode(&[(k.as_str(), c.as_slice())], false);
        let last = b.len() - 1;
        b[last] ^= 0xFF;
        assert!(matches!(
            decode(&b, None),
            Err(StoreError::BundleTrailerMismatch)
        ));
    }

    #[test]
    fn decode_rejects_kappa_mismatch() {
        let k = KappaLabel::sha256(b"mismatch-test");
        let b = encode(&[(k.as_str(), b"different content")], false);
        assert!(matches!(
            decode(&b, None),
            Err(StoreError::BundleKappaMismatch(_))
        ));
    }

    #[test]
    fn encode_empty_bundle() {
        let b = encode(&[], false);
        assert!(decode(&b, None).unwrap().is_empty());
    }

    #[test]
    fn header_structure() {
        let b = encode(&[], false);
        assert_eq!(&b[..4], b"KBND");
        assert_eq!(b[4], 1);
        assert_eq!(b[5], 0);
        assert_eq!(u32::from_be_bytes([b[6], b[7], b[8], b[9]]), 0);
    }

    #[test]
    fn encode_decode_with_deltas_roundtrip() {
        let base = b"line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\n";
        let var1 = b"line1\nline2-modified\nline3\nline4\nline5\nline6\nline7\nline8\n";
        let var2 = b"line1\nline2\nline3\nline4-changed\nline5\nline6\nline7\nline8\n";
        let kb = KappaLabel::sha256(base);
        let k1 = KappaLabel::sha256(var1);
        let k2 = KappaLabel::sha256(var2);
        let bundle = encode(
            &[
                (kb.as_str(), base.as_slice()),
                (k1.as_str(), var1.as_slice()),
                (k2.as_str(), var2.as_slice()),
            ],
            true,
        );
        let entries = decode(&bundle, None).unwrap();
        assert_eq!(entries.len(), 3);
        let mut found = std::collections::HashSet::new();
        for e in &entries {
            found.insert(e.kappa.clone());
            if e.kappa == kb.as_str() {
                assert_eq!(e.content, base);
            }
            if e.kappa == k1.as_str() {
                assert_eq!(e.content, var1);
            }
            if e.kappa == k2.as_str() {
                assert_eq!(e.content, var2);
            }
        }
        assert!(found.contains(kb.as_str()));
        assert!(found.contains(k1.as_str()));
        assert!(found.contains(k2.as_str()));
    }

    #[test]
    fn delta_in_no_delta_bundle_rejected() {
        let c = b"delta-flag-test-content-pad!";
        let k = KappaLabel::sha256(c);
        let mut b = Vec::new();
        b.extend_from_slice(MAGIC);
        b.push(VERSION);
        b.push(0x00); // flags: NO deltas
        b.extend_from_slice(&1u32.to_be_bytes());
        b.push(ENTRY_TYPE_DELTA);
        let kb = k.as_str().as_bytes();
        b.extend_from_slice(&(kb.len() as u16).to_be_bytes());
        b.extend_from_slice(kb);
        b.extend_from_slice(&(kb.len() as u16).to_be_bytes());
        b.extend_from_slice(kb);
        b.extend_from_slice(&0u64.to_be_bytes());
        let hash = Sha256::digest(&b);
        b.extend_from_slice(&hash);
        assert!(matches!(
            decode(&b, None),
            Err(StoreError::BundleDeltaInNoDeltaBundle)
        ));
    }
}
