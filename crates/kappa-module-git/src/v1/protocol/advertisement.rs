use std::io::Write;

use gix_packetline::blocking_io::encode;

use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::blob::BlobStore;
use kappa_store::traits::tag::TagStore;

use crate::envelope;
use crate::refs;

use super::ProtocolError;

/// Write a ref advertisement for upload-pack or receive-pack.
///
/// `capabilities` is the ordered list of capability strings the server
/// advertises. The caller constructs this from server configuration.
pub fn write_ref_advertisement<W: Write, S: TagStore + BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    service: &str,
    capabilities: &[&str],
    object_hash: gix_hash::Kind,
    mut out: W,
) -> Result<(), ProtocolError> {
    let service_line = format!("# service={}", service);
    encode::text_to_write(service_line.as_bytes(), &mut out)?;
    encode::flush_to_write(&mut out)?;

    let all_refs = refs::list_refs(store, namespace, "")?;
    let head_target = refs::resolve_ref(store, namespace, "HEAD")?;

    let caps_str = capabilities.join(" ");

    if all_refs.is_empty() && head_target.is_none() {
        let zero_id = "0".repeat(object_hash.len_in_bytes() * 2);
        let line = format!("{} capabilities^{{}}\0{}\n", zero_id, caps_str);
        encode::data_to_write(line.as_bytes(), &mut out)?;
    } else {
        let mut first = true;
        if let Some(ref target) = head_target {
            let target_label = target.to_string();
            let oid = envelope::kappa_to_hex_oid(&target_label);
            let line = if first {
                first = false;
                format!("{} HEAD\0{}\n", oid, caps_str)
            } else {
                format!("{} HEAD\n", oid)
            };
            encode::data_to_write(line.as_bytes(), &mut out)?;
        }

        for (ref_name, ref_value) in &all_refs {
            if ref_value.starts_with("ref: ") {
                continue;
            }
            let oid = envelope::kappa_to_hex_oid(ref_value);
            let line = if first {
                first = false;
                format!("{} {}\0{}\n", oid, ref_name, caps_str)
            } else {
                format!("{} {}\n", oid, ref_name)
            };
            encode::data_to_write(line.as_bytes(), &mut out)?;

            if let Some(peeled_oid) = peel_tag(store, namespace, ref_name, ref_value) {
                let peeled_line = format!("{} {}^{{}}\n", peeled_oid, ref_name);
                encode::data_to_write(peeled_line.as_bytes(), &mut out)?;
            }
        }
    }

    encode::flush_to_write(&mut out)?;
    Ok(())
}

/// Write a protocol v2 capability advertisement.
///
/// `capabilities` is the ordered list of v2 capability lines.
/// Each entry becomes one pkt-line with a trailing newline.
pub fn write_v2_capability_advertisement<W: Write>(
    capabilities: &[&str],
    mut out: W,
) -> Result<(), ProtocolError> {
    encode::data_to_write(b"version 2\n", &mut out)?;
    for cap in capabilities {
        let line = format!("{}\n", cap);
        encode::data_to_write(line.as_bytes(), &mut out)?;
    }
    encode::flush_to_write(&mut out)?;
    Ok(())
}

/// Build the default v1 capability list for a given hash algorithm.
pub fn default_v1_capabilities(object_hash: gix_hash::Kind) -> Vec<String> {
    let object_format = match object_hash {
        gix_hash::Kind::Sha256 => "object-format=sha256",
        _ => "object-format=sha1",
    };
    vec![
        "multi_ack_detailed".into(),
        "no-done".into(),
        "side-band-64k".into(),
        "thin-pack".into(),
        "ofs-delta".into(),
        "shallow".into(),
        "filter".into(),
        "report-status-v2".into(),
        object_format.into(),
        format!("agent=kappa-registry/{}", env!("CARGO_PKG_VERSION")),
    ]
}

/// Build the default v2 capability list for a given hash algorithm.
pub fn default_v2_capabilities(object_hash: gix_hash::Kind) -> Vec<String> {
    let object_format = match object_hash {
        gix_hash::Kind::Sha256 => "object-format=sha256",
        _ => "object-format=sha1",
    };
    vec![
        format!("agent=kappa-registry/{}", env!("CARGO_PKG_VERSION")),
        "ls-refs".into(),
        "fetch=shallow filter".into(),
        object_format.into(),
    ]
}

fn peel_tag<S: TagStore + BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    ref_name: &str,
    ref_value: &str,
) -> Option<String> {
    if !ref_name.starts_with("refs/tags/") {
        return None;
    }
    let kappa = Kappa::parse(ref_value).ok()?;
    let envelope_bytes = store.blob_get_in(namespace, &kappa).ok()?;
    let (kind, content) = envelope::unwrap(&envelope_bytes).ok()?;
    if kind != gix_object::Kind::Tag {
        return None;
    }
    content
        .split(|&b| b == b'\n')
        .find_map(|line| line.strip_prefix(b"object "))
        .and_then(|rest| std::str::from_utf8(rest).ok())
        .map(|s| s.trim().to_string())
}
