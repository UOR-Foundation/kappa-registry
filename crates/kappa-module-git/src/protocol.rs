//! Git smart HTTP protocol handlers.
//!
//! Implements ref advertisement, upload-pack (clone/fetch), and
//! receive-pack (push) over pkt-line framing. Uses gix-packetline
//! for wire format. Protocol-agnostic: takes Read/Write, not HTTP types.
//!
//! URL paths follow standard Git smart HTTP:
//!   GET  /{repo}/info/refs?service=git-upload-pack
//!   POST /{repo}/git-upload-pack
//!   GET  /{repo}/info/refs?service=git-receive-pack
//!   POST /{repo}/git-receive-pack

use std::collections::HashSet;
use std::io::{self, BufReader, Read, Write};

use gix_packetline::blocking_io::encode;
use gix_packetline::PacketLineRef;

use kappa_core::store::KappaStore;
use kappa_core::types::NamespaceRef;

use crate::envelope;
use crate::ingest;
use crate::packgen;
use crate::refs;

/// Fetch options parsed from the client's want/have lines.
#[derive(Debug, Default)]
struct FetchOptions {
    /// Maximum commit depth from each want root. None = unlimited.
    deepen: Option<u32>,
    /// Client's existing shallow boundary OIDs (hex, no prefix).
    client_shallows: HashSet<String>,
    /// Object filter specification. None = no filter (send everything).
    filter: Option<FilterSpec>,
}

/// Object filter for partial clone.
#[derive(Debug, Clone)]
enum FilterSpec {
    /// blob:none -- exclude all blobs from the pack.
    BlobNone,
    /// blob:limit=N -- exclude blobs larger than N bytes.
    BlobLimit(u64),
}

/// Errors from protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("ref error: {0}")]
    Ref(#[from] refs::RefError),
    #[error("ingest error: {0}")]
    Ingest(#[from] ingest::IngestError),
    #[error("pack gen error: {0}")]
    PackGen(#[from] packgen::PackGenError),
    #[error("envelope error: {0}")]
    Envelope(#[from] envelope::EnvelopeError),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Return the kappa prefix string for a given hash kind.
fn hash_prefix(object_hash: gix_hash::Kind) -> &'static str {
    match object_hash {
        gix_hash::Kind::Sha1 => "sha1",
        gix_hash::Kind::Sha256 => "sha256",
        _ => "sha1",
    }
}

/// Build a kappa-label from a hex OID and hash kind.
fn oid_to_kappa_string(object_hash: gix_hash::Kind, hex_oid: &str) -> String {
    format!("{}:{}", hash_prefix(object_hash), hex_oid)
}

/// Write a ref advertisement for upload-pack or receive-pack.
///
/// Format: pkt-line encoded, one ref per line, capabilities on first line.
/// Terminated by flush packet.
pub fn write_ref_advertisement<W: Write>(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    service: &str,
    mut out: W,
    object_hash: gix_hash::Kind,
) -> Result<(), ProtocolError> {
    // text_to_write appends \n, so do not include one in the string
    let service_line = format!("# service={}", service);
    encode::text_to_write(service_line.as_bytes(), &mut out)?;
    encode::flush_to_write(&mut out)?;

    let all_refs = refs::list_refs(store, namespace, "")?;
    let head_target = refs::resolve_ref(store, namespace, "HEAD")?;

    let object_format = match object_hash {
        gix_hash::Kind::Sha256 => "sha256",
        _ => "sha1",
    };
    let capabilities = format!(
        "multi_ack_detailed no-done side-band-64k thin-pack ofs-delta shallow filter report-status-v2 object-format={} agent=kappa-registry",
        object_format,
    );

    if all_refs.is_empty() && head_target.is_none() {
        let zero_id = "0".repeat(object_hash.len_in_bytes() * 2);
        let line = format!("{} capabilities^{{}}\0{}\n", zero_id, capabilities);
        encode::data_to_write(line.as_bytes(), &mut out)?;
    } else {
        let mut first = true;
        if let Some(ref target) = head_target {
            let oid = kappa_to_hex_oid(target);
            let line = if first {
                first = false;
                format!("{} HEAD\0{}\n", oid, capabilities)
            } else {
                format!("{} HEAD\n", oid)
            };
            encode::data_to_write(line.as_bytes(), &mut out)?;
        }

        for (ref_name, ref_value) in &all_refs {
            if ref_value.starts_with("ref: ") { continue; }
            let oid = kappa_to_hex_oid(ref_value);
            let line = if first {
                first = false;
                format!("{} {}\0{}\n", oid, ref_name, capabilities)
            } else {
                format!("{} {}\n", oid, ref_name)
            };
            encode::data_to_write(line.as_bytes(), &mut out)?;

            if let Some(peeled_oid) = peel_tag(store, ref_name, ref_value) {
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
/// Sent in response to `GET /info/refs?service=git-upload-pack` when the
/// client sends `Git-Protocol: version=2`. Instead of listing refs, we
/// advertise capabilities. The client then uses `command=ls-refs` or
/// `command=fetch` via POST.
pub fn write_v2_capability_advertisement<W: Write>(
    mut out: W,
    object_hash: gix_hash::Kind,
) -> Result<(), ProtocolError> {
    encode::data_to_write(b"version 2\n", &mut out)?;
    encode::data_to_write(b"agent=kappa-registry\n", &mut out)?;
    encode::data_to_write(b"ls-refs\n", &mut out)?;
    encode::data_to_write(b"fetch=shallow filter\n", &mut out)?;
    let object_format = match object_hash {
        gix_hash::Kind::Sha256 => "object-format=sha256\n",
        _ => "object-format=sha1\n",
    };
    encode::data_to_write(object_format.as_bytes(), &mut out)?;
    encode::flush_to_write(&mut out)?;
    Ok(())
}

/// Handle a protocol v2 upload-pack POST request.
///
/// Dispatches by the first pkt-line `command=...`:
/// - `ls-refs`: list refs matching optional ref-prefix arguments
/// - `fetch`: full fetch with want/have negotiation
pub fn handle_v2_upload_pack<R: Read, W: Write>(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    request: R,
    mut response: W,
    object_hash: gix_hash::Kind,
) -> Result<(), ProtocolError> {
    let mut reader = gix_packetline::blocking_io::StreamingPeekableIter::new(
        BufReader::new(request),
        &[PacketLineRef::Flush, PacketLineRef::Delimiter],
        false,
    );

    // Read the command line
    let command = {
        let mut cmd = String::new();
        if let Some(line_result) = reader.read_line() {
            let line = line_result
                .map_err(|e| ProtocolError::Protocol(e.to_string()))?
                .map_err(|e| ProtocolError::Protocol(format!("decode: {:?}", e)))?;
            if let Some(data) = line.as_slice() {
                cmd = std::str::from_utf8(data)
                    .map_err(|_| ProtocolError::Protocol("non-utf8 command".into()))?
                    .trim()
                    .to_string();
            }
        }
        cmd
    };

    if command.starts_with("command=ls-refs") {
        // Read arguments until delimiter/flush
        let mut ref_prefixes: Vec<String> = Vec::new();
        let mut symrefs = false;
        let mut peel = false;

        while let Some(line_result) = reader.read_line() {
            let line = line_result
                .map_err(|e| ProtocolError::Protocol(e.to_string()))?
                .map_err(|e| ProtocolError::Protocol(format!("decode: {:?}", e)))?;
            if let Some(data) = line.as_slice() {
                let text = std::str::from_utf8(data)
                    .map_err(|_| ProtocolError::Protocol("non-utf8 arg".into()))?
                    .trim();
                if let Some(prefix) = text.strip_prefix("ref-prefix ") {
                    ref_prefixes.push(prefix.to_string());
                } else if text == "symrefs" {
                    symrefs = true;
                } else if text == "peel" {
                    peel = true;
                }
            }
        }

        // List refs matching prefixes
        let all_refs = refs::list_refs(store, namespace, "")?;
        let head_target = refs::resolve_ref(store, namespace, "HEAD")?;

        // HEAD
        if let Some(ref target) = head_target {
            let matches = ref_prefixes.is_empty() || ref_prefixes.iter().any(|p| "HEAD".starts_with(p.as_str()));
            if matches {
                let oid = kappa_to_hex_oid(target);
                let mut line = format!("{} HEAD", oid);
                if symrefs {
                    // Check if HEAD is a symbolic ref
                    if let Ok(Some(sym_target)) = refs::resolve_ref(store, namespace, "HEAD") {
                        let _ = sym_target; // HEAD resolves to the target OID, not the symref
                        // To get the symref target name, check the raw tag value
                        if let Ok(entry) = store.tag_get(namespace, "HEAD") {
                            if entry.kappa.starts_with("ref: ") {
                                line.push_str(&format!(" symref-target:{}", &entry.kappa[5..]));
                            }
                        }
                    }
                }
                line.push('\n');
                encode::data_to_write(line.as_bytes(), &mut response)?;
            }
        }

        for (ref_name, ref_value) in &all_refs {
            if ref_value.starts_with("ref: ") { continue; }
            let matches = ref_prefixes.is_empty() || ref_prefixes.iter().any(|p| ref_name.starts_with(p.as_str()));
            if !matches { continue; }
            let oid = kappa_to_hex_oid(ref_value);
            let mut line = format!("{} {}", oid, ref_name);
            if peel {
                if let Some(peeled) = peel_tag(store, ref_name, ref_value) {
                    line.push_str(&format!(" peeled:{}", peeled));
                }
            }
            line.push('\n');
            encode::data_to_write(line.as_bytes(), &mut response)?;
        }

        encode::flush_to_write(&mut response)?;
        Ok(())
    } else if command.starts_with("command=fetch") {
        // V2 fetch: parse arguments, then want/have/done
        // The argument section ends at a delimiter, then want/have lines follow
        let mut fetch_opts = FetchOptions::default();
        let mut no_progress = false;

        // Read fetch arguments until delimiter
        while let Some(line_result) = reader.read_line() {
            let line = line_result
                .map_err(|e| ProtocolError::Protocol(e.to_string()))?
                .map_err(|e| ProtocolError::Protocol(format!("decode: {:?}", e)))?;
            if let Some(data) = line.as_slice() {
                let text = std::str::from_utf8(data)
                    .map_err(|_| ProtocolError::Protocol("non-utf8 arg".into()))?
                    .trim();
                if text == "no-progress" {
                    no_progress = true;
                } else if let Some(rest) = text.strip_prefix("deepen ") {
                    if let Ok(d) = rest.parse::<u32>() { fetch_opts.deepen = Some(d); }
                } else if let Some(rest) = text.strip_prefix("filter ") {
                    if rest == "blob:none" {
                        fetch_opts.filter = Some(FilterSpec::BlobNone);
                    } else if let Some(lim) = rest.strip_prefix("blob:limit=") {
                        if let Ok(l) = lim.parse::<u64>() { fetch_opts.filter = Some(FilterSpec::BlobLimit(l)); }
                    }
                }
            }
        }
        reader.reset_with(&[PacketLineRef::Flush]);

        // Read want/have/done lines.
        // "done" terminates the section -- stop reading after it.
        // On HTTP stateless transport, "done" is always present and
        // "ready" is always sent in the acknowledgments (no multi-round).
        let mut wants: Vec<String> = Vec::new();
        let mut haves: HashSet<String> = HashSet::new();

        while let Some(line_result) = reader.read_line() {
            let line = line_result
                .map_err(|e| ProtocolError::Protocol(e.to_string()))?
                .map_err(|e| ProtocolError::Protocol(format!("decode: {:?}", e)))?;
            if let Some(data) = line.as_slice() {
                let text = std::str::from_utf8(data)
                    .map_err(|_| ProtocolError::Protocol("non-utf8".into()))?
                    .trim();
                if let Some(rest) = text.strip_prefix("want ") {
                    wants.push(rest.split_whitespace().next().unwrap_or(rest).to_string());
                } else if let Some(rest) = text.strip_prefix("have ") {
                    haves.insert(rest.trim().to_string());
                } else if text == "done" {
                    break;
                } else if let Some(rest) = text.strip_prefix("shallow ") {
                    fetch_opts.client_shallows.insert(rest.trim().to_string());
                }
            }
        }

        if wants.is_empty() {
            encode::data_to_write(b"acknowledgments\n", &mut response)?;
            encode::data_to_write(b"NAK\n", &mut response)?;
            encode::flush_to_write(&mut response)?;
            return Ok(());
        }

        // Build the common set from have lines
        let mut common: HashSet<String> = HashSet::new();
        for have_oid in &haves {
            let kappa = oid_to_kappa_string(object_hash, have_oid);
            if store.blob_exists(&kappa).unwrap_or(false) {
                common.insert(have_oid.clone());
            }
        }

        // Acknowledgments section: only sent when the client sent have lines.
        // For a fresh clone (no haves, client sends done), skip straight to
        // packfile. Git v2 spec: "If the client has not sent done, the server
        // MUST send an acknowledgments section."
        if !haves.is_empty() {
            encode::data_to_write(b"acknowledgments\n", &mut response)?;
            for have_oid in &haves {
                if common.contains(have_oid) {
                    let ack = format!("ACK {}\n", have_oid);
                    encode::data_to_write(ack.as_bytes(), &mut response)?;
                }
            }
            if common.is_empty() {
                encode::data_to_write(b"NAK\n", &mut response)?;
            }
            // HTTP is stateless: each POST is a complete round. The server
            // MUST send "ready" to indicate it will send a packfile in this
            // response. Without "ready", the client expects the response to
            // end (more rounds needed) and rejects the packfile section.
            encode::data_to_write(b"ready\n", &mut response)?;
            encode::delim_to_write(&mut response)?;
        }

        // Packfile section
        encode::data_to_write(b"packfile\n", &mut response)?;

        let (need_kappas, new_shallows) = compute_need_set(
            store, namespace, &wants, &common, object_hash, &fetch_opts,
        );

        for shallow_oid in &new_shallows {
            let line = format!("shallow {}\n", shallow_oid);
            let mut sideband = Vec::with_capacity(1 + line.len());
            sideband.push(1);
            sideband.extend_from_slice(line.as_bytes());
            encode::data_to_write(&sideband, &mut response)?;
        }

        let name_hints = std::collections::HashMap::new();
        let total = need_kappas.len() as u32;
        let progress_cb = if no_progress {
            None
        } else {
            Some(Box::new(move |written: u32, _total: u32| {
                let _ = (written, total);
            }) as Box<dyn Fn(u32, u32)>)
        };
        let mut pack_buf = Vec::new();
        packgen::generate_pack_sorted(
            store, &need_kappas, object_hash, &name_hints,
            progress_cb.as_ref().map(|cb| cb.as_ref()),
            &mut pack_buf,
        )?;

        // Send progress on channel 2 before pack data
        if !no_progress {
            let done_msg = format!("Compressing objects: 100% ({}/{}), done.\n", total, total);
            let mut progress_pkt = Vec::with_capacity(1 + done_msg.len());
            progress_pkt.push(2);
            progress_pkt.extend_from_slice(done_msg.as_bytes());
            encode::data_to_write(&progress_pkt, &mut response)?;
        }

        let chunk_size = 65519 - 1;
        for chunk in pack_buf.chunks(chunk_size) {
            let mut sideband = Vec::with_capacity(1 + chunk.len());
            sideband.push(1);
            sideband.extend_from_slice(chunk);
            encode::data_to_write(&sideband, &mut response)?;
        }

        encode::flush_to_write(&mut response)?;
        Ok(())
    } else {
        Err(ProtocolError::Protocol(format!("unknown v2 command: {}", command)))
    }
}

/// Handle a git-upload-pack v1 request (clone/fetch).
pub fn handle_upload_pack<R: Read, W: Write>(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    request: R,
    mut response: W,
    object_hash: gix_hash::Kind,
) -> Result<(), ProtocolError> {
    let mut reader = gix_packetline::blocking_io::StreamingPeekableIter::new(
        BufReader::new(request),
        &[PacketLineRef::Flush],
        false,
    );

    let mut wants: Vec<String> = Vec::new();
    let mut haves: HashSet<String> = HashSet::new();
    let mut fetch_opts = FetchOptions::default();

    while let Some(line_result) = reader.read_line() {
        let line = line_result
            .map_err(|e| ProtocolError::Protocol(e.to_string()))?
            .map_err(|e| ProtocolError::Protocol(format!("decode: {:?}", e)))?;

        if let Some(data) = line.as_slice() {
            let text = std::str::from_utf8(data)
                .map_err(|_| ProtocolError::Protocol("non-utf8 want line".into()))?
                .trim();

            if let Some(rest) = text.strip_prefix("want ") {
                let oid_hex = rest.split_whitespace().next().unwrap_or(rest);
                wants.push(oid_hex.to_string());
            } else if let Some(rest) = text.strip_prefix("deepen ") {
                if let Ok(depth) = rest.trim().parse::<u32>() {
                    fetch_opts.deepen = Some(depth);
                }
            } else if let Some(rest) = text.strip_prefix("shallow ") {
                fetch_opts.client_shallows.insert(rest.trim().to_string());
            } else if let Some(rest) = text.strip_prefix("filter ") {
                let spec = rest.trim();
                if spec == "blob:none" {
                    fetch_opts.filter = Some(FilterSpec::BlobNone);
                } else if let Some(limit_str) = spec.strip_prefix("blob:limit=") {
                    if let Ok(limit) = limit_str.parse::<u64>() {
                        fetch_opts.filter = Some(FilterSpec::BlobLimit(limit));
                    }
                }
            }
        }
    }
    reader.reset_with(&[PacketLineRef::Flush]);

    let mut done = false;
    while let Some(line_result) = reader.read_line() {
        let line = line_result
            .map_err(|e| ProtocolError::Protocol(e.to_string()))?
            .map_err(|e| ProtocolError::Protocol(format!("decode: {:?}", e)))?;

        if let Some(data) = line.as_slice() {
            let text = std::str::from_utf8(data)
                .map_err(|_| ProtocolError::Protocol("non-utf8 have line".into()))?
                .trim();

            if let Some(rest) = text.strip_prefix("have ") {
                let oid_hex = rest.trim();
                haves.insert(oid_hex.to_string());
            } else if text == "done" {
                done = true;
                break;
            }
        }
    }

    if wants.is_empty() {
        encode::data_to_write(b"NAK\n", &mut response)?;
        encode::flush_to_write(&mut response)?;
        return Ok(());
    }

    // ACK common objects -- use object_hash for kappa construction
    let mut common: HashSet<String> = HashSet::new();
    for have_oid in &haves {
        let kappa = oid_to_kappa_string(object_hash, have_oid);
        if store.blob_exists(&kappa).unwrap_or(false) {
            common.insert(have_oid.clone());
        }
    }

    if common.is_empty() {
        encode::data_to_write(b"NAK\n", &mut response)?;
    } else {
        for ack_oid in &common {
            let ack_line = format!("ACK {} common\n", ack_oid);
            encode::data_to_write(ack_line.as_bytes(), &mut response)?;
        }
        if done {
            let first_common = common.iter().next().unwrap();
            let ack_line = format!("ACK {}\n", first_common);
            encode::data_to_write(ack_line.as_bytes(), &mut response)?;
        }
    }

    let (need_kappas, new_shallows) = compute_need_set(store, namespace, &wants, &common, object_hash, &fetch_opts);

    // Emit shallow lines for newly shallow commits
    for shallow_oid in &new_shallows {
        let line = format!("shallow {}\n", shallow_oid);
        encode::data_to_write(line.as_bytes(), &mut response)?;
    }

    // Emit unshallow for client-reported shallows that are now fully available
    for client_shallow in &fetch_opts.client_shallows {
        let kappa = oid_to_kappa_string(object_hash, client_shallow);
        if store.blob_exists(&kappa).unwrap_or(false) && !new_shallows.contains(client_shallow) {
            let line = format!("unshallow {}\n", client_shallow);
            encode::data_to_write(line.as_bytes(), &mut response)?;
        }
    }

    // Item 53: sorted pack with sliding-window delta compression
    // Item 54: progress reporting via side-band channel 2
    let name_hints = std::collections::HashMap::new();
    let total_objects = need_kappas.len() as u32;

    // Send counting progress before pack generation
    {
        let count_msg = format!("Counting objects: {}, done.\n", total_objects);
        let mut pkt = Vec::with_capacity(1 + count_msg.len());
        pkt.push(2);
        pkt.extend_from_slice(count_msg.as_bytes());
        encode::data_to_write(&pkt, &mut response)?;
    }

    let progress_messages: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let progress_ref = progress_messages.clone();
    let progress_cb = move |written: u32, total: u32| {
        let pct = if total > 0 { written * 100 / total } else { 0 };
        let msg = format!("Compressing objects: {}% ({}/{})\r", pct, written, total);
        progress_ref.lock().unwrap().push(msg);
    };

    let mut pack_buf = Vec::new();
    packgen::generate_pack_sorted(
        store, &need_kappas, object_hash, &name_hints,
        Some(&progress_cb), &mut pack_buf,
    )?;

    // Send accumulated progress messages on channel 2
    {
        let messages = progress_messages.lock().unwrap();
        for msg in messages.iter() {
            let mut pkt = Vec::with_capacity(1 + msg.len());
            pkt.push(2);
            pkt.extend_from_slice(msg.as_bytes());
            encode::data_to_write(&pkt, &mut response)?;
        }
    }
    // Send final completion message
    {
        let done_msg = format!("Compressing objects: 100% ({}/{}), done.\n", total_objects, total_objects);
        let mut pkt = Vec::with_capacity(1 + done_msg.len());
        pkt.push(2);
        pkt.extend_from_slice(done_msg.as_bytes());
        encode::data_to_write(&pkt, &mut response)?;
    }

    // Send pack data on channel 1
    let chunk_size = 65519 - 1;
    for chunk in pack_buf.chunks(chunk_size) {
        let mut sideband = Vec::with_capacity(1 + chunk.len());
        sideband.push(1);
        sideband.extend_from_slice(chunk);
        encode::data_to_write(&sideband, &mut response)?;
    }

    encode::flush_to_write(&mut response)?;

    Ok(())
}

/// Handle a git-receive-pack request (push).
pub fn handle_receive_pack<R: Read, W: Write>(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    request: R,
    mut response: W,
    object_hash: gix_hash::Kind,
) -> Result<(), ProtocolError> {
    let mut buf_reader = BufReader::new(request);

    struct RefUpdate {
        old_oid: String,
        new_oid: String,
        ref_name: String,
    }
    let mut updates: Vec<RefUpdate> = Vec::new();

    let mut reader = gix_packetline::blocking_io::StreamingPeekableIter::new(
        &mut buf_reader,
        &[PacketLineRef::Flush],
        false,
    );

    while let Some(line_result) = reader.read_line() {
        let line = line_result
            .map_err(|e| ProtocolError::Protocol(e.to_string()))?
            .map_err(|e| ProtocolError::Protocol(format!("decode: {:?}", e)))?;

        if let Some(data) = line.as_slice() {
            let text = std::str::from_utf8(data)
                .map_err(|_| ProtocolError::Protocol("non-utf8 ref update".into()))?
                .trim();

            let cmd = text.split('\0').next().unwrap_or(text);

            let parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.len() >= 3 {
                updates.push(RefUpdate {
                    old_oid: parts[0].to_string(),
                    new_oid: parts[1].to_string(),
                    ref_name: parts[2].to_string(),
                });
            }
        }
    }

    let inner_reader = reader.into_inner();
    let pack_result = ingest::ingest_pack(store, namespace, inner_reader, object_hash)?;

    tracing::info!(
        objects = pack_result.objects_ingested,
        dedup = pack_result.objects_deduplicated,
        "pack ingested"
    );

    // Item 56: Run pre-receive hook before ref updates.
    // If it rejects, all refs are rejected.
    let hook_updates: Vec<crate::hooks::RefUpdate> = updates.iter().map(|u| {
        crate::hooks::RefUpdate {
            old_oid: u.old_oid.clone(),
            new_oid: u.new_oid.clone(),
            ref_name: u.ref_name.clone(),
        }
    }).collect();

    let hook_rejected = match crate::hooks::run_pre_receive(store, namespace, &hook_updates, 30) {
        Ok(()) => None,
        Err(crate::hooks::HookError::Rejected(msg)) => Some(msg),
        Err(crate::hooks::HookError::Timeout(secs)) => Some(format!("hook timed out after {}s", secs)),
        Err(e) => Some(e.to_string()),
    };

    let zero_oid = "0".repeat(object_hash.len_in_bytes() * 2);
    let prefix = hash_prefix(object_hash);

    if let Some(ref rejection) = hook_rejected {
        // All refs rejected by pre-receive hook
        for update in &updates {
            let line = format!("ng {} pre-receive hook declined: {}\n", update.ref_name, rejection);
            encode::data_to_write(line.as_bytes(), &mut response)?;
        }
        encode::flush_to_write(&mut response)?;
        return Ok(());
    }

    let mut batch_updates: Vec<kappa_core::types::TagUpdate> = Vec::new();
    let mut deletes: Vec<String> = Vec::new();
    let mut ref_names_in_order: Vec<String> = Vec::new();

    for update in &updates {
        ref_names_in_order.push(update.ref_name.clone());
        if update.new_oid == zero_oid {
            deletes.push(update.ref_name.clone());
        } else {
            let new_kappa = format!("{}:{}", prefix, update.new_oid);
            let expected_version = if update.old_oid == zero_oid {
                Some(0)
            } else {
                match store.tag_get(namespace, &update.ref_name) {
                    Ok(entry) => Some(entry.version),
                    Err(_) => Some(0),
                }
            };
            batch_updates.push(kappa_core::types::TagUpdate {
                name: update.ref_name.clone(),
                kappa: new_kappa,
                expected_version,
            });
        }
    }

    let batch_result = if batch_updates.is_empty() {
        Ok(())
    } else {
        store.tag_set_batch(namespace, &batch_updates)
    };

    let mut delete_errors: Vec<(String, String)> = Vec::new();
    for ref_name in &deletes {
        if let Err(e) = refs::delete_ref(store, namespace, ref_name) {
            delete_errors.push((ref_name.clone(), e.to_string()));
        }
    }

    // report-status via side-band-64k.
    //
    // Git report-status format (inside side-band channel 1):
    //   pkt-line: "unpack ok\n"        (or "unpack <error>\n")
    //   pkt-line: "ok <ref>\n"         (per ref)
    //   pkt-line: "ng <ref> <reason>\n" (per failed ref)
    //   flush-pkt
    //
    // The side-band wrapping: each pkt-line is sent inside a side-band
    // channel 1 packet. The outer layer is pkt-line(\x01 + inner_pkt_line).
    // The inner pkt-line framing is preserved -- the client's side-band
    // demuxer extracts channel 1 data and feeds it to the report-status
    // parser which expects pkt-line encoded lines.

    // "unpack ok" pkt-line via side-band channel 1
    {
        let mut inner = Vec::new();
        encode::data_to_write(b"unpack ok\n", &mut inner)?;
        let mut sb = Vec::with_capacity(1 + inner.len());
        sb.push(1);
        sb.extend_from_slice(&inner);
        encode::data_to_write(&sb, &mut response)?;
    }

    // Per-ref status lines + report-status-v2 option lines via side-band channel 1
    for (i, ref_name) in ref_names_in_order.iter().enumerate() {
        let is_ok = if deletes.contains(ref_name) {
            delete_errors.iter().find(|(n, _)| n == ref_name).is_none()
        } else {
            batch_result.is_ok()
        };
        let status_line = if deletes.contains(ref_name) {
            if let Some((_, err)) = delete_errors.iter().find(|(n, _)| n == ref_name) {
                format!("ng {} {}\n", ref_name, err)
            } else {
                format!("ok {}\n", ref_name)
            }
        } else {
            match &batch_result {
                Ok(()) => format!("ok {}\n", ref_name),
                Err(e) => format!("ng {} {}\n", ref_name, e),
            }
        };

        // Status line as pkt-line inside side-band channel 1
        let mut inner = Vec::new();
        encode::data_to_write(status_line.as_bytes(), &mut inner)?;

        // report-status-v2 option lines (after each ok line)
        if is_ok {
            let update = &updates[i];
            encode::data_to_write(
                format!("option refname {}\n", ref_name).as_bytes(), &mut inner,
            )?;
            encode::data_to_write(
                format!("option old-oid {}\n", update.old_oid).as_bytes(), &mut inner,
            )?;
            encode::data_to_write(
                format!("option new-oid {}\n", update.new_oid).as_bytes(), &mut inner,
            )?;
            if update.old_oid != zero_oid && update.new_oid != zero_oid {
                let old_kappa = format!("{}:{}", prefix, update.old_oid);
                let new_reachable = walk_reachable(
                    store, vec![update.new_oid.clone()], object_hash,
                );
                if !new_reachable.contains(&old_kappa) {
                    encode::data_to_write(b"option forced-update\n", &mut inner)?;
                }
            }
        }

        // Send all inner pkt-lines as one side-band channel 1 packet
        let mut sb = Vec::with_capacity(1 + inner.len());
        sb.push(1);
        sb.extend_from_slice(&inner);
        encode::data_to_write(&sb, &mut response)?;
    }

    // Flush inside side-band channel 1
    {
        let mut inner = Vec::new();
        encode::flush_to_write(&mut inner)?;
        let mut sb = Vec::with_capacity(1 + inner.len());
        sb.push(1);
        sb.extend_from_slice(&inner);
        encode::data_to_write(&sb, &mut response)?;
    }

    // Outer flush
    encode::flush_to_write(&mut response)?;

    // Item 56: Spawn post-receive hook asynchronously
    crate::hooks::spawn_post_receive(store, namespace, &hook_updates, 30);

    Ok(())
}

/// Compute the set of objects the client needs.
///
/// Two walks: first walk from common OIDs collects all reachable objects
/// as "have". Second walk from wants collects objects NOT in "have".
///
/// Returns (needed_kappas, new_shallow_oids). When `deepen` is set,
/// commits at the depth boundary are included but their parents are not,
/// and the boundary commit OIDs are returned as new shallows. When
/// `filter` is BlobNone, blobs are excluded from the need set.
fn compute_need_set(
    store: &dyn KappaStore,
    _namespace: &NamespaceRef,
    wants: &[String],
    common: &HashSet<String>,
    object_hash: gix_hash::Kind,
    opts: &FetchOptions,
) -> (Vec<String>, HashSet<String>) {
    let prefix = hash_prefix(object_hash);
    let hash_len = object_hash.len_in_bytes();

    let have_set = walk_reachable(store, common.iter().cloned().collect(), object_hash);

    let mut needed: Vec<String> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut new_shallows: HashSet<String> = HashSet::new();
    // Track depth per kappa for shallow clone support
    let mut depth_map: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();

    for oid_hex in wants {
        let kappa = format!("{}:{}", prefix, oid_hex);
        if !have_set.contains(&kappa) && !visited.contains(&kappa) {
            depth_map.insert(kappa.clone(), 1);
            queue.push_back(kappa);
        }
    }

    while let Some(kappa) = queue.pop_front() {
        if visited.contains(&kappa) || have_set.contains(&kappa) {
            continue;
        }
        visited.insert(kappa.clone());

        let envelope_bytes = match store.blob_get(&kappa) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let (kind, _content) = match crate::envelope::unwrap(&envelope_bytes) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Filter: blob:none excludes blobs from the need set entirely.
        // The tree entry that references the blob is still included so
        // the client knows the blob exists for lazy fetch.
        if let Some(ref filter) = opts.filter {
            match filter {
                FilterSpec::BlobNone if kind == gix_object::Kind::Blob => continue,
                FilterSpec::BlobLimit(limit) if kind == gix_object::Kind::Blob => {
                    if _content.len() as u64 > *limit { continue; }
                }
                _ => {}
            }
        }

        needed.push(kappa.clone());

        let current_depth = depth_map.get(&kappa).copied().unwrap_or(0);

        // Depth limiting: for commits, check if we've reached the limit.
        // At the boundary, the commit IS included but its parents are NOT.
        // The commit becomes a shallow boundary.
        if kind == gix_object::Kind::Commit {
            if let Some(max_depth) = opts.deepen {
                if current_depth >= max_depth {
                    // This commit is at the boundary -- mark as shallow
                    let hex_oid = kappa_to_hex_oid(&kappa);
                    new_shallows.insert(hex_oid.to_string());
                    // Still walk tree children (blobs/trees) but NOT parent commits
                    for child_kappa in extract_children(&envelope_bytes, hash_len, prefix) {
                        // Only queue non-commit children (trees, blobs)
                        if !visited.contains(&child_kappa) && !have_set.contains(&child_kappa) {
                            // Check if child is a commit by looking at the first bytes
                            // Tree entries reference trees and blobs, not commits (except gitlinks).
                            // For simplicity, queue all tree children -- they won't be commits
                            // unless the tree contains a gitlink (mode 160000).
                            // The commit's "parent" lines are handled separately below.
                            if let Ok(child_bytes) = store.blob_get(&child_kappa) {
                                if let Ok((child_kind, _)) = crate::envelope::unwrap(&child_bytes) {
                                    if child_kind != gix_object::Kind::Commit {
                                        queue.push_back(child_kappa.clone());
                                        depth_map.insert(child_kappa, current_depth);
                                    }
                                }
                            }
                        }
                    }
                    continue; // Don't walk parents
                }
            }
        }

        for child_kappa in extract_children(&envelope_bytes, hash_len, prefix) {
            if !visited.contains(&child_kappa) && !have_set.contains(&child_kappa) {
                if !depth_map.contains_key(&child_kappa) {
                    // Commits increment depth, non-commits inherit parent's depth
                    depth_map.insert(child_kappa.clone(), current_depth + 1);
                }
                queue.push_back(child_kappa);
            }
        }
    }

    (needed, new_shallows)
}

/// Walk from a set of root hex OIDs and collect all reachable kappa-labels.
fn walk_reachable(
    store: &dyn KappaStore,
    roots: Vec<String>,
    object_hash: gix_hash::Kind,
) -> HashSet<String> {
    let prefix = hash_prefix(object_hash);
    let hash_len = object_hash.len_in_bytes();
    let mut reachable: HashSet<String> = HashSet::new();
    let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();

    for oid_hex in roots {
        let kappa = format!("{}:{}", prefix, oid_hex);
        queue.push_back(kappa);
    }

    while let Some(kappa) = queue.pop_front() {
        if reachable.contains(&kappa) { continue; }
        reachable.insert(kappa.clone());

        let envelope_bytes = match store.blob_get(&kappa) {
            Ok(b) => b,
            Err(_) => continue,
        };

        for child_kappa in extract_children(&envelope_bytes, hash_len, prefix) {
            if !reachable.contains(&child_kappa) {
                queue.push_back(child_kappa);
            }
        }
    }

    reachable
}

/// Extract child kappa-labels from a Git object envelope.
///
/// `hash_len` is the number of raw hash bytes per tree entry (20 for SHA-1,
/// 32 for SHA-256). `prefix` is the kappa prefix ("sha1" or "sha256").
fn extract_children(envelope_bytes: &[u8], hash_len: usize, prefix: &str) -> Vec<String> {
    let mut children = Vec::new();
    let (kind, content) = match envelope::unwrap(envelope_bytes) {
        Ok(r) => r,
        Err(_) => return children,
    };

    match kind {
        gix_object::Kind::Commit => {
            for line in content.split(|&b| b == b'\n') {
                if let Some(rest) = line.strip_prefix(b"tree ") {
                    if let Ok(hex) = std::str::from_utf8(rest) {
                        children.push(format!("{}:{}", prefix, hex.trim()));
                    }
                } else if let Some(rest) = line.strip_prefix(b"parent ") {
                    if let Ok(hex) = std::str::from_utf8(rest) {
                        children.push(format!("{}:{}", prefix, hex.trim()));
                    }
                } else if line.is_empty() {
                    break;
                }
            }
        }
        gix_object::Kind::Tree => {
            let mut pos = 0;
            while pos < content.len() {
                let nul = match content[pos..].iter().position(|&b| b == 0) {
                    Some(p) => pos + p,
                    None => break,
                };
                let hash_start = nul + 1;
                let hash_end = hash_start + hash_len;
                if hash_end > content.len() { break; }
                children.push(format!("{}:{}", prefix, hex::encode(&content[hash_start..hash_end])));
                pos = hash_end;
            }
        }
        gix_object::Kind::Tag => {
            for line in content.split(|&b| b == b'\n') {
                if let Some(rest) = line.strip_prefix(b"object ") {
                    if let Ok(hex) = std::str::from_utf8(rest) {
                        children.push(format!("{}:{}", prefix, hex.trim()));
                    }
                }
            }
        }
        gix_object::Kind::Blob => {}
    }

    children
}

/// If ref_name is a tag and ref_value points to an annotated tag object,
/// return the peeled (dereferenced) target OID hex string.
fn peel_tag(store: &dyn KappaStore, ref_name: &str, ref_value: &str) -> Option<String> {
    if !ref_name.starts_with("refs/tags/") {
        return None;
    }
    let envelope_bytes = store.blob_get(ref_value).ok()?;
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

/// Extract the hex OID from a kappa-label for pkt-line output.
fn kappa_to_hex_oid(kappa: &str) -> &str {
    kappa.split_once(':').map(|(_, hex)| hex).unwrap_or(kappa)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_core::clock::ntp_lamport::NtpLamportClock;
    use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
    use std::sync::Arc;

    fn test_store() -> (Arc<InMemoryStore>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let clock = Arc::new(NtpLamportClock::new());
        let store = InMemoryStore::new(
            MemoryStoreConfig::new(tmp.path().join("blobs")),
            clock,
        ).unwrap();
        (Arc::new(store), tmp)
    }

    // -- Test helpers: construct valid Git objects and store them --------------

    /// Store a Git blob, return its kappa-label.
    fn store_git_blob(store: &dyn KappaStore, content: &[u8]) -> String {
        let envelope_bytes = envelope::wrap(gix_object::Kind::Blob, content);
        let kappa = envelope::git_object_id_sha1(gix_object::Kind::Blob, content).unwrap();
        store.ingest_verified(&kappa, &envelope_bytes).unwrap();
        kappa
    }

    /// Store a Git tree with the given entries, return its kappa-label.
    /// Each entry is (name, blob_or_tree_kappa). Mode is 100644 for all.
    fn store_git_tree(store: &dyn KappaStore, entries: &[(&str, &str)]) -> String {
        let mut content = Vec::new();
        // Entries must be sorted by name (Git requirement)
        let mut sorted: Vec<_> = entries.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (name, kappa) in &sorted {
            // mode name\0{20-byte-hash}
            content.extend_from_slice(b"100644 ");
            content.extend_from_slice(name.as_bytes());
            content.push(0);
            // Extract hex from kappa "sha1:{hex}" and decode to raw bytes
            let hex_str = kappa.split_once(':').map(|(_, h)| h).unwrap_or(kappa);
            let hash_bytes = hex::decode(hex_str).unwrap();
            content.extend_from_slice(&hash_bytes);
        }
        let envelope_bytes = envelope::wrap(gix_object::Kind::Tree, &content);
        let kappa = envelope::git_object_id_sha1(gix_object::Kind::Tree, &content).unwrap();
        store.ingest_verified(&kappa, &envelope_bytes).unwrap();
        kappa
    }

    /// Store a Git commit, return its kappa-label.
    fn store_git_commit(
        store: &dyn KappaStore,
        tree_kappa: &str,
        parent_kappas: &[&str],
        message: &str,
    ) -> String {
        let tree_hex = kappa_to_hex_oid(tree_kappa);
        let mut body = format!("tree {}\n", tree_hex);
        for parent in parent_kappas {
            let parent_hex = kappa_to_hex_oid(parent);
            body.push_str(&format!("parent {}\n", parent_hex));
        }
        body.push_str("author Test <test@test.com> 1000000000 +0000\n");
        body.push_str("committer Test <test@test.com> 1000000000 +0000\n");
        body.push('\n');
        body.push_str(message);
        let content = body.as_bytes();
        let envelope_bytes = envelope::wrap(gix_object::Kind::Commit, content);
        let kappa = envelope::git_object_id_sha1(gix_object::Kind::Commit, content).unwrap();
        store.ingest_verified(&kappa, &envelope_bytes).unwrap();
        kappa
    }

    /// Extract hex OID from a kappa-label for test assertions.
    fn hex_oid(kappa: &str) -> String {
        kappa_to_hex_oid(kappa).to_string()
    }

    // -- Existing tests -------------------------------------------------------

    #[test]
    fn ref_advertisement_empty_repo() {
        let (store, _tmp) = test_store();
        let ns = NamespaceRef::from("test-repo");
        let mut output = Vec::new();
        write_ref_advertisement(&*store, &ns, "git-upload-pack", &mut output, gix_hash::Kind::Sha1).unwrap();

        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("git-upload-pack"));
        assert!(text.contains("capabilities"));
    }

    #[test]
    fn ref_advertisement_with_refs() {
        let (store, _tmp) = test_store();
        let ns = NamespaceRef::from("repo");
        refs::update_ref(&*store, &ns, "refs/heads/main", "sha1:aabbccddee", None).unwrap();
        refs::set_symbolic_ref(&*store, &ns, "HEAD", "refs/heads/main").unwrap();

        let mut output = Vec::new();
        write_ref_advertisement(&*store, &ns, "git-upload-pack", &mut output, gix_hash::Kind::Sha1).unwrap();

        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("aabbccddee"));
        assert!(text.contains("HEAD"));
        assert!(text.contains("refs/heads/main"));
    }

    #[test]
    fn kappa_to_hex_oid_strips_prefix() {
        assert_eq!(kappa_to_hex_oid("sha1:abc123"), "abc123");
        assert_eq!(kappa_to_hex_oid("sha256:def456"), "def456");
        assert_eq!(kappa_to_hex_oid("noprefix"), "noprefix");
    }

    // -- ITEM A/B: hash prefix parameterization verified ----------------------

    #[test]
    fn oid_to_kappa_string_sha1() {
        assert_eq!(oid_to_kappa_string(gix_hash::Kind::Sha1, "abc"), "sha1:abc");
    }

    #[test]
    fn oid_to_kappa_string_sha256() {
        assert_eq!(oid_to_kappa_string(gix_hash::Kind::Sha256, "def"), "sha256:def");
    }

    // -- ITEM C: compute_need_set full graph traversal ------------------------

    #[test]
    fn compute_need_set_walks_full_graph() {
        let (store, _tmp) = test_store();
        let blob1 = store_git_blob(&*store, b"file1 content");
        let blob2 = store_git_blob(&*store, b"file2 content");
        let tree = store_git_tree(&*store, &[("file1.txt", &blob1), ("file2.txt", &blob2)]);
        let commit = store_git_commit(&*store, &tree, &[], "initial commit");

        let (need, _shallows) = compute_need_set(
            &*store, &NamespaceRef::from("repo"), &[hex_oid(&commit)], &HashSet::new(), gix_hash::Kind::Sha1,
            &FetchOptions::default(),
        );

        assert!(need.contains(&commit), "commit must be in need set");
        assert!(need.contains(&tree), "tree must be in need set");
        assert!(need.contains(&blob1), "blob1 must be in need set");
        assert!(need.contains(&blob2), "blob2 must be in need set");
        assert_eq!(need.len(), 4);
    }

    // -- ITEM D: compute_need_set common set exclusion ------------------------

    #[test]
    fn compute_need_set_excludes_common_reachable() {
        let (store, _tmp) = test_store();
        let shared_blob = store_git_blob(&*store, b"shared content");
        let tree1 = store_git_tree(&*store, &[("shared.txt", &shared_blob)]);
        let commit1 = store_git_commit(&*store, &tree1, &[], "first commit");

        let new_blob = store_git_blob(&*store, b"new content");
        let tree2 = store_git_tree(&*store, &[
            ("new.txt", &new_blob),
            ("shared.txt", &shared_blob),
        ]);
        let commit2 = store_git_commit(&*store, &tree2, &[&commit1], "second commit");

        let mut common = HashSet::new();
        common.insert(hex_oid(&commit1));
        let (need, _shallows) = compute_need_set(
            &*store, &NamespaceRef::from("repo"), &[hex_oid(&commit2)], &common, gix_hash::Kind::Sha1,
            &FetchOptions::default(),
        );

        assert!(need.contains(&commit2), "commit2 must be in need set");
        assert!(need.contains(&tree2), "tree2 must be in need set");
        assert!(need.contains(&new_blob), "new_blob must be in need set");
        assert!(!need.contains(&shared_blob), "shared blob must NOT be in need set");
        assert!(!need.contains(&commit1), "commit1 must NOT be in need set");
        assert!(!need.contains(&tree1), "tree1 must NOT be in need set");
    }

    // -- Shallow clone test (item 49) ----------------------------------------

    #[test]
    fn shallow_clone_depth_1_returns_head_only() {
        let (store, _tmp) = test_store();
        let blob = store_git_blob(&*store, b"content");
        let tree = store_git_tree(&*store, &[("file.txt", &blob)]);
        let commit1 = store_git_commit(&*store, &tree, &[], "first");
        let commit2 = store_git_commit(&*store, &tree, &[&commit1], "second");
        let commit3 = store_git_commit(&*store, &tree, &[&commit2], "third");

        let opts = FetchOptions {
            deepen: Some(1),
            ..Default::default()
        };
        let (need, shallows) = compute_need_set(
            &*store, &NamespaceRef::from("repo"), &[hex_oid(&commit3)], &HashSet::new(),
            gix_hash::Kind::Sha1, &opts,
        );

        // Depth 1: only commit3, its tree, and blob. commit2 and commit1 excluded.
        assert!(need.contains(&commit3), "HEAD commit must be in need set");
        assert!(need.contains(&tree), "tree must be in need set");
        assert!(need.contains(&blob), "blob must be in need set");
        assert!(!need.contains(&commit2), "parent must NOT be in need set at depth 1");
        assert!(!need.contains(&commit1), "grandparent must NOT be in need set at depth 1");
        // commit3 is the shallow boundary
        assert!(shallows.contains(&hex_oid(&commit3)), "HEAD must be marked shallow");
    }

    #[test]
    fn shallow_clone_depth_2_returns_two_commits() {
        let (store, _tmp) = test_store();
        let blob = store_git_blob(&*store, b"content");
        let tree = store_git_tree(&*store, &[("file.txt", &blob)]);
        let commit1 = store_git_commit(&*store, &tree, &[], "first");
        let commit2 = store_git_commit(&*store, &tree, &[&commit1], "second");
        let commit3 = store_git_commit(&*store, &tree, &[&commit2], "third");

        let opts = FetchOptions {
            deepen: Some(2),
            ..Default::default()
        };
        let (need, shallows) = compute_need_set(
            &*store, &NamespaceRef::from("repo"), &[hex_oid(&commit3)], &HashSet::new(),
            gix_hash::Kind::Sha1, &opts,
        );

        assert!(need.contains(&commit3), "HEAD commit in need set");
        assert!(need.contains(&commit2), "parent in need set at depth 2");
        assert!(!need.contains(&commit1), "grandparent NOT in need set at depth 2");
        // commit2 is at the boundary
        assert!(shallows.contains(&hex_oid(&commit2)), "parent must be marked shallow");
    }

    // -- Partial clone test (item 50) -----------------------------------------

    #[test]
    fn partial_clone_blob_none_excludes_blobs() {
        let (store, _tmp) = test_store();
        let blob1 = store_git_blob(&*store, b"file1 content");
        let blob2 = store_git_blob(&*store, b"file2 content");
        let tree = store_git_tree(&*store, &[("file1.txt", &blob1), ("file2.txt", &blob2)]);
        let commit = store_git_commit(&*store, &tree, &[], "initial");

        let opts = FetchOptions {
            filter: Some(FilterSpec::BlobNone),
            ..Default::default()
        };
        let (need, _) = compute_need_set(
            &*store, &NamespaceRef::from("repo"), &[hex_oid(&commit)], &HashSet::new(),
            gix_hash::Kind::Sha1, &opts,
        );

        assert!(need.contains(&commit), "commit in need set");
        assert!(need.contains(&tree), "tree in need set");
        assert!(!need.contains(&blob1), "blob1 must NOT be in need set with blob:none");
        assert!(!need.contains(&blob2), "blob2 must NOT be in need set with blob:none");
    }

    // -- ITEM G: into_inner buffer preservation test --------------------------

    #[test]
    fn pktline_into_inner_preserves_pack_data() {
        use std::io::Read;

        let mut stream = Vec::new();
        // Pkt-line: ref update command
        let cmd = format!("{} {} refs/heads/main\0\n", "0".repeat(40), "a".repeat(40));
        let pkt_len = format!("{:04x}", cmd.len() + 4);
        stream.extend_from_slice(pkt_len.as_bytes());
        stream.extend_from_slice(cmd.as_bytes());
        // Flush
        stream.extend_from_slice(b"0000");
        // Pack data after flush
        let pack_marker = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00";
        stream.extend_from_slice(pack_marker);
        // Pad with some trailing bytes to simulate a trailer
        stream.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let mut reader = gix_packetline::blocking_io::StreamingPeekableIter::new(
            BufReader::new(&stream[..]),
            &[PacketLineRef::Flush],
            false,
        );

        // Read the command line
        let line = reader.read_line();
        assert!(line.is_some(), "should read the command line");

        // into_inner returns the reader positioned AT the flush delimiter,
        // not after it. The flush packet "0000" is still in the stream.
        // The actual receive-pack handler reads past the flush via
        // read_line() returning None, which consumes it. Here we need
        // to read_line once more to consume the flush, OR skip 4 bytes.
        //
        // In the real handler, the loop reads until flush stops it,
        // then into_inner gives the remaining stream. The flush bytes
        // may or may not be consumed depending on the pktline version.
        // The correct assertion: pack data exists somewhere in remaining.
        let mut inner = reader.into_inner();
        let mut remaining = Vec::new();
        inner.read_to_end(&mut remaining).unwrap();

        assert!(
            remaining.len() >= 4,
            "remaining bytes must contain pack data, got {} bytes",
            remaining.len()
        );
        // Find PACK magic in the remaining bytes (after flush)
        let pack_pos = remaining.windows(4).position(|w| w == b"PACK");
        assert!(
            pack_pos.is_some(),
            "PACK magic must appear in remaining bytes after into_inner"
        );
    }

    // -- SHA-256 Git object tests -----------------------------------------------

    /// Store a Git blob under SHA-256, return its kappa-label.
    fn store_git_blob_sha256(store: &dyn KappaStore, content: &[u8]) -> String {
        let envelope_bytes = envelope::wrap(gix_object::Kind::Blob, content);
        let kappa = envelope::git_object_id_sha256(gix_object::Kind::Blob, content).unwrap();
        store.ingest_verified(&kappa, &envelope_bytes).unwrap();
        kappa
    }

    /// Store a SHA-256 Git tree with entries using 32-byte hashes.
    fn store_git_tree_sha256(store: &dyn KappaStore, entries: &[(&str, &str)]) -> String {
        let mut content = Vec::new();
        let mut sorted: Vec<_> = entries.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        for (name, kappa) in &sorted {
            content.extend_from_slice(b"100644 ");
            content.extend_from_slice(name.as_bytes());
            content.push(0);
            let hex_str = kappa.split_once(':').map(|(_, h)| h).unwrap_or(kappa);
            let hash_bytes = hex::decode(hex_str).unwrap();
            assert_eq!(hash_bytes.len(), 32, "SHA-256 tree entry must be 32 bytes");
            content.extend_from_slice(&hash_bytes);
        }
        let envelope_bytes = envelope::wrap(gix_object::Kind::Tree, &content);
        let kappa = envelope::git_object_id_sha256(gix_object::Kind::Tree, &content).unwrap();
        store.ingest_verified(&kappa, &envelope_bytes).unwrap();
        kappa
    }

    /// Store a SHA-256 Git commit.
    fn store_git_commit_sha256(
        store: &dyn KappaStore,
        tree_kappa: &str,
        parent_kappas: &[&str],
        message: &str,
    ) -> String {
        let tree_hex = kappa_to_hex_oid(tree_kappa);
        let mut body = format!("tree {}\n", tree_hex);
        for parent in parent_kappas {
            let parent_hex = kappa_to_hex_oid(parent);
            body.push_str(&format!("parent {}\n", parent_hex));
        }
        body.push_str("author Test <test@test.com> 1000000000 +0000\n");
        body.push_str("committer Test <test@test.com> 1000000000 +0000\n");
        body.push('\n');
        body.push_str(message);
        let content = body.as_bytes();
        let envelope_bytes = envelope::wrap(gix_object::Kind::Commit, content);
        let kappa = envelope::git_object_id_sha256(gix_object::Kind::Commit, content).unwrap();
        store.ingest_verified(&kappa, &envelope_bytes).unwrap();
        kappa
    }

    #[test]
    fn sha256_blob_roundtrip() {
        let (store, _tmp) = test_store();
        let content = b"sha256 test blob content";
        let kappa = store_git_blob_sha256(&*store, content);
        assert!(kappa.starts_with("sha256:"));
        assert_eq!(kappa.len(), 7 + 64); // "sha256:" + 64 hex chars
        let retrieved = store.blob_get(&kappa).unwrap();
        let (kind, inner) = envelope::unwrap(&retrieved).unwrap();
        assert_eq!(kind, gix_object::Kind::Blob);
        assert_eq!(inner, content);
    }

    #[test]
    fn sha256_tree_parsing_32_byte_entries() {
        let (store, _tmp) = test_store();
        let blob = store_git_blob_sha256(&*store, b"sha256 file");
        let tree = store_git_tree_sha256(&*store, &[("file.txt", &blob)]);

        let envelope_bytes = store.blob_get(&tree).unwrap();
        let children = extract_children(&envelope_bytes, 32, "sha256");
        assert_eq!(children.len(), 1);
        assert!(children[0].starts_with("sha256:"));
        assert_eq!(children[0].len(), 7 + 64);
        assert_eq!(children[0], blob);
    }

    #[test]
    fn sha256_ref_advertisement_64_char_oids() {
        let (store, _tmp) = test_store();
        let blob = store_git_blob_sha256(&*store, b"content");
        let tree = store_git_tree_sha256(&*store, &[("f.txt", &blob)]);
        let commit = store_git_commit_sha256(&*store, &tree, &[], "init");
        let commit_hex = kappa_to_hex_oid(&commit);

        let ns = NamespaceRef::from("repo256");
        refs::update_ref(&*store, &ns, "refs/heads/main", &commit, None).unwrap();
        refs::set_symbolic_ref(&*store, &ns, "HEAD", "refs/heads/main").unwrap();

        let mut output = Vec::new();
        write_ref_advertisement(&*store, &ns, "git-upload-pack", &mut output, gix_hash::Kind::Sha256).unwrap();

        let text = String::from_utf8_lossy(&output);
        assert!(text.contains(commit_hex), "advertisement must contain 64-char OID");
        assert!(text.contains("object-format=sha256"), "capabilities must include object-format=sha256");
    }

    #[test]
    fn sha256_compute_need_set() {
        let (store, _tmp) = test_store();
        let blob1 = store_git_blob_sha256(&*store, b"sha256 file1");
        let blob2 = store_git_blob_sha256(&*store, b"sha256 file2");
        let tree = store_git_tree_sha256(&*store, &[("a.txt", &blob1), ("b.txt", &blob2)]);
        let commit = store_git_commit_sha256(&*store, &tree, &[], "sha256 commit");

        let (need, _shallows) = compute_need_set(
            &*store, &NamespaceRef::from("repo256"), &[hex_oid(&commit)], &HashSet::new(),
            gix_hash::Kind::Sha256, &FetchOptions::default(),
        );

        assert!(need.iter().all(|k| k.starts_with("sha256:")), "all need set kappas must have sha256 prefix");
        assert!(need.contains(&commit));
        assert!(need.contains(&tree));
        assert!(need.contains(&blob1));
        assert!(need.contains(&blob2));
        assert_eq!(need.len(), 4);
    }

    #[test]
    fn sha256_pack_trailer_32_bytes() {
        let (store, _tmp) = test_store();
        let blob = store_git_blob_sha256(&*store, b"pack trailer test");

        let mut pack_buf = Vec::new();
        packgen::generate_pack(store.as_ref(), &[blob], gix_hash::Kind::Sha256, &mut pack_buf).unwrap();

        // Pack header: 12 bytes. At least one entry. Trailer: 32 bytes.
        assert!(pack_buf.len() > 12 + 32, "pack must have header + entry + trailer");
        // Trailer is last 32 bytes
        let trailer = &pack_buf[pack_buf.len() - 32..];
        assert_ne!(trailer, &[0u8; 32], "trailer must not be all zeros");
    }

    #[test]
    fn repo_object_format_default_sha1() {
        let (store, _tmp) = test_store();
        // No _config/object_format tag -- defaults to SHA-1
        let ns = NamespaceRef::from("newrepo");
        let kind = match store.tag_get(&ns, "_config/object_format") {
            Ok(entry) => match entry.kappa.as_str() {
                "sha256" => gix_hash::Kind::Sha256,
                _ => gix_hash::Kind::Sha1,
            },
            Err(_) => gix_hash::Kind::Sha1,
        };
        assert_eq!(kind, gix_hash::Kind::Sha1);
    }

    #[test]
    fn repo_object_format_stored_sha256() {
        let (store, _tmp) = test_store();
        let ns = NamespaceRef::from("repo256");
        store.tag_set(&ns, "_config/object_format", "sha256").unwrap();
        let kind = match store.tag_get(&ns, "_config/object_format") {
            Ok(entry) => match entry.kappa.as_str() {
                "sha256" => gix_hash::Kind::Sha256,
                _ => gix_hash::Kind::Sha1,
            },
            Err(_) => gix_hash::Kind::Sha1,
        };
        assert_eq!(kind, gix_hash::Kind::Sha256);
    }
}
