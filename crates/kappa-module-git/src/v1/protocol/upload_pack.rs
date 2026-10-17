use std::collections::HashSet;
use std::io::{self, BufReader, Read, Write};

use gix_packetline::PacketLineRef;
use gix_packetline::blocking_io::encode;

use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::blob::BlobStore;
use kappa_store::traits::tag::TagStore;

use crate::envelope;
use crate::packgen;
use crate::refs;

use super::graph;
use super::{FetchOptions, FilterSpec, ProtocolError};

/// Handle a protocol v2 upload-pack POST request.
pub fn handle_v2_upload_pack<R: Read, W: Write, S: BlobStore + TagStore + ?Sized>(
    store: &S,
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

    let command = read_command(&mut reader)?;

    if command.starts_with("command=ls-refs") {
        handle_ls_refs(store, namespace, &mut reader, &mut response, object_hash)
    } else if command.starts_with("command=fetch") {
        handle_v2_fetch(store, namespace, &mut reader, &mut response, object_hash)
    } else {
        Err(ProtocolError::Protocol(format!(
            "unknown v2 command: {}",
            command
        )))
    }
}

/// Handle a git-upload-pack v1 request.
pub fn handle_upload_pack<R: Read, W: Write, S: BlobStore + TagStore + ?Sized>(
    store: &S,
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
    let mut done = false;

    // Read want lines until flush
    while let Some(line_result) = reader.read_line() {
        let text = decode_line(line_result)?;
        if let Some(rest) = text.strip_prefix("want ") {
            wants.push(rest.split_whitespace().next().unwrap_or(rest).to_string());
        } else if let Some(rest) = text.strip_prefix("deepen ") {
            if let Ok(d) = rest.trim().parse::<u32>() {
                fetch_opts.deepen = Some(d);
            }
        } else if let Some(rest) = text.strip_prefix("shallow ") {
            fetch_opts.client_shallows.insert(rest.trim().to_string());
        } else if let Some(rest) = text.strip_prefix("filter ") {
            parse_filter_spec(rest.trim(), &mut fetch_opts);
        }
    }
    reader.reset_with(&[PacketLineRef::Flush]);

    // Read have/done lines
    while let Some(line_result) = reader.read_line() {
        let text = decode_line(line_result)?;
        if let Some(rest) = text.strip_prefix("have ") {
            haves.insert(rest.trim().to_string());
        } else if text == "done" {
            done = true;
            break;
        }
    }

    if wants.is_empty() {
        encode::data_to_write(b"NAK\n", &mut response)?;
        encode::flush_to_write(&mut response)?;
        return Ok(());
    }

    let common = find_common(store, namespace, &haves, object_hash);

    if common.is_empty() {
        encode::data_to_write(b"NAK\n", &mut response)?;
    } else {
        for ack_oid in &common {
            let ack_line = format!("ACK {} common\n", ack_oid);
            encode::data_to_write(ack_line.as_bytes(), &mut response)?;
        }
        if done && let Some(first) = common.iter().next() {
            let ack_line = format!("ACK {}\n", first);
            encode::data_to_write(ack_line.as_bytes(), &mut response)?;
        }
    }

    let (need_kappas, new_shallows) =
        graph::compute_need_set(store, namespace, &wants, &common, object_hash, &fetch_opts);

    for shallow_oid in &new_shallows {
        let line = format!("shallow {}\n", shallow_oid);
        encode::data_to_write(line.as_bytes(), &mut response)?;
    }

    for client_shallow in &fetch_opts.client_shallows {
        let kappa_str = envelope::oid_to_kappa_string(object_hash, client_shallow);
        if let Ok(k) = Kappa::parse(&kappa_str)
            && store.blob_exists_in(namespace, &k).unwrap_or(false)
            && !new_shallows.contains(client_shallow)
        {
            let line = format!("unshallow {}\n", client_shallow);
            encode::data_to_write(line.as_bytes(), &mut response)?;
        }
    }

    write_pack_sideband(store, namespace, &need_kappas, object_hash, &mut response)?;

    encode::flush_to_write(&mut response)?;
    Ok(())
}

fn handle_ls_refs<R: Read, W: Write, S: BlobStore + TagStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    reader: &mut gix_packetline::blocking_io::StreamingPeekableIter<R>,
    response: &mut W,
    _object_hash: gix_hash::Kind,
) -> Result<(), ProtocolError> {
    let mut ref_prefixes: Vec<String> = Vec::new();
    let mut symrefs = false;
    let mut peel = false;

    while let Some(line_result) = reader.read_line() {
        let text = decode_line(line_result)?;
        if let Some(prefix) = text.strip_prefix("ref-prefix ") {
            ref_prefixes.push(prefix.to_string());
        } else if text == "symrefs" {
            symrefs = true;
        } else if text == "peel" {
            peel = true;
        }
    }

    let all_refs = refs::list_refs(store, namespace, "")?;
    let head_target = refs::resolve_ref(store, namespace, "HEAD")?;

    if let Some(ref target) = head_target {
        let matches =
            ref_prefixes.is_empty() || ref_prefixes.iter().any(|p| "HEAD".starts_with(p.as_str()));
        if matches {
            let target_label = target.to_string();
            let oid = envelope::kappa_to_hex_oid(&target_label);
            let mut line = format!("{} HEAD", oid);
            if symrefs
                && let Ok(entry) = store.tag_get(namespace, "HEAD")
                && let Some(ref sym) = entry.symref
            {
                line.push_str(&format!(" symref-target:{}", sym));
            }
            line.push('\n');
            encode::data_to_write(line.as_bytes(), &mut *response)?;
        }
    }

    for (ref_name, ref_value) in &all_refs {
        if ref_value.starts_with("ref: ") {
            continue;
        }
        let matches = ref_prefixes.is_empty()
            || ref_prefixes
                .iter()
                .any(|p| ref_name.starts_with(p.as_str()));
        if !matches {
            continue;
        }
        let oid = envelope::kappa_to_hex_oid(ref_value);
        let mut line = format!("{} {}", oid, ref_name);
        if peel
            && let Ok(kappa) = Kappa::parse(ref_value)
            && let Ok(envelope_bytes) = store.blob_get_in(namespace, &kappa)
            && let Ok((kind, content)) = envelope::unwrap(&envelope_bytes)
            && kind == gix_object::Kind::Tag
            && let Some(peeled) = content
                .split(|&b| b == b'\n')
                .find_map(|l| l.strip_prefix(b"object "))
                .and_then(|r| std::str::from_utf8(r).ok())
        {
            line.push_str(&format!(" peeled:{}", peeled.trim()));
        }
        line.push('\n');
        encode::data_to_write(line.as_bytes(), &mut *response)?;
    }

    encode::flush_to_write(&mut *response)?;
    Ok(())
}

fn handle_v2_fetch<R: Read, W: Write, S: BlobStore + TagStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    reader: &mut gix_packetline::blocking_io::StreamingPeekableIter<R>,
    response: &mut W,
    object_hash: gix_hash::Kind,
) -> Result<(), ProtocolError> {
    let mut fetch_opts = FetchOptions::default();
    let mut no_progress = false;

    // Read fetch arguments until delimiter
    while let Some(line_result) = reader.read_line() {
        let text = decode_line(line_result)?;
        if text == "no-progress" {
            no_progress = true;
        } else if let Some(rest) = text.strip_prefix("deepen ") {
            if let Ok(d) = rest.parse::<u32>() {
                fetch_opts.deepen = Some(d);
            }
        } else if let Some(rest) = text.strip_prefix("filter ") {
            parse_filter_spec(rest, &mut fetch_opts);
        }
    }
    reader.reset_with(&[PacketLineRef::Flush]);

    // Read want/have/done
    let mut wants: Vec<String> = Vec::new();
    let mut haves: HashSet<String> = HashSet::new();

    while let Some(line_result) = reader.read_line() {
        let text = decode_line(line_result)?;
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

    if wants.is_empty() {
        encode::data_to_write(b"acknowledgments\n", &mut *response)?;
        encode::data_to_write(b"NAK\n", &mut *response)?;
        encode::flush_to_write(&mut *response)?;
        return Ok(());
    }

    let common = find_common(store, namespace, &haves, object_hash);

    // Acknowledgments: only when client sent have lines
    if !haves.is_empty() {
        encode::data_to_write(b"acknowledgments\n", &mut *response)?;
        for have_oid in &haves {
            if common.contains(have_oid) {
                let ack = format!("ACK {}\n", have_oid);
                encode::data_to_write(ack.as_bytes(), &mut *response)?;
            }
        }
        if common.is_empty() {
            encode::data_to_write(b"NAK\n", &mut *response)?;
        }
        encode::data_to_write(b"ready\n", &mut *response)?;
        encode::delim_to_write(&mut *response)?;
    }

    // Packfile section
    encode::data_to_write(b"packfile\n", &mut *response)?;

    let (need_kappas, new_shallows) =
        graph::compute_need_set(store, namespace, &wants, &common, object_hash, &fetch_opts);

    for shallow_oid in &new_shallows {
        let line = format!("shallow {}\n", shallow_oid);
        let mut sb = Vec::with_capacity(1 + line.len());
        sb.push(1);
        sb.extend_from_slice(line.as_bytes());
        encode::data_to_write(&sb, &mut *response)?;
    }

    if !no_progress {
        let total = need_kappas.len();
        let msg = format!("Compressing objects: 100% ({}/{}), done.\n", total, total);
        let mut progress_pkt = Vec::with_capacity(1 + msg.len());
        progress_pkt.push(2);
        progress_pkt.extend_from_slice(msg.as_bytes());
        encode::data_to_write(&progress_pkt, &mut *response)?;
    }

    write_pack_sideband(store, namespace, &need_kappas, object_hash, response)?;

    encode::flush_to_write(response)?;
    Ok(())
}

fn write_pack_sideband<W: Write, S: BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    need_kappas: &[Kappa],
    object_hash: gix_hash::Kind,
    response: &mut W,
) -> Result<(), ProtocolError> {
    let name_hints = std::collections::HashMap::new();
    let mut sideband = SidebandWriter::new(response);
    packgen::generate_pack(
        store,
        namespace,
        need_kappas,
        object_hash,
        &name_hints,
        None,
        &mut sideband,
    )?;
    sideband.flush()?;
    Ok(())
}

/// Channel payload per side-band packet. gix-packetline caps a packet's data
/// at 65516 bytes (git's `LARGE_PACKET_DATA_MAX`), and the channel byte is
/// part of that data.
const SIDEBAND_DATA_BYTES: usize = 65515;

struct SidebandWriter<'a, W> {
    response: &'a mut W,
    frame: Vec<u8>,
}

impl<'a, W: Write> SidebandWriter<'a, W> {
    fn new(response: &'a mut W) -> Self {
        let mut frame = Vec::with_capacity(SIDEBAND_DATA_BYTES + 1);
        frame.push(1);
        Self { response, frame }
    }

    fn emit(&mut self) -> io::Result<()> {
        if self.frame.len() > 1 {
            encode::data_to_write(&self.frame, &mut *self.response)?;
            self.frame.truncate(1);
        }
        Ok(())
    }
}

impl<W: Write> Write for SidebandWriter<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let available = SIDEBAND_DATA_BYTES + 1 - self.frame.len();
        let count = available.min(data.len());
        self.frame.extend_from_slice(&data[..count]);
        if self.frame.len() == SIDEBAND_DATA_BYTES + 1 {
            self.emit()?;
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit()?;
        self.response.flush()
    }
}

fn find_common<S: BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    haves: &HashSet<String>,
    object_hash: gix_hash::Kind,
) -> HashSet<String> {
    let mut common = HashSet::new();
    for have_oid in haves {
        let kappa_str = envelope::oid_to_kappa_string(object_hash, have_oid);
        if let Ok(k) = Kappa::parse(&kappa_str)
            && store.blob_exists_in(namespace, &k).unwrap_or(false)
        {
            common.insert(have_oid.clone());
        }
    }
    common
}

fn parse_filter_spec(spec: &str, opts: &mut FetchOptions) {
    if spec == "blob:none" {
        opts.filter = Some(FilterSpec::BlobNone);
    } else if let Some(lim) = spec.strip_prefix("blob:limit=")
        && let Ok(l) = lim.parse::<u64>()
    {
        opts.filter = Some(FilterSpec::BlobLimit(l));
    }
}

fn read_command<R: Read>(
    reader: &mut gix_packetline::blocking_io::StreamingPeekableIter<R>,
) -> Result<String, ProtocolError> {
    if let Some(line_result) = reader.read_line() {
        decode_line(line_result)
    } else {
        Ok(String::new())
    }
}

pub(super) fn decode_line<E: std::fmt::Debug>(
    line_result: Result<gix_error::ExnMessageResult<gix_packetline::PacketLineRef<'_>>, E>,
) -> Result<String, ProtocolError> {
    let line = line_result
        .map_err(|e| ProtocolError::Protocol(format!("{e:?}")))?
        .map_err(|e| ProtocolError::Protocol(format!("decode: {e:?}")))?;
    if let Some(data) = line.as_slice() {
        let text = std::str::from_utf8(data)
            .map_err(|_| ProtocolError::Protocol("non-utf8 line".into()))?
            .trim()
            .to_string();
        Ok(text)
    } else {
        Ok(String::new())
    }
}

#[cfg(test)]
mod sideband_tests {
    use super::{SIDEBAND_DATA_BYTES, SidebandWriter};
    use std::io::{self, Write};

    #[test]
    fn frames_reconstruct_payload_across_packet_boundaries() -> io::Result<()> {
        let payload = vec![0x5a; SIDEBAND_DATA_BYTES * 2 + 17];
        let mut output = Vec::new();
        {
            let mut writer = SidebandWriter::new(&mut output);
            writer.write_all(&payload[..13])?;
            writer.write_all(&payload[13..])?;
            writer.flush()?;
        }
        let mut reconstructed = Vec::new();
        let mut packets = output.as_slice();
        let mut count = 0;
        while !packets.is_empty() {
            let header = std::str::from_utf8(&packets[..4]).map_err(io::Error::other)?;
            let length = usize::from_str_radix(header, 16).map_err(io::Error::other)?;
            assert!(length <= SIDEBAND_DATA_BYTES + 5);
            assert_eq!(packets[4], 1);
            reconstructed.extend_from_slice(&packets[5..length]);
            packets = &packets[length..];
            count += 1;
        }
        assert_eq!(count, 3);
        assert_eq!(reconstructed, payload);
        Ok(())
    }

    struct FailedResponse;

    impl Write for FailedResponse {
        fn write(&mut self, _data: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "disconnected"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn response_failure_propagates_from_full_frame() {
        let mut response = FailedResponse;
        let mut writer = SidebandWriter::new(&mut response);
        let result = writer.write_all(&vec![0; SIDEBAND_DATA_BYTES]);
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::BrokenPipe));
    }
}
