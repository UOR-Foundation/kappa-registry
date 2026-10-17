//! S3 XML response encoding.
//!
//! Produces well-formed XML 1.0 with proper escaping via quick-xml.
//! Keys containing bytes 0x00-0x1F are percent-encoded when
//! encoding-type=url is set.

use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesRef, BytesStart, BytesText, Event};

use crate::list::ListObjectsV2Response;

const XML_DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Encode a ListObjectsV2 response to XML bytes.
pub fn encode_list_objects_v2_xml(response: &ListObjectsV2Response) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    buf.extend_from_slice(XML_DECLARATION.as_bytes());

    let mut writer = Writer::new(&mut buf);

    let mut root = BytesStart::new("ListBucketResult");
    root.push_attribute(("xmlns", S3_XMLNS));
    // Writing to Vec<u8> is infallible. The unwrap is provably safe.
    writer.write_event(Event::Start(root)).unwrap();

    write_element(&mut writer, "Name", &response.name);
    if let Some(ref p) = response.prefix {
        write_element(&mut writer, "Prefix", p);
    }
    write_element(&mut writer, "MaxKeys", &response.max_keys.to_string());
    write_element(&mut writer, "KeyCount", &response.key_count.to_string());
    write_element(
        &mut writer,
        "IsTruncated",
        if response.is_truncated {
            "true"
        } else {
            "false"
        },
    );

    if let Some(ref d) = response.delimiter {
        write_element(&mut writer, "Delimiter", d);
    }
    if let Some(ref et) = response.encoding_type {
        write_element(&mut writer, "EncodingType", et);
    }
    if let Some(ref token) = response.next_continuation_token {
        write_element(&mut writer, "NextContinuationToken", token);
    }

    let url_encode = response.encoding_type.as_deref() == Some("url");

    for entry in &response.contents {
        writer
            .write_event(Event::Start(BytesStart::new("Contents")))
            .unwrap();
        let key = if url_encode {
            percent_encode_key(&entry.key)
        } else {
            entry.key.clone()
        };
        write_element(&mut writer, "Key", &key);
        write_element(&mut writer, "LastModified", &entry.last_modified);
        write_element(&mut writer, "ETag", &entry.etag);
        write_element(&mut writer, "Size", &entry.size.to_string());
        write_element(&mut writer, "StorageClass", &entry.storage_class);
        writer
            .write_event(Event::End(BytesEnd::new("Contents")))
            .unwrap();
    }

    for cp in &response.common_prefixes {
        writer
            .write_event(Event::Start(BytesStart::new("CommonPrefixes")))
            .unwrap();
        let prefix = if url_encode {
            percent_encode_key(cp)
        } else {
            cp.clone()
        };
        write_element(&mut writer, "Prefix", &prefix);
        writer
            .write_event(Event::End(BytesEnd::new("CommonPrefixes")))
            .unwrap();
    }

    writer
        .write_event(Event::End(BytesEnd::new("ListBucketResult")))
        .unwrap();

    buf
}

/// Encode an S3 error response.
pub fn encode_s3_error_xml(code: &str, message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(XML_DECLARATION.as_bytes());
    let mut writer = Writer::new(&mut buf);
    writer
        .write_event(Event::Start(BytesStart::new("Error")))
        .unwrap();
    write_element(&mut writer, "Code", code);
    write_element(&mut writer, "Message", message);
    writer
        .write_event(Event::End(BytesEnd::new("Error")))
        .unwrap();
    buf
}

/// Encode a DeleteResult response.
pub fn encode_delete_result_xml(
    deleted: &[String],
    errors: &[(String, String, String)],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(XML_DECLARATION.as_bytes());
    let mut writer = Writer::new(&mut buf);
    writer
        .write_event(Event::Start(BytesStart::new("DeleteResult")))
        .unwrap();
    for key in deleted {
        writer
            .write_event(Event::Start(BytesStart::new("Deleted")))
            .unwrap();
        write_element(&mut writer, "Key", key);
        writer
            .write_event(Event::End(BytesEnd::new("Deleted")))
            .unwrap();
    }
    for (key, code, message) in errors {
        writer
            .write_event(Event::Start(BytesStart::new("Error")))
            .unwrap();
        write_element(&mut writer, "Key", key);
        write_element(&mut writer, "Code", code);
        write_element(&mut writer, "Message", message);
        writer
            .write_event(Event::End(BytesEnd::new("Error")))
            .unwrap();
    }
    writer
        .write_event(Event::End(BytesEnd::new("DeleteResult")))
        .unwrap();
    buf
}

/// Encode an InitiateMultipartUpload response.
pub fn encode_initiate_multipart_xml(bucket: &str, key: &str, upload_id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(XML_DECLARATION.as_bytes());
    let mut writer = Writer::new(&mut buf);
    let mut root = BytesStart::new("InitiateMultipartUploadResult");
    root.push_attribute(("xmlns", S3_XMLNS));
    writer.write_event(Event::Start(root)).unwrap();
    write_element(&mut writer, "Bucket", bucket);
    write_element(&mut writer, "Key", key);
    write_element(&mut writer, "UploadId", upload_id);
    writer
        .write_event(Event::End(BytesEnd::new("InitiateMultipartUploadResult")))
        .unwrap();
    buf
}

/// Encode a CompleteMultipartUpload response.
pub fn encode_complete_multipart_xml(bucket: &str, key: &str, etag: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(XML_DECLARATION.as_bytes());
    let mut writer = Writer::new(&mut buf);
    let mut root = BytesStart::new("CompleteMultipartUploadResult");
    root.push_attribute(("xmlns", S3_XMLNS));
    writer.write_event(Event::Start(root)).unwrap();
    write_element(&mut writer, "Bucket", bucket);
    write_element(&mut writer, "Key", key);
    write_element(&mut writer, "ETag", etag);
    writer
        .write_event(Event::End(BytesEnd::new("CompleteMultipartUploadResult")))
        .unwrap();
    buf
}

/// Part info for ListParts responses.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PartInfo {
    pub part_number: u32,
    pub etag: String,
    pub size: u64,
    pub last_modified: String,
}

/// Encode a ListParts response.
pub fn encode_list_parts_xml(parts: &[PartInfo]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(XML_DECLARATION.as_bytes());
    let mut writer = Writer::new(&mut buf);
    writer
        .write_event(Event::Start(BytesStart::new("ListPartsResult")))
        .unwrap();
    for part in parts {
        writer
            .write_event(Event::Start(BytesStart::new("Part")))
            .unwrap();
        write_element(&mut writer, "PartNumber", &part.part_number.to_string());
        write_element(&mut writer, "ETag", &part.etag);
        write_element(&mut writer, "Size", &part.size.to_string());
        if !part.last_modified.is_empty() {
            write_element(&mut writer, "LastModified", &part.last_modified);
        }
        writer
            .write_event(Event::End(BytesEnd::new("Part")))
            .unwrap();
    }
    writer
        .write_event(Event::End(BytesEnd::new("ListPartsResult")))
        .unwrap();
    buf
}

/// Encode a CopyObject result.
pub fn encode_copy_result_xml(etag: &str, last_modified: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(XML_DECLARATION.as_bytes());
    let mut writer = Writer::new(&mut buf);
    writer
        .write_event(Event::Start(BytesStart::new("CopyObjectResult")))
        .unwrap();
    write_element(&mut writer, "ETag", etag);
    write_element(&mut writer, "LastModified", last_modified);
    writer
        .write_event(Event::End(BytesEnd::new("CopyObjectResult")))
        .unwrap();
    buf
}

/// Write a single XML text element. Writing to Vec<u8> is infallible.
fn write_element<W: std::io::Write>(writer: &mut Writer<W>, name: &str, value: &str) {
    writer
        .write_event(Event::Start(BytesStart::new(name)))
        .unwrap();
    writer
        .write_event(Event::Text(BytesText::new(value)))
        .unwrap();
    writer.write_event(Event::End(BytesEnd::new(name))).unwrap();
}

/// Percent-encode a key for encoding-type=url per RFC 3986.
pub fn percent_encode_key(key: &str) -> String {
    let mut result = String::with_capacity(key.len());
    for byte in key.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

/// Append the character an XML reference stands for: a numeric character
/// reference, or one of the five entities XML predefines. No other entity
/// is defined for S3 request bodies, so any other name is an error rather
/// than text passed through.
///
/// # Errors
///
/// Returns a description of an invalid character reference or an
/// undefined entity.
pub fn push_reference(out: &mut String, reference: &BytesRef<'_>) -> Result<(), String> {
    if let Some(ch) = reference
        .resolve_char_ref()
        .map_err(|e| format!("invalid character reference &{};: {e}", &**reference))?
    {
        out.push(ch);
        return Ok(());
    }
    out.push(match &**reference {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "apos" => '\'',
        "quot" => '"',
        other => return Err(format!("undefined entity reference &{other};")),
    });
    Ok(())
}

/// Append the character data of a text, CDATA or reference event to `out`.
/// Returns `false`, appending nothing, for every other event. quick-xml
/// reports text, CDATA sections and references as separate events, so an
/// element's value is the concatenation of all of them, with XML 1.0
/// line-end normalization.
///
/// # Errors
///
/// Returns a description of an invalid reference.
pub fn push_character_data(out: &mut String, event: &Event<'_>) -> Result<bool, String> {
    match event {
        Event::Text(text) => out.push_str(&text.xml10_content()),
        Event::CData(cdata) => out.push_str(&cdata.xml10_content()),
        Event::GeneralRef(reference) => push_reference(out, reference)?,
        _ => return Ok(false),
    }
    Ok(true)
}

/// Parse object keys from a DeleteObjects XML body.
///
/// Format: `<Delete><Object><Key>...</Key></Object>...</Delete>`
///
/// A key is its element's character data exactly, whitespace included:
/// S3 keys may begin or end with spaces. Empty `<Key/>` elements name no
/// object and are skipped.
///
/// # Errors
///
/// Returns a description string on malformed XML.
pub fn parse_delete_keys(xml_bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut reader = quick_xml::Reader::from_reader(xml_bytes);
    let mut buf = Vec::new();
    let mut keys = Vec::new();
    let mut key: Option<String> = None;

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| format!("invalid XML: {e}"))?;
        match event {
            Event::Start(ref e) if e.name().as_ref() == "Key" => key = Some(String::new()),
            Event::End(ref e) if e.name().as_ref() == "Key" => {
                if let Some(text) = key.take().filter(|text| !text.is_empty()) {
                    keys.push(text);
                }
            }
            Event::Eof => break,
            ref other => {
                if let Some(text) = key.as_mut() {
                    push_character_data(text, other)?;
                }
            }
        }
        buf.clear();
    }
    Ok(keys)
}

/// Which tag field the parser is inside.
enum TagField {
    Key,
    Value,
}

/// Parse object tags from a PutObjectTagging XML body.
///
/// Format: `<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag>...</TagSet></Tagging>`
///
/// Keys and values are their elements' character data exactly, whitespace
/// included.
///
/// # Errors
///
/// Returns a description string on malformed XML or if tags exceed `max_tags`.
pub fn parse_tagging(xml_bytes: &[u8], max_tags: usize) -> Result<Vec<(String, String)>, String> {
    let mut reader = quick_xml::Reader::from_reader(xml_bytes);
    let mut buf = Vec::new();
    let mut tags = Vec::new();
    let mut current_key: Option<String> = None;
    let mut current_value: Option<String> = None;
    let mut field: Option<(TagField, String)> = None;

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| format!("invalid XML: {e}"))?;
        match event {
            Event::Start(ref e) => match e.name().as_ref() {
                "Key" => field = Some((TagField::Key, String::new())),
                "Value" => field = Some((TagField::Value, String::new())),
                _ => {}
            },
            Event::End(ref e) => match e.name().as_ref() {
                "Key" | "Value" => match field.take() {
                    Some((TagField::Key, text)) => current_key = Some(text),
                    Some((TagField::Value, text)) => current_value = Some(text),
                    None => {}
                },
                "Tag" => {
                    if let (Some(k), Some(v)) = (current_key.take(), current_value.take()) {
                        tags.push((k, v));
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            ref other => {
                if let Some((_, text)) = field.as_mut() {
                    push_character_data(text, other)?;
                }
            }
        }
        buf.clear();
    }
    if tags.len() > max_tags {
        return Err(format!("object tags cannot exceed {max_tags}"));
    }
    Ok(tags)
}

/// Encode object tags as `<Tagging><TagSet>` XML.
pub fn encode_tagging_xml(tags: &[(String, String)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(XML_DECLARATION.as_bytes());
    let mut writer = Writer::new(&mut buf);
    writer
        .write_event(Event::Start(BytesStart::new("Tagging")))
        .unwrap();
    writer
        .write_event(Event::Start(BytesStart::new("TagSet")))
        .unwrap();
    for (k, v) in tags {
        writer
            .write_event(Event::Start(BytesStart::new("Tag")))
            .unwrap();
        write_element(&mut writer, "Key", k);
        write_element(&mut writer, "Value", v);
        writer
            .write_event(Event::End(BytesEnd::new("Tag")))
            .unwrap();
    }
    writer
        .write_event(Event::End(BytesEnd::new("TagSet")))
        .unwrap();
    writer
        .write_event(Event::End(BytesEnd::new("Tagging")))
        .unwrap();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::list::ObjectEntry;

    #[test]
    fn error_xml_structure() {
        let xml = encode_s3_error_xml("NoSuchKey", "The specified key does not exist.");
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<Code>NoSuchKey</Code>"));
        assert!(text.contains("<Message>The specified key does not exist.</Message>"));
        assert!(text.starts_with("<?xml"));
    }

    #[test]
    fn error_xml_escapes_special_chars() {
        let xml = encode_s3_error_xml("Test", "value with <angle> & \"quotes\"");
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("&lt;angle&gt;"));
        assert!(text.contains("&amp;"));
        assert!(text.contains("&quot;quotes&quot;"));
    }

    #[test]
    fn list_objects_xml_structure() {
        let resp = ListObjectsV2Response {
            name: "mybucket".into(),
            prefix: Some("photos/".into()),
            delimiter: Some("/".into()),
            max_keys: 1000,
            is_truncated: false,
            contents: vec![ObjectEntry {
                key: "photos/sunset.jpg".into(),
                last_modified: "2024-01-01T00:00:00Z".into(),
                etag: "\"abc123\"".into(),
                size: 12345,
                storage_class: "STANDARD".into(),
            }],
            common_prefixes: vec!["photos/2023/".into()],
            next_continuation_token: None,
            key_count: 2,
            encoding_type: None,
        };
        let xml = encode_list_objects_v2_xml(&resp);
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<Name>mybucket</Name>"));
        assert!(text.contains("<Key>photos/sunset.jpg</Key>"));
        assert!(text.contains("<Size>12345</Size>"));
        assert!(text.contains("<Prefix>photos/2023/</Prefix>"));
        assert!(text.contains("xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\""));
    }

    #[test]
    fn percent_encode_control_chars() {
        let encoded = percent_encode_key("key\x01with\x02control");
        assert_eq!(encoded, "key%01with%02control");
    }

    #[test]
    fn percent_encode_preserves_slash() {
        let encoded = percent_encode_key("path/to/file.txt");
        assert_eq!(encoded, "path/to/file.txt");
    }

    #[test]
    fn initiate_multipart_xml() {
        let xml = encode_initiate_multipart_xml("mybucket", "mykey", "upload-123");
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<Bucket>mybucket</Bucket>"));
        assert!(text.contains("<Key>mykey</Key>"));
        assert!(text.contains("<UploadId>upload-123</UploadId>"));
    }

    #[test]
    fn complete_multipart_xml() {
        let xml = encode_complete_multipart_xml("mybucket", "mykey", "\"etag-value\"");
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<ETag>&quot;etag-value&quot;</ETag>"));
    }

    #[test]
    fn delete_result_xml() {
        let xml = encode_delete_result_xml(
            &["key1".into(), "key2".into()],
            &[("key3".into(), "AccessDenied".into(), "forbidden".into())],
        );
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<Deleted><Key>key1</Key></Deleted>"));
        assert!(text.contains("<Error><Key>key3</Key><Code>AccessDenied</Code>"));
    }

    #[test]
    fn delete_keys_assemble_references_cdata_and_whitespace() -> Result<(), String> {
        let keys = parse_delete_keys(
            b"<Delete>\n  <Object><Key> a &amp; b </Key></Object>\n  \
              <Object><Key>&#x41;&lt;<![CDATA[<raw>]]>&gt;</Key></Object>\n  \
              <Object><Key></Key></Object>\n</Delete>",
        )?;
        assert_eq!(keys, [" a & b ", "A<<raw>>"]);
        Ok(())
    }

    #[test]
    fn tagging_values_resolve_every_predefined_entity() -> Result<(), String> {
        let tags = parse_tagging(
            b"<Tagging><TagSet><Tag><Key>k&apos;1</Key>\
              <Value>&quot;v&quot; &amp; w</Value></Tag></TagSet></Tagging>",
            10,
        )?;
        assert_eq!(tags, [("k'1".to_owned(), "\"v\" & w".to_owned())]);
        Ok(())
    }

    #[test]
    fn undefined_entities_and_bad_character_references_are_rejected() {
        for xml in [
            "<Delete><Object><Key>&nbsp;</Key></Object></Delete>",
            "<Delete><Object><Key>&#xZZ;</Key></Object></Delete>",
        ] {
            assert!(parse_delete_keys(xml.as_bytes()).is_err(), "accepted {xml}");
        }
        assert!(
            parse_tagging(
                b"<Tagging><TagSet><Tag><Key>k</Key><Value>&bogus;</Value></Tag></TagSet></Tagging>",
                10
            )
            .is_err()
        );
    }

    #[test]
    fn list_parts_xml() {
        let xml = encode_list_parts_xml(&[
            PartInfo {
                part_number: 1,
                etag: "\"aaa\"".into(),
                size: 1000,
                last_modified: String::new(),
            },
            PartInfo {
                part_number: 2,
                etag: "\"bbb\"".into(),
                size: 2000,
                last_modified: String::new(),
            },
        ]);
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<PartNumber>1</PartNumber>"));
        assert!(text.contains("<PartNumber>2</PartNumber>"));
        assert!(text.contains("<Size>1000</Size>"));
    }
}
