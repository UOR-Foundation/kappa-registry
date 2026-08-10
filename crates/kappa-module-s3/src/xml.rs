//! S3 XML response encoding.
//!
//! Produces well-formed XML 1.0 with proper escaping. Keys containing
//! bytes 0x00-0x1F are percent-encoded when encoding-type=url is set.

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

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
    writer.write_event(Event::Start(root)).unwrap();

    write_text_element(&mut writer, "Name", &response.name);
    if let Some(ref p) = response.prefix {
        write_text_element(&mut writer, "Prefix", p);
    }
    write_text_element(&mut writer, "MaxKeys", &response.max_keys.to_string());
    write_text_element(&mut writer, "KeyCount", &response.key_count.to_string());
    write_text_element(&mut writer, "IsTruncated", if response.is_truncated { "true" } else { "false" });

    if let Some(ref d) = response.delimiter {
        write_text_element(&mut writer, "Delimiter", d);
    }
    if let Some(ref et) = response.encoding_type {
        write_text_element(&mut writer, "EncodingType", et);
    }
    if let Some(ref token) = response.next_continuation_token {
        write_text_element(&mut writer, "NextContinuationToken", token);
    }

    let url_encode = response.encoding_type.as_deref() == Some("url");

    for entry in &response.contents {
        writer.write_event(Event::Start(BytesStart::new("Contents"))).unwrap();
        let key = if url_encode { percent_encode_key(&entry.key) } else { entry.key.clone() };
        write_text_element(&mut writer, "Key", &key);
        if !entry.last_modified.is_empty() {
            write_text_element(&mut writer, "LastModified", &entry.last_modified);
        }
        write_text_element(&mut writer, "ETag", &entry.etag);
        write_text_element(&mut writer, "Size", &entry.size.to_string());
        write_text_element(&mut writer, "StorageClass", &entry.storage_class);
        writer.write_event(Event::End(BytesEnd::new("Contents"))).unwrap();
    }

    for cp in &response.common_prefixes {
        writer.write_event(Event::Start(BytesStart::new("CommonPrefixes"))).unwrap();
        let prefix = if url_encode { percent_encode_key(cp) } else { cp.clone() };
        write_text_element(&mut writer, "Prefix", &prefix);
        writer.write_event(Event::End(BytesEnd::new("CommonPrefixes"))).unwrap();
    }

    writer.write_event(Event::End(BytesEnd::new("ListBucketResult"))).unwrap();

    buf
}

/// Encode an S3 error response.
pub fn encode_s3_error_xml(code: &str, message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(XML_DECLARATION.as_bytes());
    let mut writer = Writer::new(&mut buf);
    writer.write_event(Event::Start(BytesStart::new("Error"))).unwrap();
    write_text_element(&mut writer, "Code", code);
    write_text_element(&mut writer, "Message", message);
    writer.write_event(Event::End(BytesEnd::new("Error"))).unwrap();
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
    writer.write_event(Event::Start(BytesStart::new("DeleteResult"))).unwrap();
    for key in deleted {
        writer.write_event(Event::Start(BytesStart::new("Deleted"))).unwrap();
        write_text_element(&mut writer, "Key", key);
        writer.write_event(Event::End(BytesEnd::new("Deleted"))).unwrap();
    }
    for (key, code, message) in errors {
        writer.write_event(Event::Start(BytesStart::new("Error"))).unwrap();
        write_text_element(&mut writer, "Key", key);
        write_text_element(&mut writer, "Code", code);
        write_text_element(&mut writer, "Message", message);
        writer.write_event(Event::End(BytesEnd::new("Error"))).unwrap();
    }
    writer.write_event(Event::End(BytesEnd::new("DeleteResult"))).unwrap();
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
    write_text_element(&mut writer, "Bucket", bucket);
    write_text_element(&mut writer, "Key", key);
    write_text_element(&mut writer, "UploadId", upload_id);
    writer.write_event(Event::End(BytesEnd::new("InitiateMultipartUploadResult"))).unwrap();
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
    write_text_element(&mut writer, "Bucket", bucket);
    write_text_element(&mut writer, "Key", key);
    write_text_element(&mut writer, "ETag", etag);
    writer.write_event(Event::End(BytesEnd::new("CompleteMultipartUploadResult"))).unwrap();
    buf
}

/// Part info for ListParts.
#[derive(Debug, Clone)]
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
    writer.write_event(Event::Start(BytesStart::new("ListPartsResult"))).unwrap();
    for part in parts {
        writer.write_event(Event::Start(BytesStart::new("Part"))).unwrap();
        write_text_element(&mut writer, "PartNumber", &part.part_number.to_string());
        write_text_element(&mut writer, "ETag", &part.etag);
        write_text_element(&mut writer, "Size", &part.size.to_string());
        if !part.last_modified.is_empty() {
            write_text_element(&mut writer, "LastModified", &part.last_modified);
        }
        writer.write_event(Event::End(BytesEnd::new("Part"))).unwrap();
    }
    writer.write_event(Event::End(BytesEnd::new("ListPartsResult"))).unwrap();
    buf
}

/// Encode a CopyObject result.
pub fn encode_copy_result_xml(etag: &str, last_modified: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(XML_DECLARATION.as_bytes());
    let mut writer = Writer::new(&mut buf);
    writer.write_event(Event::Start(BytesStart::new("CopyObjectResult"))).unwrap();
    write_text_element(&mut writer, "ETag", etag);
    write_text_element(&mut writer, "LastModified", last_modified);
    writer.write_event(Event::End(BytesEnd::new("CopyObjectResult"))).unwrap();
    buf
}

fn write_text_element<W: std::io::Write>(writer: &mut Writer<W>, name: &str, value: &str) {
    writer.write_event(Event::Start(BytesStart::new(name))).unwrap();
    writer.write_event(Event::Text(BytesText::new(value))).unwrap();
    writer.write_event(Event::End(BytesEnd::new(name))).unwrap();
}

/// Percent-encode a key for encoding-type=url.
/// Encodes bytes 0x00-0x1F and other non-URI-safe characters per RFC 3986.
fn percent_encode_key(key: &str) -> String {
    let mut result = String::with_capacity(key.len());
    for byte in key.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'.' | b'_' | b'~' | b'/' => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::list::ObjectEntry;

    #[test]
    fn error_xml_parses() {
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
        // Quotes in ETag are XML-escaped by BytesText
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
    fn list_parts_xml() {
        let xml = encode_list_parts_xml(&[
            PartInfo { part_number: 1, etag: "\"aaa\"".into(), size: 1000, last_modified: String::new() },
            PartInfo { part_number: 2, etag: "\"bbb\"".into(), size: 2000, last_modified: String::new() },
        ]);
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<PartNumber>1</PartNumber>"));
        assert!(text.contains("<PartNumber>2</PartNumber>"));
        assert!(text.contains("<Size>1000</Size>"));
    }
}
