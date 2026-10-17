use kappa_handler::HandlerError;
use quick_xml::{Reader, events::Event};
use topcoat::router::StatusCode;

fn malformed() -> HandlerError {
    HandlerError::protocol(
        StatusCode::BAD_REQUEST,
        "MalformedXML",
        "expected CompleteMultipartUpload containing numbered parts and ETags",
    )
}

/// The elements a CompleteMultipartUpload body may contain, by depth.
fn admits(depth: usize, name: &str) -> bool {
    matches!(
        (depth, name),
        (0, "CompleteMultipartUpload") | (1, "Part") | (2, "PartNumber" | "ETag")
    )
}

pub(super) fn parse(bytes: &[u8]) -> Result<Vec<(u32, String)>, HandlerError> {
    let mut reader = Reader::from_reader(bytes);
    let mut stack: Vec<String> = Vec::new();
    let mut parts = Vec::new();
    let mut root_seen = false;
    let mut number: Option<u32> = None;
    let mut etag: Option<String> = None;
    // Character data of the open element: text, CDATA and references
    // arrive as separate events and are assembled here.
    let mut text = String::new();
    loop {
        let event = reader.read_event().map_err(|_| malformed())?;
        match event {
            Event::Start(ref element) => {
                let name = element.name().as_ref().to_owned();
                if !admits(stack.len(), &name) || !text.trim().is_empty() {
                    return Err(malformed());
                }
                match name.as_str() {
                    "CompleteMultipartUpload" if root_seen => return Err(malformed()),
                    "CompleteMultipartUpload" => root_seen = true,
                    "Part" => {
                        number = None;
                        etag = None;
                    }
                    "PartNumber" if number.is_some() => return Err(malformed()),
                    "ETag" if etag.is_some() => return Err(malformed()),
                    _ => {}
                }
                text.clear();
                stack.push(name);
            }
            Event::End(ref element) => {
                let name = stack.pop().ok_or_else(malformed)?;
                if name != element.name().as_ref() {
                    return Err(malformed());
                }
                let value = std::mem::take(&mut text);
                match name.as_str() {
                    "PartNumber" => {
                        number = Some(value.trim().parse().map_err(|_| malformed())?);
                    }
                    "ETag" => {
                        let value = value.trim();
                        if value.is_empty() {
                            return Err(malformed());
                        }
                        etag = Some(value.to_owned());
                    }
                    "Part" => {
                        if !value.trim().is_empty() {
                            return Err(malformed());
                        }
                        let number = number.take().ok_or_else(malformed)?;
                        if !(1..=super::multipart::MAX_PART_NUMBER).contains(&u64::from(number)) {
                            return Err(malformed());
                        }
                        let etag = etag.take().ok_or_else(malformed)?;
                        if parts
                            .last()
                            .is_some_and(|(previous, _)| number <= *previous)
                        {
                            return Err(HandlerError::protocol(
                                StatusCode::BAD_REQUEST,
                                "InvalidPartOrder",
                                "parts must be ascending",
                            ));
                        }
                        parts.push((number, etag));
                        if parts.len() as u64 > super::multipart::MAX_PART_NUMBER {
                            return Err(malformed());
                        }
                    }
                    _ if !value.trim().is_empty() => return Err(malformed()),
                    _ => {}
                }
            }
            Event::Decl(_) if !root_seen && stack.is_empty() => {}
            Event::Comment(_) => {}
            Event::Eof if root_seen && stack.is_empty() && !parts.is_empty() => return Ok(parts),
            ref other => {
                // Character data belongs to the open element; outside every
                // element only whitespace is allowed.
                let mut data = String::new();
                if !crate::xml::push_character_data(&mut data, other).map_err(|_| malformed())? {
                    return Err(malformed());
                }
                if stack.is_empty() {
                    if !data.trim().is_empty() {
                        return Err(malformed());
                    }
                } else {
                    text.push_str(&data);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn rejects_incomplete_duplicate_and_wrong_root_xml() {
        for xml in [
            "",
            "<CompleteMultipartUpload/>",
            "<Wrong><Part><PartNumber>1</PartNumber><ETag>x</ETag></Part></Wrong>",
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>x</ETag></Part>",
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><PartNumber>2</PartNumber><ETag>x</ETag></Part></CompleteMultipartUpload>",
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>",
            "<CompleteMultipartUpload><Part>stray<PartNumber>1</PartNumber><ETag>x</ETag></Part></CompleteMultipartUpload>",
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>&bogus;</ETag></Part></CompleteMultipartUpload>",
        ] {
            assert!(parse(xml.as_bytes()).is_err(), "accepted {xml}");
        }
    }

    #[test]
    fn decodes_quoted_etags() -> Result<(), kappa_handler::HandlerError> {
        assert_eq!(parse(b"<CompleteMultipartUpload><Part><PartNumber>9</PartNumber><ETag>&quot;digest&quot;</ETag></Part></CompleteMultipartUpload>")?, [(9, "\"digest\"".into())]);
        Ok(())
    }

    #[test]
    fn accepts_declaration_indentation_and_comments() -> Result<(), kappa_handler::HandlerError> {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                   <CompleteMultipartUpload>\n  <!-- parts -->\n  <Part>\n    \
                   <PartNumber> 1 </PartNumber>\n    <ETag>\"a\"</ETag>\n  </Part>\n  \
                   <Part><PartNumber>2</PartNumber><ETag><![CDATA[\"b\"]]></ETag></Part>\n\
                   </CompleteMultipartUpload>\n";
        assert_eq!(
            parse(xml.as_bytes())?,
            [(1, "\"a\"".into()), (2, "\"b\"".into())]
        );
        Ok(())
    }
}
