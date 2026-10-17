use super::{SigV4Error, UNSIGNED_PAYLOAD, build_canonical_query, build_canonical_request};

pub fn check_presigned_expiration(
    datetime: &str,
    expires_secs: u64,
    now_secs: u64,
) -> Result<(), SigV4Error> {
    let invalid = || SigV4Error::MalformedAuth {
        field: "X-Amz-Date".into(),
        reason: "expected valid UTC YYYYMMDDTHHMMSSZ".into(),
    };
    let bytes = datetime.as_bytes();
    if bytes.len() != 16
        || bytes[8] != b'T'
        || bytes[15] != b'Z'
        || !bytes[..8]
            .iter()
            .chain(bytes[9..15].iter())
            .all(u8::is_ascii_digit)
    {
        return Err(invalid());
    }
    let number = |range: std::ops::Range<usize>| -> Result<u16, SigV4Error> {
        datetime[range].parse().map_err(|_| invalid())
    };
    let time = kappa_types::clock::UtcDateTime {
        year: number(0..4)?,
        month: number(4..6)? as u8,
        day: number(6..8)? as u8,
        hour: number(9..11)? as u8,
        minute: number(11..13)? as u8,
        second: number(13..15)? as u8,
        millisecond: 0,
    }
    .to_unix()
    .map_err(|_| invalid())?;
    let start = u64::try_from(time.unix_seconds()).map_err(|_| invalid())?;
    if !(1..=604_800).contains(&expires_secs) {
        return Err(SigV4Error::MalformedAuth {
            field: "X-Amz-Expires".into(),
            reason: "must be between 1 and 604800 seconds".into(),
        });
    }
    let end = start.checked_add(expires_secs).ok_or_else(invalid)?;
    if now_secs < start || now_secs > end {
        return Err(SigV4Error::Expired);
    }
    Ok(())
}

pub fn build_presigned_canonical_request(
    method: &str,
    uri: &str,
    params: &[(&str, &str)],
    headers: &str,
    signed_headers: &str,
) -> String {
    build_canonical_request(
        method,
        uri,
        &build_canonical_query(params),
        headers,
        signed_headers,
        UNSIGNED_PAYLOAD,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiration_validates_calendar_and_window() {
        assert!(check_presigned_expiration("19700101T000000Z", 60, 60).is_ok());
        assert!(check_presigned_expiration("19700101T000000Z", 60, 61).is_err());
        assert!(check_presigned_expiration("19700101T000100Z", 60, 59).is_err());
        for date in ["20260229T000000Z", "19700101T000060Z", "éééééééé"] {
            assert!(check_presigned_expiration(date, 60, 0).is_err());
        }
        assert!(check_presigned_expiration("19700101T000000Z", u64::MAX, 0).is_err());
    }
}
