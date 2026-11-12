//! Allocation-free comparison for an already authenticated Sign1 envelope.
//! Both definite and indefinite CBOR strings/arrays are accepted. This does
//! not establish authority; callers must authenticate the envelope first.

use super::*;

struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn head(&mut self) -> Result<(u8, Option<u64>), CryptoError> {
        let (&first, rest) = self
            .bytes
            .split_first()
            .ok_or(CoseError::Profile("truncated envelope"))?;
        self.bytes = rest;
        let additional = first & 31;
        let length = match additional {
            0..=23 => return Ok((first >> 5, Some(u64::from(additional)))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 => return Ok((first >> 5, None)),
            _ => return Err(CoseError::Profile("reserved CBOR head").into()),
        };
        let data = self.take(length)?;
        Ok((
            first >> 5,
            Some(
                data.iter()
                    .fold(0, |value, byte| (value << 8) | u64::from(*byte)),
            ),
        ))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CryptoError> {
        let data = self
            .bytes
            .get(..length)
            .ok_or(CoseError::Profile("truncated envelope field"))?;
        self.bytes = &self.bytes[length..];
        Ok(data)
    }

    fn end(&mut self) -> bool {
        if self.bytes.first() == Some(&0xff) {
            self.bytes = &self.bytes[1..];
            true
        } else {
            false
        }
    }

    fn string(&mut self, mut visit: impl FnMut(&[u8])) -> Result<(), CryptoError> {
        let (major, length) = self.head()?;
        if major != 2 {
            return Err(CoseError::Profile("expected envelope byte string").into());
        }
        if let Some(length) = length {
            let length = usize::try_from(length)
                .map_err(|_| CoseError::Profile("envelope field exceeds address space"))?;
            visit(self.take(length)?);
            return Ok(());
        }
        while !self.end() {
            let (major, length) = self.head()?;
            let length = length
                .filter(|_| major == 2)
                .ok_or(CoseError::Profile("invalid indefinite byte string chunk"))?;
            let length = usize::try_from(length)
                .map_err(|_| CoseError::Profile("envelope chunk exceeds address space"))?;
            visit(self.take(length)?);
        }
        Ok(())
    }
}

pub(super) fn matches(envelope: &[u8], returned: &[u8]) -> Result<bool, CryptoError> {
    let mut cursor = Cursor { bytes: envelope };
    let (major, length) = cursor.head()?;
    if major != 4 || length.is_some_and(|length| length != 4) {
        return Err(CoseError::Profile("expected four-field Sign1 array").into());
    }
    cursor.string(|_| {})?;
    let (major, fields) = cursor.head()?;
    if major != 5 || fields.is_some_and(|fields| fields != 0) || (fields.is_none() && !cursor.end())
    {
        return Err(CoseError::Profile("unprotected headers must be empty").into());
    }
    cursor.string(|_| {})?;
    let mut remaining = returned;
    let mut equal = true;
    cursor.string(|chunk| {
        if let Some(prefix) = remaining.get(..chunk.len()) {
            equal &= prefix == chunk;
            remaining = &remaining[chunk.len()..];
        } else {
            equal = false;
        }
    })?;
    if (length.is_none() && !cursor.end()) || !cursor.bytes.is_empty() {
        return Err(CoseError::Profile("trailing envelope fields or bytes").into());
    }
    Ok(equal && remaining.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definite_and_chunked_forms_compare_without_reencoding() {
        let definite = [0x84, 0x40, 0xa0, 0x40, 0x43, 1, 2, 3];
        let chunked = [
            0x9f, 0x5f, 0xff, 0xbf, 0xff, 0x5f, 0xff, 0x5f, 0x41, 1, 0x42, 2, 3, 0xff, 0xff,
        ];
        for bytes in [&definite[..], &chunked[..]] {
            assert!(matches(bytes, &[1, 2, 3]).unwrap());
            for different in [&[][..], &[1, 2][..], &[1, 2, 4][..], &[1, 2, 3, 4][..]] {
                assert!(!matches(bytes, different).unwrap());
            }
            for end in 0..bytes.len() {
                assert!(matches(&bytes[..end], &[1, 2, 3]).is_err());
            }
        }
    }
}
