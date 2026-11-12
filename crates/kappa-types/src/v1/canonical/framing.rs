//! Allocation-free CBOR item framing for bounded ledger readers.
//!
//! This measures framing only. Canonical validation remains with dCBOR.

use crate::StoreError;

/// Deepest container nesting a ledger element may have. An `EpochMutation`
/// nests two levels; the bound keeps the decoder that follows from
/// recursing as deep as an element's bytes would allow.
pub const MAX_NESTING: usize = 16;

fn oversized() -> StoreError {
    StoreError::Rejected("ledger declares a CBOR length beyond the address space".into())
}

/// The head of the CBOR data item at the start of `bytes`: major type,
/// argument and head length; `None` while `bytes` holds only part of it.
/// Indefinite lengths and reserved heads are refused, as dCBOR refuses
/// them.
pub fn head(bytes: &[u8]) -> Result<Option<(u8, u64, usize)>, StoreError> {
    let Some(&first) = bytes.first() else {
        return Ok(None);
    };
    let major = first >> 5;
    let length = match first & 0x1f {
        info @ 0..=23 => return Ok(Some((major, u64::from(info), 1))),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => {
            return Err(StoreError::Rejected(
                "ledger holds an indefinite or reserved CBOR head".into(),
            ));
        }
    };
    let Some(argument) = bytes.get(1..=length) else {
        return Ok(None);
    };
    let value = argument
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    Ok(Some((major, value, 1 + length)))
}

/// Length of the CBOR data item at the start of `bytes`; `None` while
/// `bytes` holds only part of it. Work is one step per head examined, so
/// it is bounded by the bytes held, whatever lengths the heads declare;
/// state is one count per open container, at most [`MAX_NESTING`].
pub fn item_len(bytes: &[u8]) -> Result<Option<usize>, StoreError> {
    let mut offset = 0usize;
    // Items still owed by each open container, innermost last; the
    // outermost entry is the one item asked for.
    let mut open = [0u64; MAX_NESTING + 1];
    open[0] = 1;
    let mut depth = 1;
    while depth > 0 {
        if open[depth - 1] == 0 {
            depth -= 1;
            continue;
        }
        open[depth - 1] -= 1;
        let Some((major, argument, length)) = head(&bytes[offset..])? else {
            return Ok(None);
        };
        offset += length;
        let nested = match major {
            0 | 1 | 7 => 0,
            2 | 3 => {
                let size = usize::try_from(argument).map_err(|_| oversized())?;
                if bytes.len() - offset < size {
                    return Ok(None);
                }
                offset += size;
                0
            }
            4 => argument,
            5 => argument.checked_mul(2).ok_or_else(oversized)?,
            _ => 1,
        };
        if nested > 0 {
            if depth == open.len() {
                return Err(StoreError::Rejected(format!(
                    "ledger element nests deeper than {MAX_NESTING} containers"
                )));
            }
            open[depth] = nested;
            depth += 1;
        }
    }
    Ok(Some(offset))
}

#[cfg(test)]
mod tests {
    use super::{head, item_len};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Item lengths of canonical encodings of every major type, whole, at
    /// every truncation and followed by more bytes: a prefix is never
    /// mistaken for a complete item, and an item never takes its successor.
    #[test]
    fn item_lengths_are_exact_and_prefixes_are_incomplete() -> TestResult {
        let mut byte_string = vec![0x81, 0x59, 0x01, 0x2c];
        byte_string.extend_from_slice(&[0xab; 300]);
        let items: Vec<Vec<u8>> = vec![
            vec![0x07],
            vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            b"\x66latest".to_vec(),
            vec![0x83, 0x01, 0x02, 0x03],
            byte_string,
            vec![0xa1, 0x01, 0x62, b'h', b'i'],
            vec![0xc1, 0x1a, 0x00, 0x00, 0x00, 0x01],
            vec![0x82, 0xa1, 0x00, 0x80, 0xf6],
        ];
        for item in &items {
            assert_eq!(item_len(item)?, Some(item.len()), "{item:02x?}");
            for cut in 0..item.len() {
                assert_eq!(item_len(&item[..cut])?, None, "prefix {cut} of {item:02x?}");
            }
            let mut followed = item.clone();
            followed.extend_from_slice(&[0x01, 0x02]);
            assert_eq!(item_len(&followed)?, Some(item.len()));
        }
        Ok(())
    }

    /// Nesting up to the limit is measured; one level deeper is refused
    /// before any further byte is examined.
    #[test]
    fn nesting_beyond_the_limit_is_refused() -> TestResult {
        let mut within = vec![0x81; super::MAX_NESTING];
        within.push(0x00);
        assert_eq!(item_len(&within)?, Some(within.len()));
        let mut beyond = vec![0x81; super::MAX_NESTING + 1];
        beyond.push(0x00);
        assert!(item_len(&beyond).is_err());
        Ok(())
    }

    /// Indefinite and reserved heads are refused; a declared length beyond
    /// the held bytes is incomplete, not an allocation.
    #[test]
    fn indefinite_heads_are_refused_and_huge_lengths_are_incomplete() -> TestResult {
        assert!(head(&[0x9f]).is_err());
        assert!(head(&[0x1c]).is_err());
        assert_eq!(
            item_len(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])?,
            None
        );
        assert_eq!(
            item_len(&[0x9b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01])?,
            None
        );
        Ok(())
    }
}
