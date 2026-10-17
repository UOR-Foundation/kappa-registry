//! Validated arithmetic for the framed AEAD format, not authentication evidence.
//!
//! Age stream.go validates size before authenticating the final chunk;
//! AWS-LC Counter32 separately bounds nonce issuance. Keep those obligations
//! distinct: constructing this value does not prove any ciphertext authentic.

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("AEAD frame counter exhausted")]
    CounterExhausted,
    #[error("AEAD encrypted length overflow")]
    LengthOverflow,
    #[error("AEAD encrypted length mismatch: expected {expected}, actual {actual}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("AEAD frame index {index} exceeds final index {last}")]
    IndexOutOfBounds { index: u32, last: u32 },
}

/// Frame index admitted against a particular framing value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameIndex(u32);

impl FrameIndex {
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Checked format dimensions. Ciphertext authentication is a separate step.
#[derive(Debug, Clone, Copy)]
pub struct FrameLayout {
    plaintext_size: u64,
    frame_count: u32,
    encrypted_size: u64,
}

impl FrameLayout {
    pub fn new(plaintext_size: u64) -> Result<Self, FramingError> {
        let count = plaintext_size.saturating_sub(1) / super::aead::FRAME_SIZE as u64 + 1;
        let frame_count = u32::try_from(count).map_err(|_| FramingError::CounterExhausted)?;
        let encrypted_size = count
            .checked_mul(super::aead::FRAME_TAG_SIZE as u64)
            .and_then(|tags| plaintext_size.checked_add(tags))
            .ok_or(FramingError::LengthOverflow)?;
        Ok(Self {
            plaintext_size,
            frame_count,
            encrypted_size,
        })
    }

    pub fn check_encrypted_size(self, actual: u64) -> Result<Self, FramingError> {
        if actual != self.encrypted_size {
            return Err(FramingError::LengthMismatch {
                expected: self.encrypted_size,
                actual,
            });
        }
        Ok(self)
    }

    pub const fn plaintext_size(self) -> u64 {
        self.plaintext_size
    }
    pub const fn frame_count(self) -> u32 {
        self.frame_count
    }
    pub const fn encrypted_size(self) -> u64 {
        self.encrypted_size
    }
    pub const fn final_index(self) -> FrameIndex {
        FrameIndex(self.frame_count - 1)
    }

    pub fn index(self, index: u32) -> Result<FrameIndex, FramingError> {
        if index >= self.frame_count {
            return Err(FramingError::IndexOutOfBounds {
                index,
                last: self.final_index().get(),
            });
        }
        Ok(FrameIndex(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_boundary_is_checked_without_allocating_payloads() {
        let limit = u64::from(u32::MAX) * super::super::aead::FRAME_SIZE as u64;
        let layout = FrameLayout::new(limit).expect("last admitted layout");
        assert_eq!(layout.frame_count(), u32::MAX);
        assert_eq!(layout.final_index().get(), u32::MAX - 1);
        assert!(matches!(
            layout.index(u32::MAX),
            Err(FramingError::IndexOutOfBounds { .. })
        ));
        assert!(matches!(
            FrameLayout::new(limit + 1),
            Err(FramingError::CounterExhausted)
        ));
        assert!(matches!(
            FrameLayout::new(u64::MAX),
            Err(FramingError::CounterExhausted)
        ));
        let empty = FrameLayout::new(0).expect("empty layout");
        assert_eq!(empty.frame_count(), 1);
        assert!(empty.check_encrypted_size(0).is_err());
        assert!(
            empty
                .check_encrypted_size(super::super::aead::FRAME_TAG_SIZE as u64)
                .is_ok()
        );
    }
}
