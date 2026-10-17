use crate::cursor::{KappaCursor, TERMINATED};

/// A cursor over exactly one element.
pub struct OnceCursor {
    element: Vec<u8>,
    exhausted: bool,
}

impl OnceCursor {
    pub const fn new(element: Vec<u8>) -> Self {
        Self {
            element,
            exhausted: false,
        }
    }
}

impl KappaCursor for OnceCursor {
    fn key(&self) -> &[u8] {
        if self.exhausted {
            TERMINATED
        } else {
            &self.element
        }
    }

    fn advance(&mut self) -> &[u8] {
        self.exhausted = true;
        TERMINATED
    }

    fn seek(&mut self, target: &[u8]) -> &[u8] {
        if self.exhausted || self.element.as_slice() < target {
            self.exhausted = true;
            return TERMINATED;
        }
        &self.element
    }

    fn size_hint(&self) -> u64 {
        u64::from(!self.exhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yields_one_element() {
        let mut c = OnceCursor::new(b"hello".to_vec());
        assert_eq!(c.key(), b"hello");
        assert_eq!(c.advance(), TERMINATED);
        assert_eq!(c.key(), TERMINATED);
    }

    #[test]
    fn seek_to_element() {
        let mut c = OnceCursor::new(b"mm".to_vec());
        assert_eq!(c.seek(b"aa"), b"mm");
        assert_eq!(c.seek(b"mm"), b"mm");
    }

    #[test]
    fn seek_past_element() {
        let mut c = OnceCursor::new(b"aa".to_vec());
        assert_eq!(c.seek(b"zz"), TERMINATED);
    }
}
