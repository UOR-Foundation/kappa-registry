use crate::cursor::{KappaCursor, TERMINATED};

/// A cursor over zero elements. Zero allocation.
pub struct EmptyCursor;

impl KappaCursor for EmptyCursor {
    fn key(&self) -> &[u8] {
        TERMINATED
    }
    fn advance(&mut self) -> &[u8] {
        TERMINATED
    }
    fn seek(&mut self, _target: &[u8]) -> &[u8] {
        TERMINATED
    }
    fn size_hint(&self) -> u64 {
        0
    }
    fn cost(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_terminated() {
        let mut c = EmptyCursor;
        assert_eq!(c.key(), TERMINATED);
        assert_eq!(c.advance(), TERMINATED);
        assert_eq!(c.seek(b"anything"), TERMINATED);
    }
}
