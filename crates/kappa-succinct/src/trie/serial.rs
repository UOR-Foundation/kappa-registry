use std::io::{self, Write};

use super::LoudsDsTrie;
use sha2::{Digest, Sha256};

impl LoudsDsTrie {
    /// Write canonical KDST bytes directly to a caller-owned sink.
    /// The caller owns buffering, flushing, and durable publication.
    pub fn serialize_into<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(b"KDST")?;
        writer.write_all(&4u32.to_le_bytes())?;
        writer.write_all(&[self.cutover_depth])?;
        for value in [
            self.key_count,
            self.total_nodes,
            self.total_dense_terminals,
            self.sparse_child_offset,
        ] {
            writer.write_all(&value.to_le_bytes())?;
        }
        let dense_count = u8::try_from(self.dense_levels.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "dense level count exceeds framing",
            )
        })?;
        writer.write_all(&[dense_count])?;
        writer.write_all(&(self.dense_terminal_cumulative.len() as u64).to_le_bytes())?;
        for value in &self.dense_terminal_cumulative {
            writer.write_all(&value.to_le_bytes())?;
        }
        for (level, dense) in self.dense_levels.iter().enumerate() {
            writer.write_all(&dense.node_count().to_le_bytes())?;
            for (length, bits) in dense.serialization_bits() {
                writer.write_all(&length.to_le_bytes())?;
                write_bits(&mut writer, bits)?;
            }
            let mapping = &self.dense_node_to_bfs[level];
            writer.write_all(&(mapping.len() as u64).to_le_bytes())?;
            for value in mapping {
                writer.write_all(&value.to_le_bytes())?;
            }
        }
        let count = self.sparse.label_count();
        writer.write_all(&count.to_le_bytes())?;
        // Bounded staging avoids cloning the labels and three full bit arrays.
        let mut buffer = [0u8; 8192];
        let mut start = 0;
        while start < count {
            let length =
                usize::try_from((count - start).min(buffer.len() as u64)).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "label chunk exceeds address space",
                    )
                })?;
            for (offset, byte) in buffer[..length].iter_mut().enumerate() {
                *byte = self.sparse.label_at(start + offset as u64);
            }
            writer.write_all(&buffer[..length])?;
            start += length as u64;
        }
        write_bits(
            &mut writer,
            (0..count).map(|position| self.sparse.has_child(position)),
        )?;
        write_bits(
            &mut writer,
            (0..count).map(|position| self.sparse.is_node_start(position)),
        )?;
        write_bits(
            &mut writer,
            (0..count).map(|position| self.sparse.is_terminal(position)),
        )?;
        writer.write_all(&(self.sparse_pos_to_bfs.len() as u64).to_le_bytes())?;
        for value in &self.sparse_pos_to_bfs {
            writer.write_all(&value.to_le_bytes())?;
        }
        writer.write_all(&self.total_nodes.to_le_bytes())?;
        for (parent, label) in &self.parents {
            writer.write_all(&parent.to_le_bytes())?;
            writer.write_all(&[*label])?;
        }
        Ok(())
    }

    pub(super) fn serialized_digest(&self) -> io::Result<[u8; 32]> {
        #[derive(Debug)]
        struct HashWriter(Sha256);
        impl Write for HashWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut sink = std::io::BufWriter::with_capacity(65536, HashWriter(Sha256::new()));
        self.serialize_into(&mut sink)?;
        sink.flush()?;
        let hash = sink
            .into_inner()
            .map_err(std::io::IntoInnerError::into_error)?;
        Ok(hash.0.finalize().into())
    }
}

fn write_bits(writer: &mut impl Write, bits: impl Iterator<Item = bool>) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    let mut length = 0;
    for bit in bits {
        buffer[length] = u8::from(bit);
        length += 1;
        if length == buffer.len() {
            writer.write_all(&buffer)?;
            length = 0;
        }
    }
    writer.write_all(&buffer[..length])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie::{TrieConfig, sha256_bytes};

    struct ShortWriter {
        bytes: Vec<u8>,
        limit: usize,
    }

    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.bytes.len() == self.limit {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "sink closed"));
            }
            let count = bytes.len().min(3).min(self.limit - self.bytes.len());
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn partial_writes_preserve_bytes_and_sink_failure_propagates()
    -> Result<(), Box<dyn std::error::Error>> {
        let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"a".as_slice(), b"abc", b"xyz"])?;
        let expected = trie.serialize()?;
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            limit: usize::MAX,
        };
        trie.serialize_into(&mut writer)?;
        assert_eq!(writer.bytes, expected);
        assert_eq!(*trie.digest(), sha256_bytes(&writer.bytes));
        let mut failing = ShortWriter {
            bytes: Vec::new(),
            limit: 37,
        };
        assert!(
            matches!(trie.serialize_into(&mut failing), Err(error) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert_eq!(failing.bytes, expected[..37]);
        Ok(())
    }
}
