use super::{DenseLevel, SparseLevel, TrieError};

pub fn err(reason: &str) -> TrieError {
    TrieError::DeserializeFailed {
        reason: reason.into(),
    }
}

pub fn need(position: usize, length: usize, available: usize) -> Result<(), TrieError> {
    if position > available || length > available - position {
        return Err(err(&format!("truncated at {position}")));
    }
    Ok(())
}

pub fn read_u64(data: &[u8], position: &mut usize) -> Result<u64, TrieError> {
    need(*position, 8, data.len())?;
    let value = u64::from_le_bytes(
        data[*position..*position + 8]
            .try_into()
            .map_err(|_| err("invalid u64 framing"))?,
    );
    *position += 8;
    Ok(value)
}

pub fn read_u32(data: &[u8], position: &mut usize) -> Result<u32, TrieError> {
    need(*position, 4, data.len())?;
    let value = u32::from_le_bytes(
        data[*position..*position + 4]
            .try_into()
            .map_err(|_| err("invalid u32 framing"))?,
    );
    *position += 4;
    Ok(value)
}

fn read_length(data: &[u8], position: &mut usize) -> Result<usize, TrieError> {
    usize::try_from(read_u64(data, position)?).map_err(|_| err("length exceeds address space"))
}

pub fn decode_parents(
    data: &[u8],
    position: &mut usize,
    total_nodes: u64,
) -> Result<Vec<(u32, u8)>, TrieError> {
    let count = read_length(data, position)?;
    if count as u64 != total_nodes {
        return Err(err("parent count mismatch"));
    }
    need(
        *position,
        count
            .checked_mul(5)
            .ok_or_else(|| err("parent length overflow"))?,
        data.len(),
    )?;
    let mut parents = Vec::with_capacity(count);
    for index in 0..count {
        let parent = read_u32(data, position)?;
        let label = data[*position];
        *position += 1;
        if (index == 0 && (parent != 0 || label != 0))
            || (index != 0 && u64::from(parent) >= index as u64)
        {
            return Err(err("invalid parent ordering"));
        }
        parents.push((parent, label));
    }
    Ok(parents)
}

fn read_bits(data: &[u8], position: &mut usize, length: usize) -> Result<Vec<bool>, TrieError> {
    need(*position, length, data.len())?;
    let bytes = &data[*position..*position + length];
    if bytes.iter().any(|&byte| byte > 1) {
        return Err(err("noncanonical bit byte"));
    }
    *position += length;
    Ok(bytes.iter().map(|&byte| byte == 1).collect())
}

fn read_mapping(data: &[u8], position: &mut usize, expected: usize) -> Result<Vec<u64>, TrieError> {
    let length = read_length(data, position)?;
    if length != expected {
        return Err(err("node mapping length mismatch"));
    }
    need(
        *position,
        length
            .checked_mul(8)
            .ok_or_else(|| err("mapping length overflow"))?,
        data.len(),
    )?;
    (0..length).map(|_| read_u64(data, position)).collect()
}

pub fn decode_dense(
    data: &[u8],
    position: &mut usize,
) -> Result<(DenseLevel, Vec<u64>), TrieError> {
    let count = read_u64(data, position)?;
    if count == 0 || count > 1_000_000_000 {
        return Err(err("dense node count outside bounds"));
    }
    let nodes = usize::try_from(count).map_err(|_| err("node count exceeds address space"))?;
    let label_length = read_length(data, position)?;
    if Some(label_length) != nodes.checked_mul(256) {
        return Err(err("dense labels mismatch"));
    }
    let labels = read_bits(data, position, label_length)?;
    let child_length = read_length(data, position)?;
    if child_length != labels.iter().filter(|&&bit| bit).count() {
        return Err(err("dense child indicator count mismatch"));
    }
    let children = read_bits(data, position, child_length)?;
    let terminal_length = read_length(data, position)?;
    if terminal_length != nodes {
        return Err(err("dense terminal mismatch"));
    }
    let terminals = read_bits(data, position, terminal_length)?;
    let mapping = read_mapping(data, position, nodes)?;
    Ok((
        DenseLevel::new(&labels, &children, &terminals, count),
        mapping,
    ))
}

pub fn decode_sparse(
    data: &[u8],
    position: &mut usize,
) -> Result<(SparseLevel, Vec<u64>), TrieError> {
    let length = read_length(data, position)?;
    if length == 0 || length > 1_000_000_000 {
        return Err(err("sparse count outside bounds"));
    }
    need(
        *position,
        length
            .checked_mul(4)
            .ok_or_else(|| err("sparse length overflow"))?,
        data.len(),
    )?;
    let labels = data[*position..*position + length].to_vec();
    *position += length;
    let children = read_bits(data, position, length)?;
    let louds = read_bits(data, position, length)?;
    let terminals = read_bits(data, position, length)?;
    let mapping = read_mapping(data, position, length)?;
    Ok((
        SparseLevel::new(labels, &children, &louds, &terminals),
        mapping,
    ))
}
