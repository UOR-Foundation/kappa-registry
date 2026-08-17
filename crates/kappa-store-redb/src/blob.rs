//! Blob operations for PersistentStore.
//!
//! Invariant: hash(bytes_on_disk) == storage_address (kappa). Always.
//!
//! Under no encryption (default): sigma == kappa. Plaintext on disk.
//! Under encryption: framed AEAD (64KB frames). kappa = hash(framed_ciphertext).
//! sigma = hash(plaintext). Binding record maps sigma to (kappa, base_nonce,
//! plaintext_size). Range reads decrypt only the needed frames.

use std::path::PathBuf;

use redb::{ReadableDatabase, ReadableTable};

use kappa_core::kappa::kappa_from_bytes;
use kappa_core::types::StoreError;

use crate::tables::{BINDING_RECORDS, BLOB_META, COMPRESSION_RECORDS, NAMESPACES};
use crate::PersistentStore;

/// Binding record on-disk format:
/// [base_nonce:8][plaintext_size:8 BE][kappa_len:2 BE][kappa_bytes]
pub(crate) fn encode_binding(kappa: &str, base_nonce: &[u8; 8], plaintext_size: u64) -> Vec<u8> {
    let kb = kappa.as_bytes();
    let klen = kb.len() as u16;
    let mut buf = Vec::with_capacity(8 + 8 + 2 + kb.len());
    buf.extend_from_slice(base_nonce);
    buf.extend_from_slice(&plaintext_size.to_be_bytes());
    buf.extend_from_slice(&klen.to_be_bytes());
    buf.extend_from_slice(kb);
    buf
}

struct DecodedBinding {
    kappa: String,
    base_nonce: [u8; 8],
    plaintext_size: u64,
}

fn decode_binding(data: &[u8]) -> Result<DecodedBinding, StoreError> {
    if data.len() < 18 {
        return Err(StoreError::Io(std::io::Error::other("binding record too short")));
    }
    let mut base_nonce = [0u8; 8];
    base_nonce.copy_from_slice(&data[..8]);
    let plaintext_size = u64::from_be_bytes(data[8..16].try_into().unwrap());
    let kappa_len = u16::from_be_bytes([data[16], data[17]]) as usize;
    if data.len() < 18 + kappa_len {
        return Err(StoreError::Io(std::io::Error::other("binding record truncated")));
    }
    let kappa = std::str::from_utf8(&data[18..18 + kappa_len])
        .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?
        .to_string();
    Ok(DecodedBinding { kappa, base_nonce, plaintext_size })
}

/// Compression record on-disk format:
/// [algo_len:1][algo:N][kappa_len:2 BE][kappa:M][uncompressed_size:8 BE]
pub(crate) fn encode_compression_record(kappa: &str, algo: &str, uncompressed_size: u64) -> Vec<u8> {
    let ab = algo.as_bytes();
    let kb = kappa.as_bytes();
    let klen = kb.len() as u16;
    let mut buf = Vec::with_capacity(1 + ab.len() + 2 + kb.len() + 8);
    buf.push(ab.len() as u8);
    buf.extend_from_slice(ab);
    buf.extend_from_slice(&klen.to_be_bytes());
    buf.extend_from_slice(kb);
    buf.extend_from_slice(&uncompressed_size.to_be_bytes());
    buf
}

pub(crate) struct DecodedCompression {
    pub kappa: String,
    pub algorithm: String,
    pub uncompressed_size: u64,
}

pub(crate) fn decode_compression_record(data: &[u8]) -> Result<DecodedCompression, StoreError> {
    if data.is_empty() {
        return Err(StoreError::Io(std::io::Error::other("compression record empty")));
    }
    let algo_len = data[0] as usize;
    if data.len() < 1 + algo_len + 2 {
        return Err(StoreError::Io(std::io::Error::other("compression record truncated")));
    }
    let algorithm = std::str::from_utf8(&data[1..1 + algo_len])
        .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?
        .to_string();
    let kappa_len = u16::from_be_bytes([
        data[1 + algo_len],
        data[1 + algo_len + 1],
    ]) as usize;
    let kappa_start = 1 + algo_len + 2;
    if data.len() < kappa_start + kappa_len + 8 {
        return Err(StoreError::Io(std::io::Error::other("compression record truncated")));
    }
    let kappa = std::str::from_utf8(&data[kappa_start..kappa_start + kappa_len])
        .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?
        .to_string();
    let size_start = kappa_start + kappa_len;
    let uncompressed_size = u64::from_be_bytes(
        data[size_start..size_start + 8].try_into().unwrap()
    );
    Ok(DecodedCompression { kappa, algorithm, uncompressed_size })
}

impl PersistentStore {
    pub(crate) fn kappa_path(&self, kappa: &str) -> Result<PathBuf, StoreError> {
        kappa_core::kappa::blob_path_for(&self.blob_root, kappa)
    }

    pub(crate) fn blob_put_impl(&self, verified: &kappa_core::verified::VerifiedContent) -> Result<bool, StoreError> {
        let sigma = verified.kappa();
        let content = verified.content();
        tracing::debug!(sigma = sigma, size = content.len(), "blob_put");

        match &self.blob_encryptor {
            Some(enc) => {
                // 1. Encrypt in frames
                let encrypted = enc.encrypt(sigma, content)
                    .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;

                // 2. kappa = hash(disk_bytes) -- storage address
                let kappa = kappa_from_bytes(&encrypted.disk_bytes);

                // 3. Write to kappa path
                let path = self.kappa_path(&kappa)?;
                let newly_placed = if path.exists() {
                    false
                } else {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
                    }
                    let tmp = path.with_extension("tmp");
                    {
                        use std::io::Write;
                        let file = std::fs::File::create(&tmp).map_err(StoreError::Io)?;
                        let mut w = std::io::BufWriter::new(file);
                        w.write_all(&encrypted.disk_bytes).map_err(StoreError::Io)?;
                        let f = w.into_inner().map_err(|e| StoreError::Io(e.into_error()))?;
                        if self.fsync { f.sync_all().map_err(StoreError::Io)?; }
                    }
                    std::fs::rename(&tmp, &path).map_err(StoreError::Io)?;
                    if self.fsync {
                        if let Some(p) = path.parent() {
                            if let Ok(d) = std::fs::File::open(p) { let _ = d.sync_all(); }
                        }
                    }
                    true
                };

                // 4. Binding record: sigma -> (kappa, base_nonce, plaintext_size)
                let txn = self.db.begin_write().map_err(Self::redb_err)?;
                {
                    let mut table = txn.open_table(BINDING_RECORDS).map_err(Self::redb_err)?;
                    let rec = encode_binding(&kappa, &encrypted.base_nonce, encrypted.plaintext_size);
                    table.insert(sigma, rec.as_slice()).map_err(Self::redb_err)?;
                }
                txn.commit().map_err(Self::redb_err)?;

                Ok(newly_placed)
            }
            None => {
                // No encryption: sigma == kappa, plaintext on disk
                let path = kappa_core::kappa::blob_path_for(&self.blob_root, sigma)?;
                if path.exists() { return Ok(false); }
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
                }
                let tmp = path.with_extension("tmp");
                {
                    use std::io::Write;
                    let file = std::fs::File::create(&tmp).map_err(StoreError::Io)?;
                    let mut w = std::io::BufWriter::new(file);
                    w.write_all(content).map_err(StoreError::Io)?;
                    let f = w.into_inner().map_err(|e| StoreError::Io(e.into_error()))?;
                    if self.fsync { f.sync_all().map_err(StoreError::Io)?; }
                }
                std::fs::rename(&tmp, &path).map_err(StoreError::Io)?;
                if self.fsync {
                    if let Some(p) = path.parent() {
                        if let Ok(d) = std::fs::File::open(p) { let _ = d.sync_all(); }
                    }
                }
                Ok(true)
            }
        }
    }

    pub(crate) fn blob_get_impl(&self, sigma: &str) -> Result<Vec<u8>, StoreError> {
        match &self.blob_encryptor {
            Some(enc) => {
                let txn = self.db.begin_read().map_err(Self::redb_err)?;
                let table = txn.open_table(BINDING_RECORDS).map_err(Self::redb_err)?;
                let val = table.get(sigma).map_err(Self::redb_err)?
                    .ok_or_else(|| StoreError::NotFound(sigma.to_string()))?;
                let b = decode_binding(val.value())?;
                drop(table);
                drop(txn);

                let path = self.kappa_path(&b.kappa)?;
                let disk_bytes = std::fs::read(&path).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        StoreError::NotFound(sigma.to_string())
                    } else { StoreError::Io(e) }
                })?;

                enc.decrypt_all(sigma, &disk_bytes, &b.base_nonce, b.plaintext_size)
                    .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))
            }
            None => {
                let path = kappa_core::kappa::blob_path_for(&self.blob_root, sigma)?;
                std::fs::read(&path).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        StoreError::NotFound(sigma.to_string())
                    } else { StoreError::Io(e) }
                })
            }
        }
    }

    pub(crate) fn blob_exists_impl(&self, sigma: &str) -> Result<bool, StoreError> {
        // Check compression records first (cheapest: single redb read)
        {
            let txn = self.db.begin_read().map_err(Self::redb_err)?;
            let table = txn.open_table(COMPRESSION_RECORDS).map_err(Self::redb_err)?;
            if table.get(sigma).map_err(Self::redb_err)?.is_some() {
                return Ok(true);
            }
        }
        if self.encryption_key.is_some() {
            let txn = self.db.begin_read().map_err(Self::redb_err)?;
            let table = txn.open_table(BINDING_RECORDS).map_err(Self::redb_err)?;
            Ok(table.get(sigma).map_err(Self::redb_err)?.is_some())
        } else {
            Ok(kappa_core::kappa::blob_path_for(&self.blob_root, sigma)?.exists())
        }
    }

    pub(crate) fn blob_delete_impl(&self, sigma: &str) -> Result<(), StoreError> {
        if self.encryption_key.is_some() {
            let kappa_to_delete;
            {
                let txn = self.db.begin_read().map_err(Self::redb_err)?;
                let table = txn.open_table(BINDING_RECORDS).map_err(Self::redb_err)?;
                match table.get(sigma).map_err(Self::redb_err)? {
                    Some(v) => { kappa_to_delete = Some(decode_binding(v.value())?.kappa); }
                    None => { return Ok(()); }
                }
            }
            // Remove binding record
            let txn = self.db.begin_write().map_err(Self::redb_err)?;
            {
                let mut table = txn.open_table(BINDING_RECORDS).map_err(Self::redb_err)?;
                table.remove(sigma).map_err(Self::redb_err)?;
            }
            txn.commit().map_err(Self::redb_err)?;
            // Remove file
            if let Some(k) = kappa_to_delete {
                let path = self.kappa_path(&k)?;
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(StoreError::Io(e)),
                }
            }
            Ok(())
        } else {
            let path = kappa_core::kappa::blob_path_for(&self.blob_root, sigma)?;
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(StoreError::Io(e)),
            }
        }
    }

    pub(crate) fn blob_size_impl(&self, sigma: &str) -> Result<u64, StoreError> {
        // Check compression records first: return uncompressed_size
        {
            let txn = self.db.begin_read().map_err(Self::redb_err)?;
            let table = txn.open_table(COMPRESSION_RECORDS).map_err(Self::redb_err)?;
            if let Some(val) = table.get(sigma).map_err(Self::redb_err)? {
                let cr = decode_compression_record(val.value())?;
                return Ok(cr.uncompressed_size);
            }
        }
        if self.encryption_key.is_some() {
            let txn = self.db.begin_read().map_err(Self::redb_err)?;
            let table = txn.open_table(BINDING_RECORDS).map_err(Self::redb_err)?;
            let val = table.get(sigma).map_err(Self::redb_err)?
                .ok_or_else(|| StoreError::NotFound(sigma.to_string()))?;
            let b = decode_binding(val.value())?;
            Ok(b.plaintext_size)
        } else {
            let path = kappa_core::kappa::blob_path_for(&self.blob_root, sigma)?;
            std::fs::metadata(&path).map(|m| m.len()).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StoreError::NotFound(sigma.to_string())
                } else { StoreError::Io(e) }
            })
        }
    }

    pub(crate) fn blob_open_impl(&self, sigma: &str) -> Result<Box<dyn kappa_core::store::BlobReader>, StoreError> {
        if let Some(enc) = &self.blob_encryptor {
            // Streaming frame-decrypting reader. One 64KB frame in memory
            // at a time. Plaintext never touches disk. RSS bounded.
            let txn = self.db.begin_read().map_err(Self::redb_err)?;
            let table = txn.open_table(BINDING_RECORDS).map_err(Self::redb_err)?;
            let val = table.get(sigma).map_err(Self::redb_err)?
                .ok_or_else(|| StoreError::NotFound(sigma.to_string()))?;
            let b = decode_binding(val.value())?;
            drop(table);
            drop(txn);

            let path = self.kappa_path(&b.kappa)?;
            let file = std::fs::File::open(&path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StoreError::NotFound(sigma.to_string())
                } else { StoreError::Io(e) }
            })?;

            // Construct an independent BlobEncryptor for the reader to own
            let reader_enc = enc.clone_for_reader()
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;

            Ok(Box::new(crate::frame_reader::FrameDecryptingReader::new(
                file,
                reader_enc,
                b.base_nonce,
                sigma.to_string(),
                b.plaintext_size,
            )))
        } else {
            // Zero-copy: return raw filesystem File handle
            let path = kappa_core::kappa::blob_path_for(&self.blob_root, sigma)?;
            let file = std::fs::File::open(&path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StoreError::NotFound(sigma.to_string())
                } else { StoreError::Io(e) }
            })?;
            Ok(Box::new(file))
        }
    }

    pub(crate) fn blob_get_range_impl(
        &self,
        sigma: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        if let Some(enc) = &self.blob_encryptor {
            // Framed AEAD range read: decrypt only needed frames
            let txn = self.db.begin_read().map_err(Self::redb_err)?;
            let table = txn.open_table(BINDING_RECORDS).map_err(Self::redb_err)?;
            let val = table.get(sigma).map_err(Self::redb_err)?
                .ok_or_else(|| StoreError::NotFound(sigma.to_string()))?;
            let b = decode_binding(val.value())?;
            drop(table);
            drop(txn);

            let path = self.kappa_path(&b.kappa)?;
            let disk_bytes = std::fs::read(&path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StoreError::NotFound(sigma.to_string())
                } else { StoreError::Io(e) }
            })?;

            enc.decrypt_range(sigma, &disk_bytes, &b.base_nonce, b.plaintext_size, offset, length)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))
        } else {
            use std::io::{Read, Seek, SeekFrom};
            let path = kappa_core::kappa::blob_path_for(&self.blob_root, sigma)?;
            let mut file = std::fs::File::open(&path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StoreError::NotFound(sigma.to_string())
                } else { StoreError::Io(e) }
            })?;
            file.seek(SeekFrom::Start(offset)).map_err(StoreError::Io)?;
            let mut buf = vec![0u8; length as usize];
            let n = file.read(&mut buf).map_err(StoreError::Io)?;
            buf.truncate(n);
            Ok(buf)
        }
    }

    pub(crate) fn blob_list_impl(&self) -> Result<Vec<String>, StoreError> {
        if self.encryption_key.is_some() {
            let txn = self.db.begin_read().map_err(Self::redb_err)?;
            let table = txn.open_table(BINDING_RECORDS).map_err(Self::redb_err)?;
            let mut sigmas: Vec<String> = table.iter().map_err(Self::redb_err)?
                .filter_map(|item| item.ok().map(|(k, _)| k.value().to_string()))
                .collect();
            sigmas.sort();
            Ok(sigmas)
        } else {
            let mut kappas = Vec::new();
            let Ok(algo_entries) = std::fs::read_dir(&self.blob_root) else {
                return Ok(kappas);
            };
            for algo_entry in algo_entries {
                let algo_entry = algo_entry.map_err(StoreError::Io)?;
                if !algo_entry.file_type().map_err(StoreError::Io)?.is_dir() { continue; }
                let algo = algo_entry.file_name().to_string_lossy().to_string();
                for s1 in std::fs::read_dir(algo_entry.path()).map_err(StoreError::Io)? {
                    let s1 = s1.map_err(StoreError::Io)?;
                    if !s1.file_type().map_err(StoreError::Io)?.is_dir() { continue; }
                    for s2 in std::fs::read_dir(s1.path()).map_err(StoreError::Io)? {
                        let s2 = s2.map_err(StoreError::Io)?;
                        if !s2.file_type().map_err(StoreError::Io)?.is_dir() { continue; }
                        for blob in std::fs::read_dir(s2.path()).map_err(StoreError::Io)? {
                            let blob = blob.map_err(StoreError::Io)?;
                            let name = blob.file_name().to_string_lossy().to_string();
                            if name.ends_with(".tmp") { continue; }
                            kappas.push(format!("{}:{}", algo, name));
                        }
                    }
                }
            }
            kappas.sort();
            Ok(kappas)
        }
    }

    // -- Compression-transparent blob storage -----------------------------------

    pub(crate) fn ingest_compressed_impl(
        &self,
        uncompressed_hash: &str,
        compressed_content: &[u8],
        compression: &str,
        uncompressed_size: u64,
    ) -> Result<kappa_core::store::IngestResult, StoreError> {
        // Hash the compressed content for the storage kappa
        let kappa = kappa_from_bytes(compressed_content);

        // Write compressed bytes to disk at kappa path
        let path = kappa_core::kappa::blob_path_for(&self.blob_root, &kappa)?;
        let newly_stored = if path.exists() {
            false
        } else {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
            }
            let tmp = path.with_extension("tmp");
            {
                use std::io::Write;
                let file = std::fs::File::create(&tmp).map_err(StoreError::Io)?;
                let mut w = std::io::BufWriter::new(file);
                w.write_all(compressed_content).map_err(StoreError::Io)?;
                let f = w.into_inner().map_err(|e| StoreError::Io(e.into_error()))?;
                if self.fsync { f.sync_all().map_err(StoreError::Io)?; }
            }
            std::fs::rename(&tmp, &path).map_err(StoreError::Io)?;
            if self.fsync {
                if let Some(p) = path.parent() {
                    if let Ok(d) = std::fs::File::open(p) { let _ = d.sync_all(); }
                }
            }
            true
        };

        // Insert compression record: uncompressed_hash -> (kappa, algo, size)
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut table = txn.open_table(COMPRESSION_RECORDS).map_err(Self::redb_err)?;
            let rec = encode_compression_record(&kappa, compression, uncompressed_size);
            table.insert(uncompressed_hash, rec.as_slice()).map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;

        Ok(kappa_core::store::IngestResult::new(kappa, newly_stored))
    }

    pub(crate) fn blob_open_compressed_impl(
        &self,
        uncompressed_hash: &str,
    ) -> Result<Box<dyn kappa_core::store::BlobReader>, StoreError> {
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(COMPRESSION_RECORDS).map_err(Self::redb_err)?;
        let val = table.get(uncompressed_hash).map_err(Self::redb_err)?
            .ok_or_else(|| StoreError::NotFound(uncompressed_hash.to_string()))?;
        let cr = decode_compression_record(val.value())?;
        drop(table);
        drop(txn);

        let path = kappa_core::kappa::blob_path_for(&self.blob_root, &cr.kappa)?;
        let file = std::fs::File::open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(uncompressed_hash.to_string())
            } else { StoreError::Io(e) }
        })?;
        Ok(Box::new(file))
    }

    pub(crate) fn blob_open_decompressed_impl(
        &self,
        uncompressed_hash: &str,
    ) -> Result<Box<dyn kappa_core::store::BlobReader>, StoreError> {
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(COMPRESSION_RECORDS).map_err(Self::redb_err)?;
        let val = table.get(uncompressed_hash).map_err(Self::redb_err)?
            .ok_or_else(|| StoreError::NotFound(uncompressed_hash.to_string()))?;
        let cr = decode_compression_record(val.value())?;
        drop(table);
        drop(txn);

        let path = kappa_core::kappa::blob_path_for(&self.blob_root, &cr.kappa)?;
        let compressed = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(uncompressed_hash.to_string())
            } else { StoreError::Io(e) }
        })?;

        let decompressed = crate::decompress_reader::decompress(&compressed, &cr.algorithm)?;
        Ok(Box::new(std::io::Cursor::new(decompressed)))
    }

    // -- Blob metadata (redb BLOB_META table) ---------------------------------

    pub(crate) fn blob_put_meta_impl(
        &self, kappa: &str, key: &str, value: &[u8],
    ) -> Result<(), StoreError> {
        let db_key = format!("{}\x00{}", kappa, key);
        let stored_value: Vec<u8> = match &self.table_encryptor {
            Some(enc) => enc.encrypt_value(&db_key, value)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?,
            None => value.to_vec(),
        };
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut table = txn.open_table(BLOB_META).map_err(Self::redb_err)?;
            table.insert(db_key.as_str(), stored_value.as_slice()).map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    pub(crate) fn blob_get_meta_impl(
        &self, kappa: &str, key: &str,
    ) -> Result<Vec<u8>, StoreError> {
        let db_key = format!("{}\x00{}", kappa, key);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(BLOB_META).map_err(Self::redb_err)?;
        let raw = table.get(db_key.as_str()).map_err(Self::redb_err)?
            .map(|v| v.value().to_vec())
            .ok_or_else(|| StoreError::NotFound(format!("meta {}:{}", kappa, key)))?;
        match &self.table_encryptor {
            Some(enc) => enc.decrypt_value(&db_key, &raw)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string()))),
            None => Ok(raw),
        }
    }

    pub(crate) fn blob_delete_meta_impl(
        &self, kappa: &str, key: &str,
    ) -> Result<(), StoreError> {
        let db_key = format!("{}\x00{}", kappa, key);
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut table = txn.open_table(BLOB_META).map_err(Self::redb_err)?;
            table.remove(db_key.as_str()).map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    // -- Namespace-scoped metadata (redb NS_META multimap) --------------------

    pub(crate) fn meta_set_impl(
        &self, ns: &str, kappa: &str, key: &str, value: &str,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut ns_table = txn.open_table(NAMESPACES).map_err(Self::redb_err)?;
            ns_table.insert(ns, ()).map_err(Self::redb_err)?;
            let db_key = format!("{}\x00{}\x00{}", ns, key, value);
            let stored_kappa = match &self.table_encryptor {
                Some(enc) => {
                    let encrypted = enc.encrypt_value(&db_key, kappa.as_bytes())
                        .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
                    hex::encode(&encrypted)
                }
                None => kappa.to_string(),
            };
            let mut table = txn.open_multimap_table(crate::tables::NS_META).map_err(Self::redb_err)?;
            table.insert(db_key.as_str(), stored_kappa.as_str()).map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    pub(crate) fn meta_query_impl(
        &self, ns: &str, key: &str, value: &str,
    ) -> Result<Vec<String>, StoreError> {
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_multimap_table(crate::tables::NS_META).map_err(Self::redb_err)?;
        let mut results = Vec::new();

        let decrypt_multimap_value = |db_key: &str, raw: &str| -> Result<String, StoreError> {
            match &self.table_encryptor {
                Some(enc) => {
                    let bytes = hex::decode(raw)
                        .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
                    let pt = enc.decrypt_value(db_key, &bytes)
                        .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
                    String::from_utf8(pt)
                        .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))
                }
                None => Ok(raw.to_string()),
            }
        };

        if value.is_empty() {
            let prefix = format!("{}\x00{}\x00", ns, key);
            match Self::prefix_successor(prefix.as_bytes()) {
                Some(end_bytes) => {
                    let end_str = String::from_utf8(end_bytes)
                        .map_err(|_| StoreError::Io(std::io::Error::other("utf8")))?;
                    for entry in table.range::<&str>(prefix.as_str()..end_str.as_str()).map_err(Self::redb_err)? {
                        let (k, values) = entry.map_err(Self::redb_err)?;
                        let db_key = k.value();
                        for v in values {
                            let raw = v.map_err(Self::redb_err)?.value().to_string();
                            results.push(decrypt_multimap_value(db_key, &raw)?);
                        }
                    }
                }
                None => {
                    for entry in table.range::<&str>(prefix.as_str()..).map_err(Self::redb_err)? {
                        let (k, values) = entry.map_err(Self::redb_err)?;
                        if !k.value().starts_with(&prefix) { break; }
                        let db_key = k.value();
                        for v in values {
                            let raw = v.map_err(Self::redb_err)?.value().to_string();
                            results.push(decrypt_multimap_value(db_key, &raw)?);
                        }
                    }
                }
            }
        } else {
            let db_key = format!("{}\x00{}\x00{}", ns, key, value);
            for v in table.get(db_key.as_str()).map_err(Self::redb_err)? {
                let raw = v.map_err(Self::redb_err)?.value().to_string();
                results.push(decrypt_multimap_value(&db_key, &raw)?);
            }
        }

        results.sort();
        results.dedup();
        Ok(results)
    }
}
