//! DHT record persistence through the Transport trait.
//!
//! Every operation goes through Transport::create_record, open_record,
//! write_record, read_record, watch_record, inspect_record, close_record,
//! delete_record. Zero veilid_core types.

use std::sync::Arc;

use tracing::{debug, info};

use rekindle_types::transport::{InspectResult, OpenRecord, RecordSchema, Transport, WatchToken};

use crate::error::TransportError;

/// Handle to an open DHT record with its writer keypair bytes.
#[derive(Debug, Clone)]
pub struct DhtRecord {
    pub key: String,
    pub writer_bytes: Vec<u8>,
}

/// DHT persistence through the Transport trait.
pub struct DhtPersistence<T: Transport> {
    transport: Arc<T>,
}

impl<T: Transport> DhtPersistence<T> {
    pub fn new(transport: Arc<T>) -> Self {
        Self { transport }
    }

    /// Create a single-writer DHT record.
    pub async fn create_record(&self, subkey_count: u32) -> Result<DhtRecord, TransportError> {
        let schema = RecordSchema::SingleWriter { subkey_count };
        let (record, writer_bytes) = self
            .transport
            .create_record(schema)
            .await
            .map_err(TransportError::from)?;

        let key = record.key().to_string();
        debug!(
            key = key.as_str(),
            subkeys = subkey_count,
            "DHT record created"
        );

        Ok(DhtRecord { key, writer_bytes })
    }

    /// Create a multi-writer DHT record.
    pub async fn create_multi_writer(
        &self,
        owner_subkeys: u16,
        member_subkeys: u16,
        member_keys: Vec<[u8; 32]>,
    ) -> Result<DhtRecord, TransportError> {
        let schema = RecordSchema::MultiWriter {
            owner_subkeys,
            member_subkeys,
            member_keys,
        };
        let (record, writer_bytes) = self
            .transport
            .create_record(schema)
            .await
            .map_err(TransportError::from)?;

        let key = record.key().to_string();
        debug!(key = key.as_str(), "DHT multi-writer record created");

        Ok(DhtRecord { key, writer_bytes })
    }

    /// Open a record for reading.
    pub async fn open_readonly(&self, key: &str) -> Result<OpenRecord, TransportError> {
        self.transport
            .open_record(key, None)
            .await
            .map_err(TransportError::from)
    }

    /// Open a record for writing.
    pub async fn open_writable(
        &self,
        key: &str,
        writer_bytes: &[u8],
    ) -> Result<OpenRecord, TransportError> {
        self.transport
            .open_record(key, Some(writer_bytes))
            .await
            .map_err(TransportError::from)
    }

    /// Write data to a subkey.
    pub async fn write(
        &self,
        record: &OpenRecord,
        subkey: u32,
        data: &[u8],
        writer_bytes: Option<&[u8]>,
    ) -> Result<(), TransportError> {
        self.transport
            .write_record(record, subkey, data, writer_bytes)
            .await
            .map_err(TransportError::from)
    }

    /// Read a subkey value.
    pub async fn read(
        &self,
        record: &OpenRecord,
        subkey: u32,
        force_refresh: bool,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        self.transport
            .read_record(record, subkey, force_refresh)
            .await
            .map_err(TransportError::from)
    }

    /// Watch subkeys for changes. Changes arrive as InboundEvent::RecordChange.
    pub async fn watch(
        &self,
        record: &OpenRecord,
        subkeys: &[u32],
    ) -> Result<WatchToken, TransportError> {
        self.transport
            .watch_record(record, subkeys)
            .await
            .map_err(TransportError::from)
    }

    /// Cancel a watch.
    pub async fn cancel_watch(&self, token: WatchToken) -> Result<(), TransportError> {
        self.transport
            .cancel_watch(token)
            .await
            .map_err(TransportError::from)
    }

    /// Inspect subkey sequence numbers.
    pub async fn inspect(
        &self,
        record: &OpenRecord,
        subkeys: &[u32],
    ) -> Result<InspectResult, TransportError> {
        self.transport
            .inspect_record(record, subkeys)
            .await
            .map_err(TransportError::from)
    }

    /// Close a record.
    pub async fn close(&self, record: OpenRecord) -> Result<(), TransportError> {
        self.transport
            .close_record(record)
            .await
            .map_err(TransportError::from)
    }

    /// Delete a record from local storage.
    pub async fn delete(&self, key: &str) -> Result<(), TransportError> {
        self.transport
            .delete_record(key)
            .await
            .map_err(TransportError::from)
    }

    /// Publish epoch root bytes to a DHT record subkey.
    pub async fn publish_epoch(
        &self,
        dht_record: &DhtRecord,
        subkey: u32,
        epoch_bytes: &[u8],
    ) -> Result<(), TransportError> {
        let record = self
            .open_writable(&dht_record.key, &dht_record.writer_bytes)
            .await?;
        self.write(&record, subkey, epoch_bytes, Some(&dht_record.writer_bytes))
            .await?;
        info!(
            key = dht_record.key.as_str(),
            subkey,
            len = epoch_bytes.len(),
            "epoch published to DHT"
        );
        Ok(())
    }
}
