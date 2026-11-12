//! Writer-excluded persistence and discharge of durable publication custody.

use super::*;

fn custody_context(instance: &StorageInstance) -> String {
    bound("custody", &instance.key())
}

fn check_exclusion(writer: &WriterToken, instance: &StorageInstance) -> Result<(), StoreError> {
    if writer.instance() != instance {
        return Err(StoreError::Internal(format!(
            "custody of {instance} written under the writer gate of {}",
            writer.instance()
        )));
    }
    Ok(())
}

impl PersistentStore {
    /// Store the complete record under its instance writer, bounded before I/O.
    pub(crate) fn store_custody(
        &self,
        writer: &WriterToken,
        instance: &StorageInstance,
        record: &CustodyRecord,
    ) -> Result<(), StoreError> {
        check_exclusion(writer, instance)?;
        if record.namespace()? != *instance.namespace()
            || instance.incarnation() != Incarnation::Known(record.incarnation()?)
        {
            return Err(StoreError::Conflict(format!(
                "custody record written for {instance} names another instance"
            )));
        }
        // A previous persistence failure may have left a live override.
        // Advance it before any fallible encoding or I/O: otherwise a later
        // load could prefer Prepared over a returned signature on disk and
        // authorize a second invocation of the same coordinate.
        if let Some(live) = self
            .live_custody
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(instance)
        {
            live.clone_from(record);
        }
        let sealed = self.encrypt_bytes(&custody_context(instance), &canonical_bytes(record))?;
        if sealed.len() as u64 > self.custody_record_bytes {
            return Err(StoreError::CapacityExceeded(format!(
                "custody of {instance} holds {} bytes, above {}",
                sealed.len(),
                self.custody_record_bytes
            )));
        }
        Kind::Custody.store(self.namespaces.root(), instance, &sealed)
    }

    /// Load bounded custody, preferring progress whose persistence failed on
    /// this handle. Validate the complete instance before returning it.
    pub(crate) fn load_custody(
        &self,
        instance: &StorageInstance,
        meter: &mut dyn Meter,
    ) -> Result<Option<CustodyRecord>, StoreError> {
        let bound = self.custody_record_bytes;
        {
            let live = self
                .live_custody
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(record) = live.get(instance) {
                meter.charge(Dimension::BytesAllocated, bound.saturating_mul(2))?;
                return Ok(Some(record.clone()));
            }
        }
        meter.charge(Dimension::Handles, 1)?;
        meter.admits(&[
            (Dimension::BytesRead, bound),
            (Dimension::BytesAllocated, bound.saturating_mul(2)),
            (Dimension::BytesDecoded, bound),
        ])?;
        let Some(sealed) = Kind::Custody.load(self.namespaces.root(), instance, bound)? else {
            return Ok(None);
        };
        let length = sealed.len() as u64;
        meter.consume(Dimension::BytesRead, length)?;
        meter.consume(Dimension::BytesAllocated, length.saturating_mul(2))?;
        meter.consume(Dimension::BytesDecoded, length)?;
        let record: CustodyRecord =
            from_canonical(&self.decrypt_bytes(&custody_context(instance), &sealed)?)?;
        if record.version != CUSTODY_VERSION {
            return Err(StoreError::Internal(format!(
                "custody of {instance} has unknown version {}",
                record.version
            )));
        }
        if record.namespace()? != *instance.namespace()
            || instance.incarnation() != Incarnation::Known(record.incarnation()?)
        {
            return Err(StoreError::Internal(format!(
                "custody of {instance} names another instance"
            )));
        }
        Ok(Some(record))
    }

    /// Only exact authenticated committed evidence permits durable discharge.
    pub(crate) fn discharge_custody(
        &self,
        writer: &WriterToken,
        instance: &StorageInstance,
        record: &CustodyRecord,
        committed: &EpochRoot,
        work: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        check_exclusion(writer, instance)?;
        record.check_committed(instance, committed, work, &self.encoding_storage)?;
        Kind::Custody.complete(self.namespaces.root(), instance)?;
        self.live_custody
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(instance);
        self.custody_debt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(instance);
        Ok(())
    }

    pub(crate) fn holds_custody(&self, instance: &StorageInstance) -> Result<bool, StoreError> {
        if self
            .live_custody
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(instance)
        {
            return Ok(true);
        }
        Kind::Custody.holds(self.namespaces.root(), instance)
    }
}

#[cfg(test)]
#[path = "custody_persistence_tests.rs"]
mod tests;
