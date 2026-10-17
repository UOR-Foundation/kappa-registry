use std::io;

/// Owned forwarding adapter for caller-provided storage implementations.
#[derive(Debug)]
pub struct OwnedBackend(pub Box<dyn redb::StorageBackend>);

impl redb::StorageBackend for OwnedBackend {
    fn len(&self) -> io::Result<u64> {
        self.0.len()
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read(offset, out)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.0.set_len(len)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.0.sync_data()
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.0.write(offset, data)
    }

    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}
