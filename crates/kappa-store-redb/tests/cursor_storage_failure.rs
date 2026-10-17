use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kappa_cursor::FallibleCursor;
use kappa_store_redb::redb_cursor::RedbCursor;
use redb::{ReadableDatabase, StorageBackend, TableDefinition};

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("cursor_failure");

#[derive(Debug)]
struct FaultBackend {
    file: Mutex<std::fs::File>,
    fail_reads: Arc<AtomicBool>,
}

impl FaultBackend {
    fn file(&self) -> io::Result<std::sync::MutexGuard<'_, std::fs::File>> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("backend file lock poisoned"))
    }
}

impl StorageBackend for FaultBackend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.file()?.metadata()?.len())
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(io::Error::other("injected cursor read failure"));
        }
        let mut file = self.file()?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(out)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.file()?.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.file()?.sync_all()
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut file = self.file()?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)
    }
}

fn database() -> Result<(redb::Database, Arc<AtomicBool>), Box<dyn std::error::Error>> {
    let fail_reads = Arc::new(AtomicBool::new(false));
    let backend = FaultBackend {
        file: Mutex::new(tempfile::tempfile()?),
        fail_reads: fail_reads.clone(),
    };
    // Like redb's disk-corruption tests, faults must reach backing storage;
    // a successful cached read would not exercise failure propagation.
    let db = redb::Database::builder()
        .set_cache_size(0)
        .create_with_backend(backend)?;
    let write = db.begin_write()?;
    {
        let mut table = write.open_table(TABLE)?;
        for number in 0..2048u32 {
            table.insert(number.to_be_bytes().as_slice(), &[7; 1024][..])?;
        }
    }
    write.commit()?;
    Ok((db, fail_reads))
}

#[test]
fn navigation_failure_is_sticky_and_never_becomes_exhaustion()
-> Result<(), Box<dyn std::error::Error>> {
    let (db, fail_reads) = database()?;
    let read = db.begin_read()?;
    let table = read.open_table(TABLE)?;
    let mut cursor = RedbCursor::new(table)?;
    drop(read);
    fail_reads.store(true, Ordering::SeqCst);
    loop {
        match cursor.advance() {
            Err(error) => {
                assert!(error.to_string().contains("injected cursor read failure"));
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("backing storage failure was reported as exhaustion"),
        }
    }
    fail_reads.store(false, Ordering::SeqCst);
    for error in [
        cursor.key().err().ok_or("key lost sticky failure")?,
        cursor
            .advance()
            .err()
            .ok_or("advance lost sticky failure")?,
        cursor
            .seek(&0u32.to_be_bytes())
            .err()
            .ok_or("seek lost sticky failure")?,
    ] {
        match error {
            kappa_types::StoreError::Io(error) => {
                assert_eq!(error.kind(), io::ErrorKind::Other);
                assert!(error.to_string().contains("injected cursor read failure"));
            }
            other => panic!("lost retained storage error category: {other}"),
        }
    }
    Ok(())
}

#[test]
fn rerange_failure_cannot_reuse_the_previous_head() -> Result<(), Box<dyn std::error::Error>> {
    let (db, fail_reads) = database()?;
    let read = db.begin_read()?;
    let mut cursor = RedbCursor::new(read.open_table(TABLE)?)?;
    fail_reads.store(true, Ordering::SeqCst);
    assert!(cursor.seek(&2047u32.to_be_bytes()).is_err());
    fail_reads.store(false, Ordering::SeqCst);
    assert!(cursor.key().is_err());
    assert!(cursor.advance().is_err());
    Ok(())
}
