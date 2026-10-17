use kappa_store::blob_admission::verify_decoded;
use kappa_types::{Kappa, StoreError};
use std::io::{self, Read};

struct Expansion {
    delivered: usize,
    largest_request: usize,
}

impl Read for Expansion {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.largest_request = self.largest_request.max(buffer.len());
        buffer.fill(42);
        self.delivered += buffer.len();
        Ok(buffer.len())
    }
}

#[test]
fn excess_expansion_stops_at_one_byte_past_the_declared_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    for size in [0, 1, 16384, 65537] {
        let mut source = Expansion {
            delivered: 0,
            largest_request: 0,
        };
        assert!(matches!(
            verify_decoded(&Kappa::sha256(&[]), size, &mut source),
            Err(StoreError::Rejected(_))
        ));
        assert_eq!(source.delivered, usize::try_from(size)? + 1);
        assert!(source.largest_request <= 16384);
    }
    Ok(())
}

#[test]
fn source_failure_preserves_io_identity_even_after_exact_content() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(5))
        }
    }
    match verify_decoded(&Kappa::sha256(&[]), 0, &mut Failing) {
        Err(StoreError::Io(error)) => assert_eq!(error.raw_os_error(), Some(5)),
        other => panic!("lost source failure: {other:?}"),
    }
}

#[test]
fn exact_identity_requires_eof_and_retries_interrupted_reads() -> Result<(), StoreError> {
    struct Interrupted<'a> {
        bytes: &'a [u8],
        interrupt: bool,
    }
    impl Read for Interrupted<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.interrupt {
                self.interrupt = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.bytes.read(buffer)
        }
    }
    let bytes = b"bounded decoded content";
    let key = Kappa::sha256(bytes);
    verify_decoded(
        &key,
        bytes.len() as u64,
        &mut Interrupted {
            bytes,
            interrupt: true,
        },
    )?;
    assert!(verify_decoded(&key, bytes.len() as u64 + 1, &mut bytes.as_slice()).is_err());
    assert!(
        verify_decoded(
            &Kappa::sha256(b"different"),
            bytes.len() as u64,
            &mut bytes.as_slice()
        )
        .is_err()
    );
    Ok(())
}
