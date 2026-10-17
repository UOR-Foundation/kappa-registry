//! Per-namespace writer gates.
//!
//! An execution of one namespace holds that namespace's gate for its whole
//! life, through its publication and the bookkeeping that follows the view
//! store, so two executions of the same namespace never run concurrently
//! while executions of different namespaces proceed in parallel. The gate
//! lives in the namespace's slot, which the store keeps for the
//! namespace's lifetime, so a namespace never has two gates.

use std::sync::{Arc, Condvar, Mutex, PoisonError};

#[derive(Default)]
pub struct Gate {
    held: Mutex<bool>,
    released: Condvar,
}

/// Exclusive publication ownership of one namespace; released on drop.
pub struct WriterToken {
    gate: Arc<Gate>,
}

impl Drop for WriterToken {
    fn drop(&mut self) {
        // The guarded flag is set and cleared in single statements; a lock
        // a panicking holder poisoned still guards a coherent flag.
        let mut held = self
            .gate
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *held = false;
        drop(held);
        self.gate.released.notify_one();
    }
}

impl Gate {
    /// Hold the gate if it is free now.
    pub fn try_acquire(self: &Arc<Self>) -> Option<WriterToken> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if *held {
            return None;
        }
        *held = true;
        drop(held);
        Some(WriterToken {
            gate: Arc::clone(self),
        })
    }

    /// Block until the gate is free, then hold it.
    pub fn acquire(self: &Arc<Self>) -> WriterToken {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        while *held {
            held = self
                .released
                .wait(held)
                .unwrap_or_else(PoisonError::into_inner);
        }
        *held = true;
        drop(held);
        WriterToken {
            gate: Arc::clone(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gate_admits_one_holder_and_gates_are_independent() {
        let first = Arc::new(Gate::default());
        let second = Arc::new(Gate::default());
        let held = first.acquire();
        // Another namespace's gate is free while the first is held.
        drop(second.acquire());
        let contended = Arc::clone(&first);
        let (started, start) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            started.send(()).ok();
            drop(contended.acquire());
        });
        start.recv().ok();
        assert!(
            !waiter.is_finished(),
            "a second holder of one gate was admitted"
        );
        drop(held);
        assert!(waiter.join().is_ok());
    }
}
