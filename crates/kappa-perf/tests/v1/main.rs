//! kappa-perf test harness: correctness tests from KAPPA-PERF-001.
//!
//! Coverage:
//! - PERF-EPO-001 through PERF-EPO-011 (epoch, merkle, digest, GC)
//! - PERF-EPO-009 (authenticated replay, C-10)
//! - PERF-HSH-001 through PERF-HSH-005 (hash vectors, streaming, complement)
//! - PERF-CON-001 (concurrent writers publish in issuance order)
//! - PERF-CON-002 (deadline exceeded)
//! - PERF-CON-004 (authority clock, backwards time, reservation)
//! - PERF-STO-001 through PERF-STO-003 (store parity, isolation, operation replay)
//! - PERF-STO-007 (transaction capacity limits)
//! - PERF-IDN-002 (trust state machine)
//! - PERF-IDN-003 (succession dual signature, chain limits)
//! - PERF-IDN-004 through PERF-IDN-006 (delegation, projection, session)
//! - PERF-IDN-007 (revocation fails closed)
//! - PERF-IDN-008 (handle verification and attestation)
//! - PERF-SUC-002, PERF-SUC-015 (byte-identical builds, recovery)

mod adversary;
mod authenticated_replay;
mod authority_clock;
mod byte_identical;
mod common;
mod concurrent_writers;
mod deadline;
mod delegation_lattice;
mod epoch_golden;
mod gc_reachability;
mod handle_flows;
mod hash_properties;
mod namespace_concurrency;
mod operation_replay;
mod revocation_closed;
mod store_parity;
mod succession_chain;
mod transaction_limits;
mod trust_machine;
