// kappa-perf: calibration framework, floor measurements, workload benchmarks,
// property tests, loom models, and performance gates.
//
// Architecture informed by:
// - rekindle-transport-ipc calibration (CalibratedSession, dependency graph,
//   physics-derived validation, JSONL dataset-grade records)
// - RFC 9162 Certificate Transparency (merge-delay as conformance)
// - SuRF/FST SIGMOD 2018 (succinct trie performance methodology)
// - CONIKS/SEEMless/Parakeet/OPTIKS (verifiable key directory benchmarks)
// - facebook/akd (append-only authenticated dictionary proofs)
// - etcd performance guide (durable cluster write methodology)
// - Zanzibar/SpiceDB/OpenFGA (authorization check rate methodology)
// - ANN-Benchmarks/VDBBench (recall-QPS Pareto, three-phase streaming)
// - criterion statistical method (slope/mean/median, outlier classification)
// - wrk2/Gil Tene (coordinated-omission correction for open-loop load)
// - KAPPA-PERF-001 specification (grading, evidence classes, host calibration)
//
// Five layers, each independent of the layers above:
// 1. Criterion (external, measurement harness)
// 2. CalibratedSession (orchestration, backfill from criterion, baseline)
// 3. Dependency graph (measurement ordering, skip on missing deps)
// 4. Physics-derived validation (rules that decompose end-to-end into floors)
// 5. JSONL output (dataset-grade records with full provenance)

pub mod bench;
pub mod calibrate;
/// The performance report rendered from recorded datasets.
pub mod report;
pub mod vectors;
