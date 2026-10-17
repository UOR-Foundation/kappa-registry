# kappa-registry development commands.
#
# Every recipe that builds, tests, benchmarks or runs conformance writes its
# complete, unfiltered output to tmp/logs/<recipe>-<UTC timestamp>.log, with
# tmp/logs/<recipe>.log linking to the newest run (scripts/logged.sh).

set shell := ["bash", "-c"]

# List the common development recipes.
default:
    @just --list

# Format Rust sources.
fmt:
    bash scripts/logged.sh fmt cargo fmt

# Verify formatting without changing files.
fmt-check:
    bash scripts/logged.sh fmt-check cargo fmt --check

# Run Clippy with warnings treated as errors.
clippy:
    bash scripts/logged.sh clippy cargo clippy --workspace --all-targets -- -D warnings

# Run Clippy with every feature enabled (adds veilid, atproto), warnings as errors.
clippy-all:
    bash scripts/logged.sh clippy-all cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run all workspace tests, including the custom BDD target.
test:
    bash scripts/logged.sh test cargo test --workspace

# Run all workspace tests with every feature enabled (adds veilid, atproto), continuing past failures.
test-all:
    bash scripts/logged.sh test-all cargo test --workspace --all-features --no-fail-fast

# Run the kappa-server black-box integration suite; server logs land in
# tmp/logs/it-server/.
it *filter:
    bash scripts/logged.sh it cargo test -p kappa-server --test it {{filter}}

# Run the public-interface Cucumber suite directly.
bdd:
    bash scripts/logged.sh bdd cargo test -p kappa-server --test bdd

# Check every shell script: bash syntax, then shellcheck.
lint-scripts:
    bash scripts/logged.sh lint-scripts bash -c 'for f in scripts/*.sh; do bash -n "$f" || exit 1; done; shellcheck scripts/*.sh'

# Run the local quality gates across default and all-feature builds.
check: fmt-check lint-scripts clippy clippy-all test test-all

# Run the kappa-perf calibration library and correctness suites.
perf-test:
    bash scripts/logged.sh perf-test cargo test -p kappa-perf

# Run calibrated benchmarks: tier smoke|standard|full, bench all|floors|workloads|contention|http.
perf tier="standard" bench="all" *criterion:
    bash scripts/logged.sh perf bash scripts/perf.sh {{tier}} {{bench}} {{ if criterion == "" { "" } else { "-- " + criterion } }}

# Render the performance report from a dataset directory; pass --datasets DIR and --scale results.tsv.
perf-report *args:
    bash scripts/logged.sh perf-report cargo run --release -p kappa-perf --bin perf-report -- {{args}}

# Run memory-contained succinct scale evaluations: profile smoke|baseline|endurance|full.
succinct-scale profile="baseline":
    bash scripts/logged.sh succinct-scale bash scripts/succinct-scale.sh {{profile}}

# One complete performance run into tmp/perf/<timestamp>-<tier>-<profile>/: benchmarks, scale evaluation and report.
perf-run tier="standard" profile="baseline":
    bash scripts/logged.sh perf-run bash scripts/perf-run.sh {{tier}} {{profile}}

# Fuzz the succinct and canonical decoders under AddressSanitizer: target all|trie_deserialize|epoch_deserialize|mutations_decode, seconds per target.
fuzz target="all" seconds="300":
    bash scripts/logged.sh fuzz bash scripts/fuzz.sh {{target}} {{seconds}}

# Build the workspace in debug mode.
build:
    bash scripts/logged.sh build cargo build --workspace

# Build the release binary used by the external conformance scripts.
build-release:
    bash scripts/logged.sh build-release cargo build --release

# Start the registry with the default configuration.
run:
    cargo run

# Run the kappa-Distribution conformance suite from the sibling checkout.
conformance: build-release
    bash scripts/logged.sh conformance ./scripts/conformance.sh

# Run the OCI distribution-spec conformance suite.
oci-conformance: build-release
    bash scripts/logged.sh oci-conformance ./scripts/oci-conformance.sh

# Remove Cargo build artifacts.
clean:
    cargo clean
