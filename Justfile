# kappa-registry development commands.

set shell := ["bash", "-c"]

# List the common development recipes.
default:
    @just --list

# Format Rust sources.
fmt:
    cargo fmt

# Verify formatting without changing files.
fmt-check:
    cargo fmt --check

# Run Clippy with warnings treated as errors.
clippy:
    cargo clippy --all-targets -- -D warnings

# Run all workspace tests, including the custom BDD target.
test:
    cargo test --workspace

# Run the public-interface Cucumber suite directly.
bdd:
    cargo test --test bdd

# Run the local quality gates.
check: fmt-check clippy test

# Build the workspace in debug mode.
build:
    cargo build --workspace

# Build the release binary used by the external conformance scripts.
build-release:
    cargo build --release

# Start the registry with the default configuration.
run:
    cargo run

# Run the kappa-Distribution conformance suite from the sibling checkout.
conformance: build-release
    ./scripts/conformance.sh

# Run the OCI distribution-spec conformance suite.
oci-conformance: build-release
    ./scripts/oci-conformance.sh

# Remove Cargo build artifacts.
clean:
    cargo clean
