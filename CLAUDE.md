# kappa-registry

A conforming kappa-Distribution /v2/ registry. Filesystem-backed, single-node,
all five conformance levels.

## Conventions

- Conventional commits. Objective, diff-derived, verbose technical bodies.
  No AI attribution. No PII. No `Co-Authored-By`.
- Read files in full before modification.
- Do not commit secrets or generated credentials.
- No em dashes, en dashes, arrows, ellipsis, or math operators in source.
  Use ASCII equivalents.
- File line count should not exceed 500 lines.

## Quality gates

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

All three must pass with zero warnings before any commit.

## Toolchain

Hermetic via Nix. `flake.nix` provides Rust 1.92 + musl targets via the
Konductor flake. Do not install via pip/npm/cargo/brew.

## Architecture

- `src/lib.rs` - library crate with app() and dispatch
- `src/main.rs` - binary entrypoint
- `src/handlers/` - HTTP handlers per conformance level
- `src/store/fs/` - filesystem-backed storage
- `src/routes/` - URL parsing and Route enum
- `src/kappa.rs` - KappaLabel type with independent hash computation
- `tests/integration/` - black-box integration tests against live server
