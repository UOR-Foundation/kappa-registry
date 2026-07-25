# Agent guidance for kappa-registry

This repository is a Rust Axum service implementing a filesystem-backed Kappa
Distribution `/v2/` registry. Keep changes small, reviewable, and consistent
with the existing dispatcher and handler architecture.

## Rust development

- Use the Rust toolchain supplied by `flake.nix` and `nix develop`. Do not
  install project dependencies with pip, npm, cargo, or brew.
- Run `cargo fmt` on changed Rust files and keep `cargo fmt --check` clean.
- Treat all Clippy warnings as errors:
  `cargo clippy --all-targets -- -D warnings`.
- Prefer idiomatic ownership and borrowing. Avoid unnecessary clones, dynamic
  allocation, and broad locking in hot paths.
- Return typed errors through the existing `AppError` and `StoreError` paths.
  Do not panic on request data, malformed labels, invalid JSON, missing files,
  or storage failures. Use `unwrap` or `expect` only for a proven internal
  invariant, and explain the invariant when it is not obvious.
- Keep blocking filesystem and database work off async executor threads. Follow
  the existing `spawn_blocking` pattern in HTTP handlers.
- Preserve content-addressing, verify-on-write behavior, namespace isolation,
  upload limits, atomic filesystem writes, and transaction cleanup.
- Keep dependencies minimal. When changing dependencies, update `Cargo.lock`
  and verify the full workspace build and tests.
- Add focused unit tests for pure logic and integration tests for HTTP behavior,
  persistence, concurrency, or protocol compatibility. Tests must not depend on
  the checked-in `data/` directory or generated credentials.
- Keep public-interface behavior covered by the Cucumber BDD suite. Every
  user-facing interface, including the registry HTTP API, OpenAPI document,
  Scalar UI, and any future CLI, browser, SDK, or admin interface, must have
  at least one `@status:enforced` scenario under `features/suites/`.
- BDD scenarios must exercise the real public boundary and application wiring,
  not call handlers or storage functions directly. Add the feature, step
  definitions, and `features/README.md` interface mapping together.
- Do not mark a scenario `@status:enforced` until its steps assert behavior and
  pass. The BDD runner fails when an enforced scenario is skipped.
- Do not commit secrets, private keys, generated credentials, temporary stores,
  or conformance reports.
- Keep source files below 500 lines. Use ASCII punctuation in source files.

## Routes and OpenAPI

The route parser and dispatcher are the runtime source of truth:

- Add or update the `Endpoint` variant and parser branch in `src/routes/`.
- Add or update the matching dispatch arm in `src/lib.rs`.
- Add the same method and path to the `ROUTES` catalog in `src/openapi.rs`.
- Include an operation ID, summary, tag, path and query parameters, request
  body media type, response media type, and error response in the OpenAPI entry.
- Document documentation endpoints too, including `/openapi.json`, `/docs`,
  and the Scalar asset route under `/docs/scalar.js`.
- Keep OpenAPI paths synchronized with the actual trailing-slash behavior and
  query parameter names. If a namespace can contain slashes, explain that
  behavior in the operation description or README.
- Add or update an OpenAPI test whenever routes change. The test must verify
  that every runtime route has a corresponding OpenAPI path and method; do not
  rely only on the Scalar page rendering successfully.
- When an endpoint's request or response schema changes, update both the
  OpenAPI catalog and the relevant integration test in the same change.

Before declaring route work complete, verify:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo test --test bdd
```

The equivalent grouped local gate is `just check`; run `just bdd` when changing
or adding a public interface. Keep the `Justfile` recipes and README workflow
examples synchronized with the commands CI actually runs.

For API changes, also smoke-test `/openapi.json` and `/docs` against a locally
started server and inspect the generated OpenAPI document for the changed
operation.

For interface changes, run `cargo test --test bdd` and update the matching
Gherkin scenario in `features/suites/`. The BDD suite is an integration test of
the real application boundary and must cover every public interface.

## Repository conventions

- Use conventional commits with objective, diff-derived technical bodies.
- Do not add AI attribution, PII, or `Co-Authored-By` trailers.
- Read relevant files in full before modifying them.
- Update `README.md` when public behavior, configuration, routes, or developer
  workflows change.
