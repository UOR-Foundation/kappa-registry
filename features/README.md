# Registry BDD suites

Gherkin `.feature` scenarios for the public kappa-registry interfaces. The
scenarios are run by the Cucumber integration test in `tests/bdd.rs` against the
real Axum application and its filesystem-backed store.

## Interface coverage

Every user-facing interface has an enforced scenario in
`features/suites/s0_interfaces/registry.feature`:

- `@interface:http-api` covers the registry protocol under `/v2/`.
- `@interface:openapi` covers the generated OpenAPI document at `/openapi.json`.
- `@interface:scalar` covers the Scalar page at `/docs` and its bundled asset.
- `@interface:passkey` covers the passkey routes under `/passkey/` in
  `features/suites/s0_interfaces/passkey.feature`. It is not tagged
  `@status:enforced`: `tests/bdd.rs` is not compiled by any Cargo target (the
  workspace root has no package, and the runner imports `axum` and a
  `kappa_registry` crate that no longer exist), so `cargo test --test bdd`
  reports no such target. Its scenarios run against the real server binary in
  `crates/kappa-server/tests/integration/passkey_http.rs`.

When a new interface is added, add a tagged feature scenario for it in the same
change. Interface scenarios must exercise the public boundary, not call handler
or storage functions directly.

## Status and running

Scenarios use `@status:enforced` when their steps are implemented and asserted.
The runner fails if an enforced scenario is skipped, so a green BDD run means
the scenario was actually executed.

Run the BDD suite directly:

```sh
cargo test --test bdd
```

The normal workspace test command runs this target as well:

```sh
cargo test --workspace
```
