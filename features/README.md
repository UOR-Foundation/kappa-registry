# Registry BDD suites

Gherkin `.feature` scenarios for the public kappa-registry interfaces. The
scenarios are run by the Cucumber integration test in `tests/bdd.rs` against the
real `kappa-server` binary over HTTP, with a fresh temporary persistent store
for each scenario. The test target belongs to the `kappa-server` package.

## Interface coverage

Every user-facing interface has an enforced scenario in
`features/suites/s0_interfaces/registry.feature`:

- `@interface:http-api` covers the registry protocol under `/v2/`.
- `@interface:openapi` covers the generated OpenAPI document at `/openapi.json`.
- `@interface:scalar` covers the Scalar page at `/docs` and its bundled asset.

`features/suites/s0_interfaces/events.feature` maps `@interface:events` to
the HTTP event subscription's cursor rejection and its OpenAPI resume/loss
contract. Its scenarios are awaiting execution before enforcement.

When a new interface is added, add a tagged feature scenario for it in the same
change. Interface scenarios must exercise the public boundary, not call handler
or storage functions directly.

## Status and running

`features/suites/s0_interfaces/signed_identity.feature` maps `@interface:identity`
to real HTTP COSE assertion, revocation, and watermark admission, tampered-field,
wrong-key and cross-type rejection, and persisted resolution after process restart.
The steps are implemented in `tests/bdd_identity.rs`; enforcement requires a
successful execution of these assertions.

`features/suites/s0_interfaces/node_authority.feature` maps
`@interface:node-authority` to node signing-authority rotation and status
through `/_node/authority/rotate` and `/_node/authority`: refusal without
`_root` administration, committed rotations with every follow-up guarantee
holding, retirement of earlier authorities, continued root-token
administration, readiness, and the same state after process restart. The
steps are implemented in `tests/bdd_authority.rs`; the scenarios remain
pending until their assertions have executed successfully.

`features/suites/s0_interfaces/blob_publication.feature` maps `@interface:http-api`
to verified multichunk upload, process termination/restart, and exact full/range
retrieval. Its implemented steps exercise the real server over HTTP; the scenario
remains pending until its assertions have executed successfully.

Scenarios use `@status:enforced` when their steps are implemented and asserted.
The runner fails if an enforced scenario is skipped, so a green BDD run means
the scenario was actually executed.

Run the BDD suite directly:

```sh
cargo test -p kappa-server --test bdd
```

The normal workspace test command runs this target as well:

```sh
cargo test --workspace
```
