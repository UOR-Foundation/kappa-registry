# kappa-registry

A content-addressed graph database over HTTP. Filesystem-backed, single-node,
serving as the protocol-agnostic substrate for Git, OCI, atproto, and
federation protocols.

Passes four independent test suites:

- 120 unit tests
- 84 integration tests
- 187 kappa-distribution conformance tests (5 levels)
- 848 OCI distribution-spec 1.1 conformance tests

## Quick start

```bash
# Build
cargo build --release

# Start the registry (ephemeral store, localhost:5000, rate limiting disabled)
./scripts/service.sh --start

# Push a container image
skopeo copy --dest-tls-verify=false \
  docker://docker.io/library/alpine:latest \
  docker://127.0.0.1:5000/test/alpine:latest

# Inspect it
skopeo inspect --tls-verify=false docker://127.0.0.1:5000/test/alpine:latest

# Pull it back out
skopeo copy --src-tls-verify=false \
  docker://127.0.0.1:5000/test/alpine:latest \
  oci:/tmp/pulled-image:latest

# Verify the pulled image
skopeo inspect oci:/tmp/pulled-image:latest

# Stop the registry
./scripts/service.sh --stop
```

## Service management

```bash
./scripts/service.sh --start              # start on localhost:5000
./scripts/service.sh --stop               # graceful shutdown
./scripts/service.sh --status             # show pid, store path, log path
./scripts/service.sh --logs               # print the log file
./scripts/service.sh --clean              # remove pid and log files
./scripts/service.sh --clean --force      # also remove the store directory
```

Override the listen address with `KAPPA_LISTEN_ADDR`:

```bash
KAPPA_LISTEN_ADDR=0.0.0.0:8080 ./scripts/service.sh --start
```

## Configuration

All configuration is via environment variables.

| Variable | Default | Description |
|---|---|---|
| `KAPPA_LISTEN_ADDR` | `127.0.0.1:8080` | Listen address |
| `KAPPA_STORE_ROOT` | `./data` | Filesystem store root |
| `KAPPA_MAX_BLOB_SIZE` | `67108864` | Maximum blob size (64 MiB) |
| `KAPPA_UPLOAD_TIMEOUT` | `3600` | Upload session timeout (seconds) |
| `KAPPA_MAX_TRANSACTIONS` | `64` | Maximum concurrent transactions |
| `KAPPA_MAX_STAGING_BYTES` | `268435456` | Global staging limit (256 MiB) |
| `KAPPA_SIGNING_ALGORITHM` | `ed25519` | Signing key algorithm |
| `KAPPA_RATELIMIT_READ_PERIOD_MS` | `0` | Read rate limit period (0 = disabled) |
| `KAPPA_RATELIMIT_READ_BURST` | `1000` | Read rate limit burst |
| `KAPPA_RATELIMIT_WRITE_PERIOD_MS` | `0` | Write rate limit period |
| `KAPPA_RATELIMIT_WRITE_BURST` | `200` | Write rate limit burst |
| `KAPPA_RATELIMIT_ADMIN_PERIOD_MS` | `0` | Admin rate limit period |
| `KAPPA_RATELIMIT_ADMIN_BURST` | `50` | Admin rate limit burst |

## Content addressing

Every object is identified by its kappa-label: `<algorithm>:<lowercase-hex-digest>`.

| Algorithm | Label length | Example |
|---|---|---|
| sha1 | 45 bytes | `sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` |
| sha256 | 71 bytes | `sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e...` |
| blake3 | 71 bytes | `blake3:af1349b9f5f9a1a6a0404dea36dcc949...` |
| sha512 | 135 bytes | `sha512:cf83e1357eefb8bdf1542850d66d8007...` |

SHA-1 labels use `sha1-checked` (the RustCrypto port of sha1dc) for collision
detection. `KappaLabel::sha1()` is the only fallible hash constructor, returning
`Err(CollisionDetected)` for collision-attacked content.

## API surface

### OCI distribution-spec 1.1

Standard OCI endpoints at `/v2/{namespace}/...`:

- `GET /v2/` -- version check
- Blob CRUD: GET, HEAD, PUT, DELETE, chunked upload
- Manifest CRUD: GET, HEAD, PUT, DELETE
- Tag list with pagination, ordering, time-range filtering
- Referrers API with artifactType filtering
- Single-POST monolithic blob push via `?digest=`

### kappa-distribution extensions

| Endpoint | Method | Description |
|---|---|---|
| `/v2/{ns}/tags/{name}` | PUT | Bind tag with CAS (`If-Match`, `If-None-Match`) |
| `/v2/{ns}/tags/{name}?symref={target}` | PUT | Create symbolic reference |
| `/v2/{ns}/tags/{name}?raw=true` | GET | Read raw tag value without resolution |
| `/v2/{ns}/tags/_batch` | POST | Atomic multi-tag CAS update |
| `/v2/{ns}/edges/` | PUT/GET/DELETE | Graph edge CRUD |
| `/v2/{ns}/edges/_diff` | POST | Graph set difference (have/want) |
| `/v2/{ns}/compose/` | POST | Algebraic composition (G2/F4/E6/E7/E8) |
| `/v2/{ns}/witnesses/{kappa}` | GET | Retrieve witness blob |
| `/v2/{ns}/schemas/{scope}` | PUT/GET | Schema registration and retrieval |
| `/v2/{ns}/schemas/` | GET | List schemas |
| `/v2/{ns}/filters/{scope}` | PUT/DELETE | Content filter management |
| `/v2/{ns}/filters/` | GET | List filters |
| `/v2/{ns}/blobs/_meta?key=...&value=...` | GET | Query blobs by metadata |
| `/v2/{ns}/_bundle/create` | POST | Create KBND bundle (with optional delta) |
| `/v2/{ns}/_bundle/ingest` | POST | Ingest KBND bundle |
| `/v2/{ns}/_transaction/begin` | POST | Begin multi-object transaction |
| `/v2/{ns}/_transaction/{id}/{kappa}` | PUT | Stage object in transaction |
| `/v2/{ns}/_transaction/{id}/commit` | POST | Atomic commit to main store |
| `/v2/{ns}/_transaction/{id}` | DELETE | Abort transaction |
| `/v2/{ns}/_reconcile` | POST | Range-based set reconciliation (RBSR) |
| `/v2/{ns}/_root` | GET | Namespace root hash |
| `/v2/{ns}/_root?signed=true` | GET | Signed namespace root |
| `/v2/{ns}/_root/proof/{name}` | GET | Inclusion proof for tag |
| `/v2/{ns}/gc/pin` | POST | Pin object as GC root |
| `/v2/{ns}/gc/unpin` | POST | Unpin (with finalizer support) |
| `/v2/{ns}/gc/sweep` | POST | Trigger GC sweep |
| `/v2/{ns}/gc/status` | GET | GC status |

## Primitives

Eleven protocol-agnostic primitives provide the complete substrate for
instantiating protocols without adding new registry capabilities.

**P1: SHA-1 axis with collision detection.** SHA-1 content addressing via
sha1-checked. Collision-attacked content is rejected per-axis. In a multi-label
push (sha256 + sha1), sha256 succeeds independently if sha1 collides.

**P2: Graph differencing and range-based set reconciliation.** `edge_diff`
computes reachable kappa-labels via BFS with common-ancestor early termination.
RBSR (Meyer 2023, arXiv:2212.13567) uses XOR-monoid fingerprints over ordered
ranges for O(difference) federation sync.

**P3: Multi-object transactions.** Defense-in-depth: max concurrent (64),
per-txn byte limit, global staging limit (256 MiB), TTL reap, startup orphan
cleanup. Objects staged in isolation, invisible until atomic commit.

**P4: Roaring bitmap GC acceleration.** GC sweep builds a roaring bitmap of
reachable blob positions for O(1) cache-friendly eviction checks.

**P5: Atomic multi-pointer CAS.** `tag_set_batch` applies multiple tag updates
atomically. Two-phase: validate all CAS expectations, then apply all writes.
Any failure rolls back all updates.

**P6: Symbolic pointers.** Tags store `ref:{target}` for pointer-to-pointer
resolution with loop detection (depth 10). Batch CAS operates on raw values.

**P7: Object type metadata.** Every handler stores `object-type` metadata.
`list_by_meta(key, value)` queries metadata across all blobs.

**P8: Delta-aware bulk transfer.** KBND bundle wire format with Git-compatible
binary delta encoding (COPY/INSERT instructions, FNV-1a block matching).
Topological ordering enables single-pass decode. 256 MiB decode budget. 13
typed error variants for machine-parseable error codes.

**P9: Edge store on redb.** Per-namespace redb databases with four tables
(forward, reverse, by-relation, by-kappa). Compound null-separated keys.
Atomic write transactions. Namespace isolation.

**P10: Authenticated namespace root.** SHA-256 root hash over sorted tag index
entries. Recomputed on every tag mutation. Inclusion proofs via full leaf list.
Signed roots with Ed25519/P-256/K-256.

**P11: Cryptographic signing and verification.** Trait-based signer/verifier
with Ed25519, P-256, K-256. Mandatory low-S normalization on ECDSA (atproto
compatibility). KeyStore with BLAKE3 integrity checking and tamper detection.

## Rate limiting

Tiered per-IP GCRA rate limiting with three operation classes:

- **Read**: GET/HEAD on blobs, manifests, tags, edges, referrers, schemas
- **Write**: PUT/POST/PATCH on blobs, manifests, tags, edges, uploads, compose
- **Admin**: DELETE, GC, transactions, reconcile

Health endpoints (`/v2/`, `/v2/_health/*`) are always exempt. Operation class
is determined at compile time via the `#[op_class(...)]` proc-macro annotation
on each endpoint variant.

## Store layout

```
{store_root}/
  blobs/{axis}/{shard}/{kappa-label}        # content-addressed objects
  blobs/{axis}/{shard}/{kappa-label}.meta   # JSON metadata sidecar
  tags/{escaped_ns}/index.json              # tag name -> kappa-label map
  tags/{escaped_ns}/root.json               # computed namespace root hash
  edges/{escaped_ns}.redb                   # per-namespace redb database
  index/fingerprints/{escaped_ns}.json      # RBSR fingerprint tree
  schemas/{escaped_ns}/{scope}.json         # schema registrations
  filters/{escaped_ns}/{scope}.json         # content filters
  gc/pins/{escaped_pin_kappa}.json          # GC pin records
  gc/status.json                            # last sweep status
  keys/default.{algorithm,pub,key,blake3}   # signing key material
  staging/{txn_id}/blobs/...                # transaction staging
```

## Building

Requires Rust 1.92+. The Nix flake provides a complete toolchain:

```bash
# Enter the dev shell
nix develop

# Build
cargo build --release

# Quality gates
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

Static musl binary for containers:

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

## Conformance testing

```bash
# kappa-distribution conformance (187 tests)
# Requires kappa-conformance binary in ../kappa-distribution/
./scripts/conformance.sh

# OCI distribution-spec 1.1 conformance (848 tests)
# Requires OCI conformance binary
./scripts/oci-conformance.sh
```

## Dependencies

All pure Rust. No C toolchain required.

| Crate | Version | Purpose |
|---|---|---|
| axum | 0.8 | HTTP framework |
| tokio | 1 | Async runtime |
| sha2 | 0.10 | SHA-256/SHA-512 |
| sha1-checked | 0.10 | SHA-1 with collision detection |
| blake3 | 1 | BLAKE3 hashing |
| redb | 4 | Embedded KV for edge store |
| roaring | 0.11 | Bitmap acceleration for GC |
| ed25519-dalek | 3 | Ed25519 signing |
| p256 | 0.14 | NIST P-256 ECDSA |
| k256 | 0.14 | secp256k1 ECDSA |
| governor | 0.10 | GCRA rate limiting |
| jsonschema | 0.46 | Schema validation |
| serde / serde_json | 1 | Serialization |

## Architecture

```
src/
  lib.rs              # Router, dispatch, AppState
  main.rs             # Binary entrypoint, signal handling
  config.rs           # Environment configuration
  kappa.rs            # KappaLabel type, hash computation, parse/verify
  delta.rs            # Git-compatible binary delta codec
  bundle.rs           # KBND bundle wire format with delta support
  transaction.rs      # TransactionManager with quarantine staging
  error.rs            # AppError -> HTTP error code mapping
  auth/               # Authorization stub (future hook point)
  crypto/             # Signing traits, Ed25519/ECDSA, KeyStore
  handlers/           # HTTP handlers (blob, tag, edge, compose, etc.)
  ratelimit/          # Tiered GCRA rate limiter with proc-macro classification
  routes/             # URL parser, Endpoint enum, segment constants
  store/              # KappaStore trait and filesystem implementation
    fs/               # blob, tag, edge (redb), filter, pin, schema, fingerprint
crates/
  kappa-macros/       # ClassifyEndpoint derive macro for op_class annotations
tests/
  integration/        # Black-box tests against live in-process server
scripts/
  service.sh          # Start/stop/status/logs/clean for local development
  conformance.sh      # Run kappa-distribution conformance suite
  oci-conformance.sh  # Run OCI distribution-spec conformance suite
```

## License

MIT OR Apache-2.0
