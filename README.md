# kappa-registry

`kappa-registry` is a filesystem-backed, single-node implementation of the
Kappa Distribution `/v2/` registry protocol. It stores content by verified
Kappa labels, keeps namespace metadata separate from global blob content, and
supports OCI registry interoperability plus Kappa composition and replication
workflows.

The service is written in Rust with Axum and Tokio. It provides durable
filesystem storage, bounded uploads, tiered rate limiting, signed namespace
roots, validation gates, and atomic multi-object operations.

## Implemented features

- Content-addressed blobs using `sha1`, `sha256`, `blake3`, and `sha512` labels,
  with SHA-1 collision detection.
- OCI manifests, tags, symbolic references, conditional tag updates,
  referrers, metadata queries, and tag pagination.
- Resumable uploads with recovery, ordered chunks, mount support, and body
  limits.
- Namespace-scoped edges, graph queries, graph diffs, range-based set
  reconciliation, and deterministic namespace roots with optional signatures.
- Kappa composition operations (`g2`, `f4`, `e6`, `e7`, and `e8`) and witness
  blobs.
- Validation schemas and admission filters.
- Multi-object transactions with staging limits, TTL cleanup, and atomic
  promotion into the filesystem store.
- Binary Kappa bundle creation and ingestion, including delta bundles.
- Pin, unpin, sweep, and status operations for reachability-based garbage
  collection.
- Tiered per-client-IP rate limiting for read, write, and administrative
  operations.

The black-box integration suite is organized as levels 1 through 7. The
scripts in `scripts/` run the external Kappa and OCI conformance suites when
their companion tools are available.

## API documentation

When the server is running:

- Scalar API reference: <http://127.0.0.1:8080/docs>
- OpenAPI JSON: <http://127.0.0.1:8080/openapi.json>

The OpenAPI document is generated in-process with `utoipa`, rendered by the
`scalar_api_reference` Axum integration, and served with embedded Scalar
assets. The registry protocol remains under `/v2/`; documentation routes are
outside the protocol dispatcher.

The public route groups are:

| Group | Routes |
| --- | --- |
| System | `GET /v2/`, `GET /v2`, `GET /v2/_health/{probe}` |
| Blobs | `GET`, `HEAD`, `PUT`, `DELETE /v2/{namespace}/blobs/{kappa}`; `GET /v2/{namespace}/blobs/`; `GET /v2/{namespace}/blobs/_meta` |
| Uploads | `POST /v2/{namespace}/blobs/uploads/` or `/blobs/uploads`, then `PATCH`, `GET`, `PUT`, or `DELETE /v2/_uploads/{id}` |
| Manifests and tags | `/manifests/`, `/tags/`, and `/referrers/` |
| Graph and replication | `/edges/` and `/_reconcile` |
| Transactions and bundles | `/_transaction/` and `/_bundle/` |
| Composition | `/compose/` and `/witnesses/` |
| Policies | `/schemas/` and `/filters/` |
| Lifecycle | `/gc/` and `/_root/` |

`namespace` is a logical namespace prefix. Namespaces may contain `/`, so use
the route templates in the OpenAPI document rather than treating the
namespace as a single URL segment.

## Quick start

The repository provides a Nix development shell with the Rust toolchain used
by the project:

```sh
nix develop
cargo run
```

By default the service listens on `127.0.0.1:8080` and stores data under
`./data`.

```sh
curl -i http://127.0.0.1:8080/v2/
curl -i http://127.0.0.1:8080/v2/_health/ready
```

## Basic blob workflow

Blobs are verified on write. The label in the URL must match the content under
the label's hash axis.

```sh
content='hello from kappa'
kappa="sha256:$(printf '%s' "$content" | sha256sum | cut -d ' ' -f 1)"

curl -i -X PUT \
  -H 'Content-Type: text/plain' \
  --data-binary "$content" \
  "http://127.0.0.1:8080/v2/example/blobs/$kappa"

curl -i "http://127.0.0.1:8080/v2/example/blobs/$kappa"
```

Manifests are stored as blobs and can be addressed by a tag or by their
computed digest:

```sh
curl -i -X PUT \
  -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
  --data-binary @manifest.json \
  http://127.0.0.1:8080/v2/example/manifests/latest
```

## Configuration

Configuration is read from environment variables.

| Variable | Default | Purpose |
| --- | --- | --- |
| `KAPPA_LISTEN_ADDR` | `127.0.0.1:8080` | Listen address |
| `KAPPA_STORE_ROOT` | `./data` | Filesystem store root |
| `KAPPA_MAX_BLOB_SIZE` | `67108864` | Maximum request body in bytes |
| `KAPPA_UPLOAD_TIMEOUT` | `3600` | Upload and transaction timeout in seconds |
| `KAPPA_MAX_TRANSACTIONS` | `64` | Maximum concurrent transactions |
| `KAPPA_MAX_STAGING_BYTES` | `268435456` | Global transaction staging limit |
| `KAPPA_SIGNING_ALGORITHM` | `ed25519` | Algorithm for signed namespace roots |
| `KAPPA_RATELIMIT_*` | disabled | Read, write, and admin periods and bursts |
| `RUST_LOG` | `kappa_registry=info,tower_http=debug` | Tracing filter |

On startup the service creates or loads its signing key under the store root.
Use a dedicated persistent store directory in deployments and protect the key
files and existing store data appropriately.

## Storage

The filesystem store is content addressed and shards blob files by hash axis
and digest prefix. Namespace data includes tags, edges, schemas, filters,
fingerprint indexes, and garbage-collection state. Redb is used for the edge
index. Upload sessions and rate limiter state are process-local; completed
content is durable in the filesystem store.

## Development

Run the project quality gates before submitting changes:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

The integration tests start the application in-process with a temporary
filesystem store. To run the external suites, build their companion tools and
run:

```sh
./scripts/conformance.sh
./scripts/oci-conformance.sh
```

## Repository map

| Path | Responsibility |
| --- | --- |
| `src/lib.rs` | Application state, documentation routes, and protocol dispatch |
| `src/main.rs` | Configuration, store initialization, cleanup, and server startup |
| `src/routes/` | URL parsing and endpoint classification |
| `src/handlers/` | Feature-specific protocol handlers |
| `src/store/fs/` | Filesystem persistence and indexes |
| `src/openapi.rs` | OpenAPI document and Scalar documentation routes |
| `src/kappa.rs` | Kappa label parsing, hashing, and verification |
| `tests/integration/` | Live black-box behavior tests |
| `scripts/` | External conformance runners |

## Current scope

This is a single-node registry. The authorization hook is present in the
handler pipeline but currently permits all requests. Upload sessions and rate
limiter state are process-local. Horizontal deployment, external identity
integration, and a distributed storage backend are outside the current scope.

## License

MIT OR Apache-2.0
