# kappa-registry

A content-addressed storage registry that serves six network protocols from one binary, one database, and one process. Docker, Git, S3, Nix, AT Protocol, and kappa-distribution clients connect to the same server. Each speaks its native protocol. Each stores to the same substrate. Each shares one identity system.

```
docker push registry.example.com/myorg/myimage:latest
git push http://registry.example.com/myorg/myrepo
aws s3 cp file.dat s3://mybucket --endpoint-url http://registry.example.com
nix copy --to http://registry.example.com /nix/store/...
```

55,000 lines of Rust. 16 crates. 700+ tests. 1032/1032 OCI distribution-spec conformance. 187/187 kappa-distribution conformance. Zero failures.

## Quick start

```bash
cargo build --release
./scripts/service.sh --start
```

The registry starts on `127.0.0.1:5000` with an ephemeral data directory. On first start it generates an Ed25519 signing key, derives a node anchor, writes capability edges, bootstraps system namespaces, and begins serving all protocols.

### OCI

```bash
skopeo copy --dest-tls-verify=false \
  docker://docker.io/library/alpine:latest \
  docker://127.0.0.1:5000/test/alpine:latest

skopeo inspect --tls-verify=false docker://127.0.0.1:5000/test/alpine:latest
```

### Git

```bash
git remote add kappa http://localhost:5000/myorg/myrepo
git push -u kappa main
git clone http://localhost:5000/myorg/myrepo /tmp/cloned
```

No `.git` suffix required. Nested namespaces at any depth: `myorg/team/sub/project`.

### S3

```bash
export AWS_ENDPOINT_URL=http://localhost:5000

aws s3 mb s3://mybucket
aws s3 cp file.txt s3://mybucket/dir/file.txt
aws s3 ls s3://mybucket/dir/
```

SigV4 authentication required on every request. Virtual-hosted-style routing available via `KAPPA_S3_BASE_DOMAIN`.

### Nix

```bash
nix copy --to 'http://localhost:5000/nix' $(nix build nixpkgs#hello --print-out-paths --no-link)
```

Configure as a substituter in `nix.conf`:

```
substituters = http://registry:5000/nix
```

### AT Protocol

```bash
# Create account
curl -X POST http://localhost:5000/xrpc/com.atproto.server.createAccount \
  -H 'Content-Type: application/json' \
  -d '{"handle": "alice.example.com", "password": "secret"}'

# Create session
curl -X POST http://localhost:5000/xrpc/com.atproto.server.createSession \
  -H 'Content-Type: application/json' \
  -d '{"identifier": "alice.example.com", "password": "secret"}'
```

22 XRPC routes. OAuth + DPoP session management (RFC 9449). WebSocket firehose at `/xrpc/com.atproto.sync.subscribeRepos`.

### Identity

```bash
curl -s http://localhost:5000/identity/whoami | jq .
```

Returns the node anchor, algorithm, trust position, and self-assertions.

## How it works

### Content addressing

Every object is stored at an address derived from its content. The address is a cryptographic hash of the bytes. Same bytes from any protocol share one stored copy.

Six hash axes: SHA-256, SHA-512, BLAKE3, SHA3-256, Keccak-256, SHA-1 (collision-detecting). No axis is privileged. Every ingest also computes SHA-256 as a mandatory secondary address, so content is always reachable by SHA-256 regardless of the caller's choice.

Content enters storage through `ingest_verified` (caller provides hash claim, substrate verifies) or `ingest_compute` (substrate computes hash). Both produce a `VerifiedContent` value, a sealed type with no public constructor. No code path stores unverified bytes. Enforced by compile-fail test.

Each protocol stores its own hash preimage. Git objects are stored with their envelope. OCI manifests are stored as raw JSON. Nix NARs are stored as compressed archives. `hash(stored_bytes) == protocol_address` always holds.

### Protocol detection

One TCP port. The server detects which protocol a client speaks from the request's own signals, checked in order of specificity:

| Priority | Signal                                                           | Protocol    |
| -------- | ---------------------------------------------------------------- | ----------- |
| 1        | `Content-Type: application/x-git-*`                              | Git         |
| 2        | `x-amz-content-sha256` header, `Authorization: AWS4-HMAC-SHA256` | S3          |
| 3        | `?service=git-upload-pack`, `?service=git-receive-pack`          | Git         |
| 4        | `/v2/` path prefix                                               | OCI         |
| 4        | `/xrpc/` path prefix                                             | AT Protocol |
| 5        | `/nix-cache-info`, `/nix/`, `*.narinfo`, `/nar/`                 | Nix         |
| 6        | `/info/refs`, `/git-upload-pack`, `/git-receive-pack`            | Git         |
| 7        | `/_status`, `/docs`, `/openapi.json`                             | System      |
| 8        | No match                                                         | 404         |

Headers are checked before paths because headers are definitive. S3 requires conformant SigV4 headers. No protocol is the default. An unrecognized request receives 404.

### The substrate

Five primitives. Everything is built from them.

**Blobs.** Immutable bytes at a hash address. Streaming reads via `blob_open` (zero-copy file handle for unencrypted, frame-decrypting reader for encrypted). Range reads. Compression-transparent storage and retrieval.

**Tags.** Namespace-scoped mutable bindings from a name to a hash. Version counter for optimistic concurrency. Batch compare-and-swap with all-or-nothing rollback. Symbolic refs with chain resolution.

**Edges.** Typed directed relationships. 17 relation types. Four indexes (forward, reverse, by-relation, by-asserter) plus a cross-namespace inbound index. Three-way upsert: skip exact duplicates, update metadata in place, insert new.

**Epochs.** Merkle tree snapshots of namespace state, hash-linked into a chain, Ed25519-signed. Tamper-evident audit trail and federation consistency verification.

**Sequences.** Monotonic per-namespace counters for subscription cursors.

### Namespaces

Every namespace is a UUID v7. Protocol-native names are aliases in a protocol-scoped alias table: `oci:library/nginx` and `s3:library/nginx` are separate entries pointing to separate UUIDs. Cross-protocol unification is explicit via `namespace_add_alias`.

A namespace has no type field. What it represents (a person, a team, a vehicle, a regulation, a genome) is determined by assertions and edges about it, not by a structural property. The substrate treats all namespaces identically.

Resolution happens once in a pathless interceptor layer. Every handler reads the resolved namespace from context. No handler calls a resolution function.

### Identity

**Anchor.** `sha256(dCBOR(algorithm || public_key_bytes))`. Deterministic, offline, no registry needed. Three newtypes: `AsserterAnchor` (closed constructor, compile-fail enforced), `SubjectAnchor`, `NodeAnchor`. Ed25519, P-256, K-256, FROST threshold for all three.

**Identity binding.** External identifier to anchor mapping. Nine verification methods (Plc, WebFinger, DnsTxt, WellKnown, CertificateChain, LocalConfig, RelMe, Gpg, SshKey). Five trust levels (Cryptographic, Certificate, Config, Web, ServerCustodial).

**Identity succession.** Key rotation with continuity. Old anchor to new anchor, authorized by a separate rotation key. Watermarks void old assertions: `KeyCompromise` voids everything, rotation voids before `effective_at`.

**Delegation.** Scoped (namespace UUIDs x operations), time-bounded, depth-limited, cascade-revocable. Optional WASM point-of-use filter. Narrowing invariant: can only narrow scope, shorten TTL, decrement depth on redelegate. Enforced at creation and evaluation.

**Resolution.** `resolve_at` walks succession chains, queries the cross-namespace inbound index, filters by timestamp, watermark, revocation, and viewer trust policy. Returns unmerged results. Two conflicting assertions are both returned. The substrate does not score, merge, or pick winners.

**Resolver registry.** Async `ExternalIdentifierResolver` trait with `accepts()` dispatch. NixKeyResolver (local config), PlcResolver (did:plc via PLC directory), WebFingerResolver (handle to DID via WebFinger + DNS TXT), FulcioResolver (OIDC via Sigstore Rekor + x509).

**Handle registry.** Human-readable names with bidirectional verification. Background task re-verifies via DNS TXT (hickory-resolver), WebFinger, or HTTP well-known.

### Trust

The substrate computes deterministic structural facts (signatures, edge counts, epochs, probes, absence proofs). It does not compute trust scores. Trust policy is a viewer-side trait with no default implementation.

Trust position: `Unprobed`, `Standalone`, `Federated { verified_peers }`, `Degraded { reason }`. One fault degrades. No averaging. No quorum.

The append-only key directory (AKD) provides non-membership proofs: mathematical artifacts proving an assertion was never made. Transferable, offline-verifiable, no trust in the registry operator required.

### Authorization

Seven-step authorization against a `ResolvedNamespace` from context:

1. `_root` capability check (does not touch target namespace)
2. Owner check
3. Unclaimed non-reserved namespace + write operation = `AllowCreateNew`
4. Direct capability edge on target
5. Namespace hierarchy walk
6. Two-hop role check
7. Delegation chain walk (up to 5 hops, scope-constrained)

Auth returns `Ok(Response)` for 403 and 404. Only store failures return `Err`. All downstream layers see all responses.

### Encryption

AES-256-GCM framed AEAD. 64KB frames, per-blob random nonce. `FrameDecryptingReader` caches one frame (~128KB resident regardless of blob size). Range reads decrypt only overlapping frames.

Encrypt-then-hash: `κ = hash(ciphertext)`, `σ = hash(plaintext)`. Binding records bridge them. `hash(bytes_on_disk) == κ` is verifiable without the decryption key.

### Federation

Background probe task polls configured peers at configurable interval. `GET /v2/_root?signed=true` returns epoch root with Ed25519 signature. Signature verification, equivocation detection (same epoch number, different root hash), trust position update.

Set reconciliation via RBSR with XOR-monoid fingerprint tree. Namespace-scoped.

### Server infrastructure

topcoat 0.5.0 HTTP framework (fork: trailing slash tolerance, HttpErrorResponse trait, OutboundClient). 15 middleware layers. Signal-based protocol detection in the namespace interceptor.

TCP and Unix domain socket listeners serve simultaneously. TCP for protocol clients, Unix socket for local daemon IPC. TLS with optional mTLS via rustls.

OutboundClient provides shared connection pool with request ID propagation from inbound context to outbound headers and per-host health tracking.

Six background tasks: upload eviction (60s), transaction eviction (60s), S3 lifecycle (24h), disk pressure monitor, federation probe, handle verification.

## Protocol reference

### OCI (1032/1032 conformance)

Standard OCI distribution-spec 1.1 endpoints at `/v2/{namespace}/...`. Blob CRUD with streaming download. Manifest CRUD with tag binding. Tag list with pagination. Chunked upload with digest verification. Referrers API. Content filters and schema validation evaluated before storage.

### kappa-distribution (187/187 conformance)

Extension protocol: edges CRUD with delegation depth enforcement, algebraic composition (g2/f4/e6/e7/e8), witnesses, schemas, filters, bundles with delta compression, multi-object transactions, cascading delete, set reconciliation, namespace root with inclusion proofs, monotonic sequences, SSE event streaming, WebSocket CRDT rooms.

### Git

Smart HTTP v1 and v2. Ref advertisement, pack negotiation, delta compression (OFS_DELTA, sliding window), streaming pack ingest with delta resolution. SHA-1 and SHA-256 object formats. Git LFS batch API. Pre-receive and post-receive hooks. Signal-based detection (no `.git` URL requirement). GitLab-style nested namespaces at any depth.

### S3

Object CRUD, bucket operations, ListObjectsV2 with delimiter rollup and continuation tokens, multipart upload with per-part ETag validation, batch delete, object tagging, bucket versioning, lifecycle configuration, CORS, bucket policy with statement evaluation. SigV4 authentication: header auth, presigned URLs, chunk signature chaining, trailer signatures. Virtual-hosted-style routing. Credential store with rotation grace period.

### Nix

Binary cache protocol. narinfo text codec. NAR verification after decompression (zstd, xz, bzip2). Reference scanning for closure computation via edge traversal. Compression-transparent serving. Assertion edges from signing key anchor to narinfo blob for provenance chain.

### AT Protocol

Merkle Search Tree with leading-zeros layer assignment (~4 fanout). CAR v1 encode/decode. TID generation with collision-safe anchor-derived clock ID. CIDv1 dag-cbor+sha256.

OAuth + DPoP session management with 7-step proof verification (ES256 JWT signature, JTI replay, method binding, URI binding, token hash, key binding, freshness).

22 XRPC routes: account management (createAccount, createSession, refreshSession, deleteSession, getSession), repository CRUD (createRecord, putRecord, deleteRecord, getRecord, listRecords, uploadBlob, applyWrites, describeRepo), sync (getRepo as CAR export, getBlob, getLatestCommit, listRepos, subscribeRepos firehose, requestCrawl), identity (resolveHandle, updateHandle), server (describeServer).

subscribeRepos WebSocket firehose with DAG-CBOR binary frames, four event types (#commit, #handle, #identity, #tombstone), cursor-based resume, OutdatedCursor backpressure.

Every record mutation rebuilds the MST and creates a new signed commit, maintaining a valid commit chain.

## Configuration

All configuration is via environment variables.

| Variable                            | Default                 | Description                                 |
| ----------------------------------- | ----------------------- | ------------------------------------------- |
| `KAPPA_LISTEN_ADDR`                 | `127.0.0.1:5000`        | TCP listen address                          |
| `KAPPA_STORE_ROOT`                  | `./data`                | Filesystem store root                       |
| `KAPPA_MAX_BLOB_SIZE`               | `67108864`              | Maximum blob size (64 MiB)                  |
| `KAPPA_UPLOAD_TIMEOUT`              | `3600`                  | Upload session timeout (seconds)            |
| `KAPPA_MAX_TRANSACTIONS`            | `64`                    | Maximum concurrent transactions             |
| `KAPPA_MAX_STAGING_BYTES`           | `268435456`             | Global staging byte limit (256 MiB)         |
| `KAPPA_SIGNING_ALGORITHM`           | `ed25519`               | Node signing key algorithm                  |
| `KAPPA_S3_BASE_DOMAIN`              | (unset)                 | S3 virtual-hosted-style domain              |
| `KAPPA_S3_REGION`                   | `us-east-1`             | S3 region for SigV4                         |
| `KAPPA_LIFECYCLE_INTERVAL_SECS`     | `86400`                 | S3 lifecycle evaluation interval            |
| `KAPPA_NIX_TRUSTED_KEYS`            | (unset)                 | Nix trusted keys (name:base64pubkey,...)    |
| `KAPPA_PLC_DIRECTORY_URL`           | `https://plc.directory` | PLC directory for DID resolution            |
| `KAPPA_FEDERATION_PEERS`            | (unset)                 | Federation peer URLs (comma-separated)      |
| `KAPPA_PROBE_INTERVAL_SECS`         | `60`                    | Federation probe interval                   |
| `KAPPA_HANDLE_VERIFY_INTERVAL_SECS` | `3600`                  | Handle re-verification interval             |
| `KAPPA_HANDLE_TTL_MS`               | `86400000`              | Handle verification TTL (24h)               |
| `KAPPA_PDS_HOSTNAME`                | (unset)                 | AT Protocol PDS hostname for requestCrawl   |
| `KAPPA_DISK_PRESSURE_THRESHOLD`     | (unset)                 | Reject writes below this free space (bytes) |
| `KAPPA_RATELIMIT_READ_PERIOD_MS`    | `0`                     | Read rate limit period (0 = disabled)       |
| `KAPPA_RATELIMIT_READ_BURST`        | `1000`                  | Read rate limit burst                       |
| `KAPPA_RATELIMIT_WRITE_PERIOD_MS`   | `0`                     | Write rate limit period                     |
| `KAPPA_RATELIMIT_WRITE_BURST`       | `200`                   | Write rate limit burst                      |
| `KAPPA_RATELIMIT_ADMIN_PERIOD_MS`   | `0`                     | Admin rate limit period                     |
| `KAPPA_RATELIMIT_ADMIN_BURST`       | `50`                    | Admin rate limit burst                      |
| `KAPPA_TLS_CERT`                    | (unset)                 | TLS certificate path                        |
| `KAPPA_TLS_KEY`                     | (unset)                 | TLS private key path                        |
| `KAPPA_TLS_CLIENT_CA`               | (unset)                 | mTLS client CA path                         |

## Namespace management

Seven HTTP endpoints for namespace lifecycle:

```bash
# Create
curl -X POST http://localhost:5000/v2/myorg/myrepo/_namespace/create

# Info
curl http://localhost:5000/v2/myorg/myrepo/_namespace/info

# Rename
curl -X POST http://localhost:5000/v2/myorg/myrepo/_namespace/rename \
  -d '{"new_name": "myorg/renamed"}'

# Transfer
curl -X POST http://localhost:5000/v2/myorg/myrepo/_namespace/transfer \
  -d '{"new_owner": "sha256:abc123..."}'

# Add alias
curl -X POST http://localhost:5000/v2/myorg/myrepo/_namespace/alias \
  -d '{"alias": "myorg/myrepo", "protocol": "git"}'

# Delete
curl -X DELETE http://localhost:5000/v2/myorg/myrepo/_namespace

# List all
curl http://localhost:5000/v2/_namespaces
```

## Identity endpoints

```bash
# Node identity
curl http://localhost:5000/identity/whoami

# Register anchor
curl -X POST http://localhost:5000/identity/register -d '{"anchor": "..."}'

# Assert
curl -X POST http://localhost:5000/v2/{ns}/_identity/assert \
  -d '{"subject": "...", "facet": "...", "value": "..."}'

# Resolve
curl http://localhost:5000/v2/{ns}/_identity/resolve?subject=...&facet=...

# Handle claim
curl -X POST http://localhost:5000/identity/handle/claim \
  -d '{"handle": "alice.example.com", "protocol": "atproto"}'

# Handle lookup
curl http://localhost:5000/identity/handle/atproto/alice.example.com

# Reverse lookup (all handles for an anchor)
curl http://localhost:5000/identity/anchor/sha256:abc.../handles
```

## Building

Requires Rust 1.95+. The Nix flake provides a hermetic toolchain.

```bash
nix develop
cargo build --release

# Quality gates
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

AT Protocol module is behind a feature flag:

```bash
cargo build --release --features atproto
```

## Testing

```bash
# Unit and integration tests
cargo test --workspace

# With AT Protocol
cargo test --workspace --features atproto

# kappa-distribution conformance (187 tests)
./scripts/conformance.sh

# OCI distribution-spec conformance (1032 tests)
./scripts/oci-conformance.sh

# Protocol E2E
./scripts/git-e2e.sh
./scripts/s3-e2e.sh
./scripts/nix-e2e.sh
```

## Service management

```bash
./scripts/service.sh --start    # start on localhost:5000
./scripts/service.sh --stop     # graceful shutdown
./scripts/service.sh --status   # show pid, store path, log path
./scripts/service.sh --logs     # print log file
./scripts/service.sh --clean    # remove pid and log files
```

Override the listen address:

```bash
KAPPA_LISTEN_ADDR=0.0.0.0:5000 ./scripts/service.sh --start
```

## Crate structure

```
kappa-core            substrate types, store trait, crypto, identity primitives
kappa-store-redb      production store: redb tables, filesystem blobs, encryption
kappa-akd             append-only key directory for absence proofs
kappa-conformance     conformance tests, compile-fail tests
kappa-reconcile       RBSR set reconciliation
kappa-types           shared type definitions
kappa-transport-veilid  Veilid transport for federation
kappa-server          HTTP server, middleware, handlers, resolvers
kappa-module-oci      OCI distribution-spec handlers
kappa-module-distribution  kappa-distribution extension handlers
kappa-module-git      Git smart HTTP: pack ingest/gen, refs, hooks, LFS
kappa-module-s3       S3 ListObjectsV2, XML encoding
kappa-module-nix      Nix narinfo codec, NAR verification, key format
kappa-module-identity identity HTTP endpoints, handle registry
kappa-module-atproto  MST, CAR, TID, CID, commits, XRPC, session, firehose
```

Protocol modules have no kappa-core dependency (except kappa-module-identity and kappa-module-distribution which use store types). They are pure format codecs. The server bridges codecs to the substrate.

## Dependencies

All pure Rust. No C toolchain required.

| Crate                                                    | Purpose                                                      |
| -------------------------------------------------------- | ------------------------------------------------------------ |
| topcoat 0.5.0 (fork)                                     | HTTP framework, SSE, WebSocket, Unix sockets, OutboundClient |
| redb 4                                                   | Embedded B-tree database                                     |
| tokio 1                                                  | Async runtime                                                |
| ed25519-dalek 3                                          | Ed25519 signing                                              |
| p256, k256 0.14                                          | ECDSA (P-256, secp256k1)                                     |
| frost-core, frost-ed25519, frost-p256, frost-secp256k1 3 | FROST threshold signatures                                   |
| sha2 0.11                                                | SHA-256, SHA-512                                             |
| sha1-checked 0.10                                        | SHA-1 with collision detection                               |
| blake3 1                                                 | BLAKE3                                                       |
| reqwest (via topcoat)                                    | Outbound HTTP                                                |
| hickory-resolver 0.25                                    | Async DNS TXT lookups                                        |
| x509-parser 0.18                                         | Fulcio certificate validation                                |
| gix-object, gix-pack, gix-hash, gix-packetline           | Git object/pack handling                                     |
| quick-xml 0.37                                           | S3 XML encoding                                              |
| nix-derivation                                           | Nix base32, StorePath                                        |
| dashmap 6                                                | Concurrent hash maps                                         |
| governor 0.10                                            | GCRA rate limiting                                           |
| roaring 0.11                                             | Bitmap GC acceleration                                       |
| dcbor 0.25 (fork)                                        | Deterministic CBOR                                           |
| async-trait                                              | Async trait methods                                          |

## Documentation

`docs/kappa-registry.md` is the canonical reference. It covers content addressing, protocol detection, the substrate primitives, namespaces, the full identity model, trust, authorization, federation, all six protocols, architecture, prior art, and conformance.

OpenAPI 3.1 spec with interactive documentation at `/docs` and `/openapi.json`.

## License

MIT OR Apache-2.0
