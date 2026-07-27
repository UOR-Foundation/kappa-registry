# kappa-registry

A content-addressed graph database served over HTTP with built-in node
identity, asserter-based authorization, and OCI distribution-spec 1.1
conformance. Filesystem-backed. Single-node. Federatable. Every mutation
carries an asserter anchor derived from the signing key that authorized it.

The registry serves as the protocol-agnostic substrate for Git, OCI,
atproto, SCITT, and federation protocols. Protocol-specific behavior is
delivered by modules that compose existing primitives; the registry itself
never gains protocol-specific code.

200 unit tests. 118 integration tests. 187 kappa-distribution conformance
tests across 5 levels. 848 OCI distribution-spec 1.1 conformance tests.
All passing. Zero warnings.

## Quick start

```bash
cargo build --release
./scripts/service.sh --start
```

The registry starts on `127.0.0.1:5000` with an ephemeral store directory.
On first start it generates an Ed25519 signing key, derives a node anchor
from it, writes self-assertions and capability edges, and begins serving.

```bash
# Push a container image
skopeo copy --dest-tls-verify=false \
  docker://docker.io/library/alpine:latest \
  docker://127.0.0.1:5000/test/alpine:latest

# Inspect it
skopeo inspect --tls-verify=false docker://127.0.0.1:5000/test/alpine:latest

# Pull it back
skopeo copy --src-tls-verify=false \
  docker://127.0.0.1:5000/test/alpine:latest \
  oci:/tmp/pulled-image:latest

# Ask the registry who it is
curl -s http://127.0.0.1:5000/v2/any-namespace/_identity/whoami | jq .

# Stop the registry
./scripts/service.sh --stop
```

The `whoami` response returns the node's anchor, algorithm, trust position,
epoch, and self-assertions as plain JSON. No client library required.

```json
{
  "anchor": "sha256:9f2c...",
  "algorithm": "ed25519",
  "trust_position": "unprobed",
  "epoch": 0,
  "self_assertions": {
    "node/anchor": "sha256:9f2c...",
    "node/algorithm": "ed25519",
    "node/version": "0.1.0",
    "trust/position": "unprobed"
  }
}
```

## Node identity

Every registry node has a cryptographic identity established at first boot.
The identity requires no enrollment server, no bootstrap token, and no
network connectivity. It is a pure function of the signing key.

**Bootstrap sequence** (runs once, before serving, with no network calls):

1. **Signing key**: `KeyStore::load_or_generate("default")` creates an
   Ed25519 keypair on first run. Subsequent starts load the existing key.
   BLAKE3 integrity checking detects tampering; a corrupted keystore fails
   hard and is never silently regenerated.

2. **VRF key**: `VrfKeyMaterial::load_or_generate` creates an Ed25519 key
   used for AKD label derivation. This key never rotates. Rotating it
   invalidates every derived label in every namespace.

3. **Node anchor**: `anchor_from_key(algorithm, public_key)` computes
   `sha256(u16_be(algorithm.len) + algorithm + u16_be(key.len) + key)`.
   The anchor IS the identity. Same key always produces the same anchor.

4. **Self-assertions**: The node writes four tags in its own namespace:
   `node/anchor`, `node/algorithm`, `node/version`, `trust/position`.
   These are self-asserted claims -- weakly trusted by construction,
   which is honest.

5. **Capability floor**: The node writes capability edges granting itself
   read/write/admin on all reserved namespaces. These edges are real,
   inspectable, and revocable -- not a hardcoded bypass.

**Trust position** describes what the node found when it probed for peers:

| Position | Meaning |
|----------|---------|
| `unprobed` | Bootstrap complete, probe not yet run |
| `standalone` | Probed; no peers reachable. Fully functional. Normal. |
| `federated` | Probed; at least one peer's epoch root signature verified |
| `degraded` | Probed; peers reachable but verification FAILED. This is a fault. |

`Standalone` and `Degraded` are distinct states. A node with no peers
configured is working as intended. A node whose peer is serving invalid
signatures is under attack or misconfigured. An operator must be able to
tell these apart from a dashboard.

## Typed anchor newtypes

Three anchor types enforce role separation at compile time:

```rust
NodeAnchor      // This process's identity. From anchor_from_key.
AsserterAnchor  // Verified signer. ONLY from asserter_from_signature.
SubjectAnchor   // What an assertion is about. Freely constructible.
```

`AsserterAnchor` has no public constructor. The only path to one is
successful signature verification via `crypto::anchor::asserter_from_signature`.
Forgetting to verify is a compile error, not a code review finding.

## Authorization

Every handler calls `authorize(store, ns, op, asserter)` inside
`spawn_blocking` before any store operation. Authorization is a
capability-edge lookup in the namespace being accessed.

**Open namespaces** (anything not matching a reserved prefix) pass
unconditionally. The registry is permissionless for user namespaces.

**Reserved namespaces** require a capability edge from the namespace
authority granting the asserter the requested operation class. All
operations require edges, including reads. Reserved content is not public
by default.

| Reserved prefix | Purpose |
|-----------------|---------|
| `kappa/protocols` | Protocol module WASM bytecode |
| `kappa/runtimes` | Execution runtimes and compiled cache |
| `kappa/os` | Operating system components |
| `kappa/identity` | Identity anchors and assertions |
| `nix` | Nix store mirror |
| `sesame` | Distribution profiles |

For unsigned OCI traffic (skopeo, crane, docker), the asserter is the
registry's own anchor derived from its signing key via `registry_anchor(cx)`.
The capability edges written at bootstrap grant this anchor full access
to all reserved namespaces.

**Operation classes**:

| Class | HTTP methods | Examples |
|-------|-------------|----------|
| `Exempt` | any | `/v2/`, `/v2/_health/*` |
| `Read` | GET, HEAD | blob get, tag list, edge query, whoami |
| `Write` | PUT, POST, PATCH | blob put, tag set, edge put, compose |
| `Admin` | DELETE, GC, cascade | blob delete, sweep, transaction begin/commit |

## Content addressing

Every object is identified by its kappa-label: `<algorithm>:<lowercase-hex-digest>`.

| Algorithm | Label length | Digest bits | Example |
|-----------|-------------|-------------|---------|
| sha1 | 45 bytes | 160 | `sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` |
| sha256 | 71 bytes | 256 | `sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c...` |
| blake3 | 71 bytes | 256 | `blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9...` |
| sha512 | 135 bytes | 512 | `sha512:cf83e1357eefb8bdf1542850d66d8007d620e405...` |

SHA-1 labels use `sha1-checked` for collision detection.
`KappaLabel::sha1()` returns `Err(CollisionDetected)` for crafted
collision content. All other hash constructors are infallible.

Multi-label push (`PUT /v2/{ns}/blobs/{sha256}?also={blake3}`) stores the
blob under both labels. If sha1 collides in a multi-label push, sha256
succeeds independently.

## Identity model

The identity subsystem provides cryptographic attribution for every
mutation in the registry. It is built entirely from existing primitives
(blobs, tags, edges, sequences) plus two new subsystems: an append-only
auditable key directory (AKD) for absence proofs, and a VRF for label
privacy.

### Anchors

An anchor is the minimal, immutable origin record for an identity. It
has no attributes. What kind of entity the anchor represents is a query
result over the assertion graph, not a stored field.

`AnchorSpec` contains CSPRNG entropy (32 bytes) and an optional key
commitment (SHA-256 of the initial rotation key set). The anchor kappa
is `sha256(canonical_bytes(spec))`, deterministic and reproducible.

### Assertions

An assertion is a signed claim by an asserter about a subject on a facet.
Assertions are stored in the asserter's namespace, never the subject's.

```
asserter: sha256:alice     (who says this)
subject:  sha256:bob       (about whom)
facet:    key/signing       (what aspect)
value:    <public key bytes> (the claim)
valid_from: 42              (asserter's epoch)
valid_to:   None            (unbounded)
basis:      None            (no prior assertion)
audience:   None            (public)
signature:  <64 bytes>      (over canonical form)
```

Multiple assertions about the same (subject, facet) from different
asserters are NOT conflicts. They are distinguishable facts. `resolve_at`
returns `Vec`, not `Option`. No merge operation exists.

Canonical bytes use binary length-prefixed encoding (not JSON). The kappa
includes the signature for content addressing -- identical assertions from
the same asserter deduplicate.

### Revocations

A revocation is a signed negative assertion. It is append-only, stored
alongside the original assertion, and never deleted. A revocation issued
in error is answered with a fresh assertion carrying a new nonce, not
retraction.

Reason codes partition who may author a revocation:

| Reason | Who may revoke |
|--------|---------------|
| `Superseded` | Original asserter only |
| `KeyCompromise` | Asserter or subject |
| `PrivilegeWithdrawn` | Upstream delegator only |
| `Erroneous` | Original asserter only |

### Resolution

`resolve_at(store, asserter_ns, subject, facet, valid, observed, audience)`
returns all matching assertions from a single asserter where epochs are
comparable. `valid` asks "what was true at this epoch?" and `observed` asks
"what did we know at this epoch?" Both are in the asserter's epoch space.

`resolve_all(store, asserter_namespaces, subject, facet, audience)` queries
multiple asserters and groups results by asserter. Cross-asserter epoch
comparison is not offered because it is not sound under per-asserter
Lamport counters.

`ResolutionResult.unrevoked()` filters out assertions whose kappa appears
in the revocation set.

### Trust policy

Trust is evaluated at read time by local policy. The store holds evidence
only. No computed trust value is ever persisted.

`TrustPolicy` trait with `believes(asserter, facet)` and `fuse(grouped)`.
`fuse` returns grouped-and-unmerged results -- the return type
`Vec<(String, Vec<IdentityAssertion>)>` is the type-level expression of
non-coalescence. There is no signature by which two asserters' claims can
collapse into one value.

`AllowList` is the initial implementation. Empty set trusts all asserters
(permissive default for bootstrapping). Non-empty set trusts only listed
anchors.

### Epoch chain

Each asserter's namespace has an epoch chain. Each `EpochRoot` commits to
the previous root, the current state root, the AKD tree root, and the
epoch number. Epoch advance is atomic with assertion/tag storage.

`is_equivocation(other)` detects two epoch roots at the same epoch with
different state roots -- the CT-equivalent of a log presenting inconsistent
Signed Tree Heads.

### Watermark

O(1) bulk invalidation. One monotonic integer per anchor: everything
asserted before watermark N is void. The Kerberos `not-before` pattern
applied to identity assertions. Useful for key compromise response --
invalidate all assertions from the compromised key without enumerating them.

### Absence proofs

`AbsenceProof` is the wire type for AKD `NonMembershipProof`. It proves
that a specific asserter has NOT made an assertion about a subject on a
facet at a specific epoch. Absence is always asserter-scoped -- the system
can prove "this asserter has not asserted X" but never "nobody has asserted
X."

This is a capability deployed Certificate Transparency does not have.
CT can prove inclusion but not exclusion.

### Audience derivation

`derive_audience_label(seed, subject, audience)` uses `blake3::derive_key`
with a fixed context string to produce a 32-byte pseudonym that is
deterministic, unlinkable across audiences, and non-reversible without the
seed. Length-prefixed inputs prevent injection (`("ab","c")` and `("a","bc")`
produce different labels).

Audience-scoped assertions occupy different AKD tree positions from public
assertions on the same (subject, facet).

## Cryptography

### Signing and verification

Trait-based `RegistrySigner` and `RegistryVerifier` with three algorithms:

| Algorithm | Key size | Signature size | Use case |
|-----------|----------|---------------|----------|
| Ed25519 | 32 bytes | 64 bytes | Default registry signing key |
| P-256 (secp256r1) | 32 bytes | 64 bytes (DER variable) | TLS, WebAuthn |
| secp256k1 (K-256) | 32 bytes | 64 bytes (DER variable) | Bitcoin, atproto DID:plc |

ECDSA signatures use mandatory low-S normalization for atproto compatibility.

`generate_raw_keypair(algorithm)` returns `(Zeroizing<Vec<u8>>, Vec<u8>)`.
Private key bytes are wrapped in `zeroize::Zeroizing` for automatic memory
clearing on drop.

### KeyStore

Persistent key storage with BLAKE3 integrity protection:

```
keys/
  default.algorithm    # "ed25519" | "p256" | "k256"
  default.pub          # raw public key bytes (0o644)
  default.key          # raw private key bytes (0o600)
  default.blake3       # BLAKE3(pub || key) integrity checksum (0o600)
```

`load_or_generate(algorithm)` generates on first call, loads and verifies
on subsequent calls. `load(name)` verifies the BLAKE3 checksum and fails
hard on mismatch -- a tampered keystore is never silently regenerated.

### FROST threshold signing

Three-algorithm threshold signing via frost-core:

- `generate_shares(algorithm, min_signers, max_signers)` -- trusted dealer
  key generation returning share bundles and group public key
- `split_for_recovery(algorithm, private_key, min, max)` -- split an
  existing key into guardian shares for social recovery
- `reconstruct(algorithm, shares)` -- reconstruct the signing key from
  threshold shares

All three algorithms (Ed25519, P-256, secp256k1) are implemented via
generic `generate_typed<C: Ciphersuite>`. did:plc constrains rotation keys
to secp256k1 and P-256; omitting either would make threshold rotation for
did:plc-compatible identities structurally impossible.

No HTTP endpoints. Private keys over HTTP has no correct form. The threshold
API is library code consumed by protocol modules and CLI tools.

### VRF key material

Per-node Ed25519 key for AKD label derivation. Loaded or generated at
bootstrap. Never rotates -- rotating invalidates every derived label in
every namespace's AKD tree, requiring a full rebuild. This is a permanent
constraint of the ECVRF-EDWARDS25519-SHA512-TAI suite (0x03).

## Reconciliation

Three reconciliation mechanisms serve three different sets. All three
coexist; none is redundant.

### RBSR (range-based set reconciliation)

Reconciles blob-set membership across federation peers. XOR-monoid
fingerprints over ordered ranges provide O(difference) sync cost following
Meyer 2023 (arXiv:2212.13567).

The protocol is a three-message exchange:

1. **Fingerprint**: peer sends `{lower, upper, fingerprint}` for a range.
   If local fingerprint matches, respond `done`. If count is small
   (<=32 items), respond with items directly. Otherwise subdivide into
   4 sub-ranges with corrected bounds and recomputed fingerprints.

2. **Items request**: peer requests all items in a range. Respond with
   the full item list.

3. **Items exchange**: peer sends their items. Respond with items the
   peer lacks (set difference).

Endpoint: `POST /v2/{ns}/_reconcile` with JSON body containing `type`
field dispatching to the appropriate handler.

### MST (Merkle search tree)

Reconciles tag-name state across federation peers. Uses the
domodwyer/merkle-search-tree crate with a Blake3 hasher (not the default
SipHash, which is not collision-resistant).

The MST is deterministic: the same set of (name, value) pairs always
produces the same root hash regardless of insertion order. Root hash is
128-bit (SipHash24 internally for page hashing, Blake3 for value hashing).

`page_range_snapshot()` serializes the tree's page ranges for exchange.
`diff(local_ranges, peer_ranges)` identifies inconsistent key ranges
without transferring the full tag index.

### AKD (auditable key directory)

Assertion-level inclusion and absence proofs backed by a per-namespace redb
database. Three tables mirror the AKD storage model:

| Table | Tag | Key format | Purpose |
|-------|-----|-----------|---------|
| `akd_azks` | 1 | u8 | Single AZKS record |
| `akd_tree_nodes` | 2 | raw bytes | Sparse Merkle tree nodes |
| `akd_value_states` | 4 | username_len + username + epoch_be | User state history |

Transaction priority follows the AKD constraint: TreeNode and ValueState
are written first, AZKS last, all in one redb write transaction.

`scan_user_states(username)` performs a prefix scan to retrieve all epoch
states for a username, enabling historical assertion lookup.

### SSE event stream

Tag mutations emit `TagEvent` to a `tokio::sync::broadcast` channel with
4096 capacity. Each event carries namespace, tag name, old/new values,
epoch, operation type, and sequence number.

SSE format helpers (`format_sse_event`, `format_lag_event`) produce
standard Server-Sent Events output. When a subscriber falls behind the
channel capacity, a lag event is emitted so the client knows to re-sync
via RBSR.

The event stream enables push-based federation: a tag mutation emits an
event, subscribed peers learn immediately instead of polling.

### Database handle cache

`DbCache` caches `Arc<Database>` handles keyed by file path, solving the
redb file-lock contention problem. `Database::create` acquires an exclusive
OS file lock; only one instance may exist per file. Without caching,
concurrent requests to the same namespace would each try to open the file,
causing `DatabaseAlreadyOpen` errors.

`get_or_open(path)` creates parent directories, opens or returns the cached
handle. Thread-safe via `Mutex<HashMap<PathBuf, Arc<Database>>>`.

## Primitives

Sixteen protocol-agnostic primitives provide the complete substrate.

**P1: SHA-1 axis with collision detection.** SHA-1 content addressing via
sha1-checked (the RustCrypto port of sha1dc). Collision-attacked content is
rejected per-axis with `LabelError::CollisionDetected`. In a multi-label
push (sha256 + sha1), sha256 succeeds independently if sha1 collides.

**P2: Graph differencing.** `edge_diff(ns, have, want, rels)` computes
kappa-labels reachable from `want` roots but NOT reachable from `have`
roots via BFS along specified relation types. Common-ancestor early
termination prunes the `have` walk at nodes reachable from `want`.

**P3: Multi-object transactions.** Defense-in-depth: max concurrent (64),
per-txn byte limit, global staging limit (256 MiB), TTL-based auto-reap,
startup orphan cleanup. Objects staged in isolation under
`staging/{txn_id}/blobs/`, invisible to the main store until atomic commit
promotes them via `KappaStore::put()`.

**P4: Roaring bitmap GC.** GC sweep builds a `roaring::RoaringBitmap` of
reachable blob positions for O(1) cache-friendly eviction checks. Walk
relations include `owns`, `composed-of`, `assertion`, `revocation`,
`recovery-share`, and `capability` (D-7).

**P5: Per-tag version CAS.** Each tag carries an independent monotonic
version counter. `tag_set_if(ns, name, kappa, expected_version)` compares
against the tag's version, not its value. `expected_version = 0` means
create-if-absent (tag must not exist). `tag_set_batch` validates all
expectations in phase 1, applies all writes in phase 2. Any failure
rolls back all updates.

`If-Match` header takes a version number string (`"1"`, `"2"`).
`If-None-Match: *` uses version 0 (create-if-absent).

**P6: Symbolic pointers.** Tags store `ref:{target}` for pointer-to-pointer
resolution with loop detection (depth 10). `tag_get_raw` returns the raw
value without resolution. Batch CAS operates on raw values -- a symbolic
ref's raw value is `ref:target_name`, not the resolved kappa.

**P7: Object type metadata.** Every handler stores `object-type` metadata
(manifest, edge, composition, witness, schema, filter, pin) via
`meta_set(ns, kappa, entries)`. Queryable via `meta_query(ns, key, value)`,
`meta_query_compound(ns, filters)`, `meta_query_exists(ns, key)`, and
`meta_query_prefix(ns, key, value_prefix)`.

**P8: Delta-aware bulk transfer.** KBND bundle wire format: 4-byte magic
`KBND`, u8 version (1), u8 flags (0x01 = has deltas), u32 BE entry count,
entries, 32-byte SHA-256 trailer. Entry types: 0x01 (full object), 0x02
(delta). Git-compatible binary delta encoding with COPY/INSERT instructions,
FNV-1a block matching (16-byte windows), 75% size threshold, topological
ordering for single-pass decode, 256 MiB cumulative decode budget. 13 typed
`StoreError` variants for machine-parseable error codes.

**P9: Edge store on redb.** Per-namespace redb databases with four tables
(forward, reverse, by-relation, by-kappa). Length-prefixed 4-field compound
keys: `source | relation | target | asserter` (D-8: asserter last so
prefix scans on source/target remain valid). `query_by_asserter` filters
on field 4 during the prefix scan, avoiding BY_KAPPA deserialization for
non-matching asserters. Atomic write transactions. Namespace isolation.

**P10: Authenticated namespace root.** SHA-256 root hash over sorted
(name, value) pairs from the tag index. Recomputed on every tag mutation.
`mtime` and `version` are excluded from the root hash -- they are metadata
about the tag, not part of its identity. Inclusion proofs via full leaf
list. Signed roots via `SignedRoot` with Ed25519/P-256/K-256 and RFC 3339
timestamp.

**P11: Cryptographic signing.** See the Cryptography section above.

**P12: Blob byte-range reads.** `blob_get_range(kappa, offset, length)`
returns a byte range. `blob_size(kappa)` returns size without body load.
HTTP: `Range: bytes=N-M` returns 206 Partial Content with `Content-Range`
and `Accept-Ranges: bytes`. HEAD returns `Content-Length` from `blob_size`.

**P13: Structured metadata index.** Per-namespace redb database at
`index/meta/{safe_name(ns)}.redb`. Length-prefixed compound keys:
`u16(key.len) + key + u16(value.len) + value + u16(kappa.len) + kappa`.
Supports equality query, existence query, compound intersection, prefix
scan, and targeted removal.

**P14: Cascade delete.** `remove_reachable(ns, roots, rels)` walks edges
from roots along specified relations, removes all reachable blobs, edges,
tags, and metadata. Returns `RemovalReport`. `remove_reachable_from_prefix`
resolves tags matching a prefix, cascades, then deletes the matching tags.

**P15: Monotonic sequences.** Per-namespace redb database. `sequence_next`
atomically increments and returns a counter. `sequence_current` reads
without incrementing. Used internally for identity epoch tracking
(`identity_epoch` sequence per asserter namespace).

**P16: Tag prefix operations.** `tag_list_prefix(ns, prefix)` scans the
BTreeMap tag index using `prefix_successor()` for exclusive upper bound.
`tag_delete_prefix(ns, prefix)` atomically removes all matching tags and
recomputes the namespace root.

## API surface

### OCI distribution-spec 1.1

Standard OCI endpoints at `/v2/{namespace}/...`:

- `GET /v2/` -- version check
- Blob CRUD: GET, HEAD, PUT, DELETE
- Chunked upload: POST (start), PATCH (chunk), PUT (complete), GET (recovery), DELETE (cancel)
- Single-POST monolithic blob push via `?digest=`
- Mount existing blob via `?mount={kappa}`
- Multi-label push via `?also={blake3_kappa}`
- Manifest CRUD: GET, HEAD, PUT, DELETE
- Tag list with pagination (`?n=`, `?last=`), ordering (`?order=desc`), time-range filtering (`?after=`, `?before=`)
- Referrers API with `?artifactType=` filtering and `OCI-Filters-Applied` header
- Manifest delete by digest (resolves and removes all pointing tags)

### kappa-distribution extensions

| Endpoint | Method | Description |
|---|---|---|
| `/v2/{ns}/_identity/whoami` | GET | Node anchor, algorithm, trust position, self-assertions |
| `/v2/{ns}/tags/{name}` | PUT | Bind tag with version CAS (`If-Match: N`, `If-None-Match: *`) |
| `/v2/{ns}/tags/{name}?symref={target}` | PUT | Create symbolic reference |
| `/v2/{ns}/tags/{name}?raw=true` | GET | Read raw tag value without resolution |
| `/v2/{ns}/tags/_batch` | POST | Atomic multi-tag version CAS update |
| `/v2/{ns}/tags/_prefix?prefix=...` | DELETE | Delete all tags matching prefix |
| `/v2/{ns}/tags/` | POST/GET/DELETE | Tag CRUD via body/query param (slash-safe names) |
| `/v2/{ns}/edges/` | PUT | Create edge (source must exist) |
| `/v2/{ns}/edges/{node}` | GET | Query edges (direction, relation, pagination) |
| `/v2/{ns}/edges/{kappa}` | DELETE | Delete edge |
| `/v2/{ns}/edges/_diff` | POST | Graph set difference (have/want/relations) |
| `/v2/{ns}/compose/{op}` | POST | Algebraic composition (g2/f4/e6/e7/e8) |
| `/v2/{ns}/witnesses/{kappa}` | GET | Retrieve witness blob |
| `/v2/{ns}/schemas/{scope}` | PUT/GET | Schema registration and retrieval |
| `/v2/{ns}/schemas/` | GET | List schemas |
| `/v2/{ns}/filters/{scope}` | PUT/DELETE | Content filter management |
| `/v2/{ns}/filters/` | GET | List filters |
| `/v2/{ns}/blobs/_meta` | GET | Query blobs by metadata (key/value, compound, prefix) |
| `/v2/{ns}/blobs/_cascade` | POST | Cascade delete from roots or prefix |
| `/v2/{ns}/_bundle/create` | POST | Create KBND bundle (with optional delta encoding) |
| `/v2/{ns}/_bundle/ingest` | POST | Ingest KBND bundle |
| `/v2/{ns}/_transaction/begin` | POST | Begin multi-object transaction |
| `/v2/{ns}/_transaction/{id}/{kappa}` | PUT | Stage object in transaction |
| `/v2/{ns}/_transaction/{id}/commit` | POST | Atomic commit to main store |
| `/v2/{ns}/_transaction/{id}` | DELETE | Abort transaction |
| `/v2/{ns}/_reconcile` | POST | Range-based set reconciliation (RBSR) |
| `/v2/{ns}/_root` | GET | Namespace root hash and tag count |
| `/v2/{ns}/_root?signed=true` | GET | Signed namespace root with timestamp |
| `/v2/{ns}/_root/proof/{name}` | GET | Inclusion proof for tag |
| `/v2/{ns}/_sequence/{name}/next` | POST | Increment and return sequence counter |
| `/v2/{ns}/_sequence/{name}` | GET | Read sequence counter |
| `/v2/{ns}/gc/pin` | POST | Pin object as GC root (with optional finalizer) |
| `/v2/{ns}/gc/unpin` | POST | Unpin (blocked by outstanding finalizer unless released) |
| `/v2/{ns}/gc/sweep` | POST | Trigger async GC sweep |
| `/v2/{ns}/gc/status` | GET | GC status with reachability stats and pending finalizers |

## Rate limiting

Tiered per-IP GCRA rate limiting with three operation classes:

| Class | Scope | Default |
|-------|-------|---------|
| Read | GET/HEAD on all endpoints | 1000 burst, disabled |
| Write | PUT/POST/PATCH on content endpoints | 200 burst, disabled |
| Admin | DELETE, GC, transactions, reconcile, cascade | 50 burst, disabled |

Health endpoints (`/v2/`, `/v2/_health/*`) are always exempt. Rate limit
headers (`x-ratelimit-limit`, `x-ratelimit-remaining`) are attached to
every response when enabled. 429 responses include `retry-after` and
`x-ratelimit-after`.

## Error handling

All store errors implement `HttpErrorResponse` with typed status codes:

| StoreError variant | HTTP status | Body |
|-------------------|-------------|------|
| `NotFound` | 404 | "not found" |
| `Conflict("forbidden:...")` | 403 | "forbidden" |
| `Conflict(...)` | 409 | conflict detail |
| `Io(...)` | 500 | "internal server error" |
| `Rejected(...)` | 400 | rejection reason |
| `RangeNotSatisfiable` | 400 | range detail |
| Bundle/Delta variants | 400 | error detail |

`LabelError` maps to 400. `CryptoError::InvalidSignature` and
`UnsupportedAlgorithm` map to 400. `CryptoError::InvalidKey` maps to 500.

`serde_json::from_slice` errors use `.map_err(|e| bad_request(...))` at
every call site (orphan rule prevents trait impl on foreign types).

`spawn_blocking(f).await??` is the standard pattern: first `?` unwraps
`JoinError` (500 via `HttpErrorResponse`), second `?` unwraps `StoreError`.

## Service management

```bash
./scripts/service.sh --start              # start on localhost:5000
./scripts/service.sh --stop               # graceful shutdown (SIGTERM, escalate to SIGKILL)
./scripts/service.sh --status             # show pid, store path, log path
./scripts/service.sh --logs               # print the log file
./scripts/service.sh --clean              # remove pid and log files
./scripts/service.sh --clean --force      # also remove the store directory
```

Override the listen address:

```bash
KAPPA_LISTEN_ADDR=0.0.0.0:5000 ./scripts/service.sh --start
```

## Configuration

All configuration is via environment variables. No config files.

| Variable | Default | Description |
|---|---|---|
| `KAPPA_LISTEN_ADDR` | `127.0.0.1:5000` | Listen address |
| `KAPPA_STORE_ROOT` | `./data` | Filesystem store root |
| `KAPPA_MAX_BLOB_SIZE` | `67108864` | Maximum blob size (64 MiB) |
| `KAPPA_UPLOAD_TIMEOUT` | `3600` | Upload session timeout (seconds) |
| `KAPPA_MAX_TRANSACTIONS` | `64` | Maximum concurrent transactions |
| `KAPPA_MAX_STAGING_BYTES` | `268435456` | Global staging byte limit (256 MiB) |
| `KAPPA_SIGNING_ALGORITHM` | `ed25519` | Signing key algorithm (`ed25519`, `p256`, `k256`) |
| `KAPPA_RATELIMIT_READ_PERIOD_MS` | `0` | Read rate limit period (0 = disabled) |
| `KAPPA_RATELIMIT_READ_BURST` | `1000` | Read rate limit burst |
| `KAPPA_RATELIMIT_WRITE_PERIOD_MS` | `0` | Write rate limit period |
| `KAPPA_RATELIMIT_WRITE_BURST` | `200` | Write rate limit burst |
| `KAPPA_RATELIMIT_ADMIN_PERIOD_MS` | `0` | Admin rate limit period |
| `KAPPA_RATELIMIT_ADMIN_BURST` | `50` | Admin rate limit burst |

## Store layout

```
{store_root}/
  blobs/{axis}/{shard}/{kappa-label}          # content-addressed objects
  blobs/{axis}/{shard}/{kappa-label}.meta     # JSON metadata sidecar
  tags/{safe_name(ns)}/index.json             # BTreeMap<String, IndexEntry> (name, value, mtime, version)
  tags/{safe_name(ns)}/root.json              # computed namespace root hash
  edges/{safe_name(ns)}.redb                  # per-namespace edge database (4 tables)
  index/meta/{safe_name(ns)}.redb             # per-namespace structured metadata
  index/fingerprints/{safe_name(ns)}.json     # RBSR XOR-monoid fingerprint tree
  schemas/{safe_name(ns)}/{scope}.json        # schema registrations
  filters/{safe_name(ns)}/{scope}.json        # content filters
  sequences/{safe_name(ns)}.redb              # monotonic sequence counters
  gc/pins/{safe_name(pin_kappa)}.json         # GC pin records
  gc/status.json                              # last sweep status
  keys/default.{algorithm,pub,key,blake3}     # signing key material (Ed25519/P-256/K-256)
  keys/vrf.{key,pub,blake3}                   # VRF key material (never rotates)
  staging/{txn_id}/blobs/{axis}/{shard}/...   # transaction staging area
```

`safe_name(ns)` is SHA-256 of the namespace string, hex-encoded. This
prevents filesystem injection: `a/b` and `a_b` produce different hashes.

## Building

Requires Rust 1.95+. The Nix flake provides a hermetic toolchain:

```bash
nix develop

cargo build --release

# Quality gates (all three must pass with zero warnings)
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
# kappa-distribution conformance (187 tests, 5 levels)
./scripts/conformance.sh

# OCI distribution-spec 1.1 conformance (848 tests)
./scripts/oci-conformance.sh
```

## Dependencies

All pure Rust. No C toolchain required.

| Crate | Version | Purpose |
|---|---|---|
| topcoat | 0.4 | HTTP framework with typed error responses |
| tokio | 1 | Async runtime (rt-multi-thread, signal, sync) |
| sha2 | 0.10 | SHA-256, SHA-512 |
| sha1-checked | 0.10 | SHA-1 with collision detection |
| blake3 | 1 | BLAKE3 hashing |
| redb | 4 | Embedded B-tree KV store (edges, metadata, sequences, AKD) |
| roaring | 0.11 | Bitmap acceleration for GC reachability |
| ed25519-dalek | 3 | Ed25519 signing and verification |
| p256 | 0.14 | NIST P-256 ECDSA |
| k256 | 0.14 | secp256k1 ECDSA |
| signature | 3 | Signature trait abstraction |
| frost-core | 2 | FROST threshold signing protocol |
| frost-ed25519 | 2 | FROST for Ed25519 |
| frost-p256 | 2 | FROST for P-256 |
| frost-secp256k1 | 2 | FROST for secp256k1 |
| merkle-search-tree | 0.8 | Deterministic MST for tag reconciliation |
| governor | 0.10 | GCRA rate limiting |
| jsonschema | 0.46 | JSON Schema validation |
| serde / serde_json | 1 | Serialization |
| zeroize | 1.9 | Memory clearing for private key material |
| rand | 0.8 | RNG for FROST (rand_core 0.6 compatibility) |

## Architecture

```
src/
  lib.rs                # router, app context, rate limiting layer
  main.rs               # binary entrypoint, bootstrap, signal handling
  config.rs             # environment configuration
  kappa.rs              # KappaLabel type, hash computation, parse/verify
  delta.rs              # Git-compatible binary delta codec
  bundle.rs             # KBND bundle wire format with delta support
  transaction.rs        # TransactionManager with quarantine staging
  urls.rs               # URL builder functions
  auth/
    mod.rs              # authorize() re-export, RESERVED_PREFIXES
    policy.rs           # capability-edge authorization, reserved namespace check
    trust.rs            # TrustPolicy trait, AllowList implementation
  crypto/
    mod.rs              # RegistrySigner/Verifier traits, algorithm dispatch
    anchor.rs           # anchor_from_key (NodeAnchor), asserter_from_signature (AsserterAnchor)
    ed25519.rs          # Ed25519Signer, Ed25519Verifier
    ecdsa.rs            # P256Signer/Verifier, K256Signer/Verifier
    keystore.rs         # KeyStore with BLAKE3 integrity
    threshold.rs        # FROST generate/split/reconstruct for Ed25519/P-256/K-256
    vrf.rs              # VrfKeyMaterial for AKD label derivation
  events/
    mod.rs              # TagEvent, TagEventOp, EventBroadcaster
    sse.rs              # SSE format helpers (matches_filter, format_sse_event, format_lag_event)
  handlers/
    mod.rs              # path_param, registry_anchor, read_body, version, health, cascade, sequence, namespace root/proof
    identity.rs         # GET /_identity/whoami
    blob.rs             # blob CRUD, byte-range, meta query
    tag.rs              # manifest CRUD, tag CRUD, batch CAS, symref, prefix ops
    edge.rs             # edge CRUD, diff
    compose.rs          # algebraic composition (g2/f4/e6/e7/e8), witness
    schema.rs           # schema register/get/list
    filter.rs           # filter register/list/delete
    gc.rs               # pin/unpin/sweep/status
    bundle.rs           # bundle create/ingest
    transaction.rs      # transaction begin/put/commit/abort
    reconcile.rs        # RBSR fingerprint/items/items_request
    referrers.rs        # OCI referrers API
    upload.rs           # chunked upload session management
  identity/
    mod.rs              # module root, re-exports, invariant documentation (I-1 through I-8)
    anchor.rs           # NodeAnchor, AsserterAnchor, SubjectAnchor newtypes, AnchorSpec
    node.rs             # NodeIdentity, bootstrap, self-assertion, whoami
    trust.rs            # TrustPosition, DegradeReason, PeerRecord
    assertion.rs        # IdentityAssertion, canonical_bytes, kappa
    revocation.rs       # Revocation, RevocationReason, is_authorized
    resolution.rs       # resolve_at, resolve_all, ResolutionResult, unrevoked
    epoch.rs            # EpochRoot, EpochMutation, MutationOp, equivocation detection
    watermark.rs        # Watermark (O(1) bulk invalidation)
    absence.rs          # AbsenceProof (AKD NonMembershipProof wire type)
    audience.rs         # derive_audience_label, audience_akd_label, public_akd_label
  ratelimit/
    mod.rs              # OpClass enum, RateLimitConfig, ClassConfig
    limiter.rs          # TieredRateLimiter, GCRA KeyedLimiter, 429 response builder
    extract.rs          # Client IP extraction from X-Forwarded-For/X-Real-IP/Forwarded
  reconcile/
    mod.rs              # module root (RBSR + MST + AKD coexistence documentation)
    mst.rs              # NamespaceMst, Blake3Hasher, page-range diff
  store/
    mod.rs              # KappaStore trait (52 methods), StoreError, HttpErrorResponse impl, data types
    fs/
      mod.rs            # FsStore implementation
      blob.rs           # content-addressed blob storage
      tag.rs            # BTreeMap tag index with version CAS
      edge.rs           # redb edge store with 4-field compound keys
      meta.rs           # redb structured metadata index
      sequence.rs       # redb monotonic sequence counters
      fingerprint.rs    # XOR-monoid fingerprint tree for RBSR
      pin.rs            # GC pin records
      schema.rs         # schema registration
      filter.rs         # content filter evaluation
      akd_adapter.rs    # RedbAkdStore for AKD tree storage
      db_cache.rs       # Per-namespace redb handle cache
tests/
  integration/
    common.rs           # TestServer, raw HTTP client, URI builders, fixtures
    level0.rs           # Node identity bootstrap (7 tests)
    level1.rs           # Blob operations (53 tests)
    level2.rs           # Tag operations, CAS, symref (14 tests)
    level3.rs           # Edge operations, diff (5 tests)
    level4.rs           # Composition, schemas (6 tests)
    level5.rs           # GC, filters, rate limiting, metadata (14 tests)
    level6.rs           # Bundles, transactions, reconciliation (10 tests)
    level7.rs           # Namespace root, proof, batch rollback (8 tests)
    level8.rs           # Byte-range, cascade, sequences, metadata, prefix ops (18 tests)
scripts/
  service.sh            # Start/stop/status/logs/clean for local development
  conformance.sh        # kappa-distribution conformance suite runner
  oci-conformance.sh    # OCI distribution-spec conformance suite runner
```

## License

MIT OR Apache-2.0
