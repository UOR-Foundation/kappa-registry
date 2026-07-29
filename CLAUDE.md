# kappa-registry

Content-addressed object registry implementing the OCI distribution spec v1.1
and the kappa-distribution protocol. Algorithm-agnostic store, modular crate
architecture, 1032/1032 OCI conformance, 187/187 kappa-conformance.

## Engineering discipline

These rules are non-negotiable. They apply to every file, every edit, every
session. They exist because violating them caused bugs that took hours to fix.

Read files in full before modification. Not grep. Not partial reads. Not
"I already read it earlier." Read it now, in full, immediately before writing.
Grep finds what you search for. Reading finds what you did not know to search
for.

Verify every external API against source before calling it. Read the actual
function signature in the dependency source code. Do not assume from memory,
old code, or documentation. Upstream sources are cloned at
/workspace/usrbinkat/github.com/ -- read them. The old code compiling against
a dependency does not prove the API is the same in the version cargo resolves
today.

Write each file once. Read everything you need for this file before writing.
One read pass, one write pass. If you realize mid-write that you need to read
another file, stop writing, read it, then continue.

No TODOs. No stubs. No deferred fixes. No "for now." No "I will handle at
clippy time." No "mark the gap and move on." Every line is final-form code
when you write it.

Unused imports mean unfinished work. When you see an unused import, ask: what
code should use this? If the answer is code you have not written, write the
code. If the import is genuinely dead, explain what superseded it and remove
it. "The compiler says unused" is never sufficient justification for removal.

When you identify the correct fix, implement it. Do not articulate the right
answer and then choose the easier one. Do not say "the architectural
improvement is a separate commit." Do not say "I will keep what is already
working." If you see it, you fix it. There is no later.

Errors propagate with ?. Do not discard with let \_ = unless failure is
genuinely non-fatal with a comment explaining why. Silent error swallowing
hides bugs that surface in production as data loss.

Tests fail loudly. No unwrap_or_default() in test code. No status code
grouping with ||. assert_eq! on the exact expected value with
resp.text().unwrap() in the failure message. If a response cannot be read,
the test panics with the error.

The spec is the authority. When the code on disk differs from the spec, change
the code. When a dependency is missing, add it to the Cargo.toml. Do not
override the spec because the current state is more convenient.

No capability regression. When the old code can do something and the new code
cannot, that is a regression. The superset of old capabilities plus new
enhancements is the target. Silent capability loss is never acceptable.

Surface design gaps with evidence, do not guess. When you encounter something
the spec does not cover, stop and report what you found with file paths and
line numbers. Do not invent a solution and keep going.

Do not compile or test mid-work to validate partial progress unless
instructed. Write all code first. Compile once at the end. Partial
compilation creates a false sense of progress and burns context on diagnostics
from unfinished files.

Clippy and fmt are invariants, not gates. Warnings introduced by an edit are
fixed in the same edit. Zero warnings is maintained continuously, not achieved
at the end.

Every removal has a replacement. Do not delete code, functions, imports, or
capabilities without specifying what replaces them. Deletion without
replacement is regression.

Decision hierarchy: no regression beats spec beats convenience. When they
conflict, the option that preserves the most capability wins. Option<String>
carries more information than String. The stronger validation wins. The more
complete error handling wins.

## Conventions

Conventional commits. Objective, diff-derived, verbose technical bodies.
No AI attribution. No PII. No Co-Authored-By.

No em dashes, en dashes, arrows, ellipsis, or math operators in source.
Use ASCII equivalents.

File line count should not exceed 500 lines. If a file grows past 500, the
concern is too broad. Identify what leaked in and move it to the correct
module. The architecture drives the file size, not the other way around.

## Quality gates

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo test -p kappa-server --test smoke
cargo test -p kappa-server --test operational
```

All must pass with zero warnings before any commit.

## Conformance

```
./scripts/oci-conformance.sh    # 1032/1032 OCI distribution spec v1.1
./scripts/conformance.sh        # 187/187 kappa-distribution protocol
```

Both must pass with zero failures and zero warnings before any PR.

## Toolchain

Hermetic via Nix. flake.nix provides Rust 1.92 + musl targets via the
Konductor flake. Do not install via pip/npm/cargo/brew.

## Architecture

10-crate workspace. Each crate owns one concern.

```
crates/
  kappa-core              primitives: store trait, types, crypto, identity,
                          epoch, merkle, kappa labels, canonical dCBOR,
                          events, transactions, GC, bundles, deltas
  kappa-server            binary: config, ratelimit, auth, broadcast, main
  kappa-module-oci        OCI handlers: blob, manifest, tag, upload, referrer
  kappa-module-distribution  kappa handlers: edge, compose, gc, bundle,
                          filter, schema, transaction, reconcile, sequence,
                          namespace, cascade, events SSE
  kappa-module-identity   identity handlers: assertion, revocation, whoami
  kappa-store-redb        write-through B+tree acceleration for tag queries
  kappa-akd               append-only directory checkpoints
  kappa-reconcile         MST-based set reconciliation
  kappa-conformance       90 conformance tests
  kappa-types             re-exports for external consumers
```

### Store trait contract

The store is a content-addressed key-value store. The key is the kappa. The
caller provides it. The store does not compute digests. The store does not
know what algorithm produced the kappa. Digest computation is the caller's
responsibility. This is separation of concerns at the trait boundary.

blob_put(kappa, content) stores bytes at an address the caller computed.
Returns bool: true = newly stored, false = already existed. Handlers use the
bool for status codes (201 new, 200 existing).

Per-blob metadata via blob_put_meta(kappa, key, value) and
blob_get_meta(kappa, key). Content-type and any per-blob key-value data lives
here. Not on tags. Tags are namespace-scoped name-to-kappa bindings only.
TagEntry has 3 fields: name, kappa, version. No content_type.

Namespace-scoped metadata via meta_set(ns, kappa, key, value) and
meta_query(ns, key, value). Object-type and any queryable metadata lives here.
Indexed by (namespace, key, value) for efficient queries. Handlers that store
object-type call both blob_put_meta (global, for per-blob retrieval) and
meta_set (namespace-indexed, for metadata queries).

tag_set takes 3 arguments: (ns, name, kappa). No content_type parameter.

blob_put_computed(store, content) is a free function, not a trait method.
Computes sha256 and calls blob_put. Internal code calls it. OCI handlers
never call it because the client chooses the algorithm.

Every digest algorithm is structurally equal. sha256, sha512, blake3, sha1
all stored at blobs/{algo}/{shard}/{filename}. No primary/alternate
distinction. No \_also/ tags. No \_ct/ tags. No fallback chains.

### Dependency boundaries

kappa-core does NOT depend on: serde_json, tokio, topcoat, postcard, redb,
roaring, or any HTTP/async/protocol crate.

serde (derive only) is allowed in kappa-core for types that downstream crates
need to serialize. The derive is a capability declaration. The serialization
call is in the consumer.

dCBOR is the canonical format for everything that participates in
content-addressing, signing, or persistence. JSON is a wire format for HTTP
responses. JSON exists in protocol module crates and kappa-server. kappa-core
never imports serde_json.

Protocol module crates (kappa-module-oci, kappa-module-distribution,
kappa-module-identity) depend on kappa-core, topcoat, serde, serde_json,
tracing. They own HTTP handlers that translate between requests and kappa-core
primitives. They do not own primitives, store implementations, or server
infrastructure.

kappa-server depends on kappa-core and the protocol modules. It owns config,
rate limiting, auth, broadcast, graceful shutdown, and periodic cleanup.

### Handler pattern

Every OCI handler is a straight line:

verify digest
-> evaluate filters (BEFORE storing, rejected content never stored)
-> validate schema (BEFORE storing)
-> blob_put(client_digest, content)
-> blob_put_meta("content-type", ct)
-> response with headers

Every store call goes through tokio::task::spawn_blocking in async handlers.
The store does filesystem I/O. Calling store methods directly in async context
blocks the tokio runtime.

Every error response uses the OCI error envelope:
{"errors": [{"code": "...", "message": "..."}]}
via the error_response or oci_error helper functions.

Every GET and HEAD response includes:
content-type (from blob_get_meta, default application/octet-stream)
content-length (from blob_size or content.len())
docker-content-digest (the kappa string)
x-kappa-label (the kappa string)
x-kappa-axis (the algorithm portion)
accept-ranges: bytes (on blob GET/HEAD)

Range requests use blob_size + blob_get_range. Never read the full blob for a
range request.

### EpochRoot persistence

EpochRoot is a Merkle tree of 7 dCBOR-encoded leaves. Its kappa is
kappa_from_bytes(&root_hash). The blob content is the leaves serialized with
4-byte big-endian length prefixes, plus an optional 8th entry for the
signature. from_leaf_bytes accepts 7 entries (unsigned) or 8 (signed). Merkle
root recomputed from entries 0-6 only.

epoch_get falls back to blob recovery after restart. epoch_current falls back
to the \_epoch/current tag after restart.

## Build and run

```
cargo build -p kappa-server                    # debug build
cargo build --release -p kappa-server          # release build

KAPPA_LISTEN_ADDR=127.0.0.1:5000 \
  ./target/release/kappa-server                # run
```

## Environment variables

```
KAPPA_LISTEN_ADDR             default 127.0.0.1:5000
KAPPA_STORE_ROOT              default ./data
KAPPA_MAX_BLOB_SIZE           default 268435456 (256 MiB)
KAPPA_UPLOAD_TIMEOUT          default 3600
KAPPA_SIGNING_ALGORITHM       default ed25519
KAPPA_MAX_TRANSACTIONS        default 64
KAPPA_MAX_STAGING_BYTES       default 268435456 (256 MiB)
KAPPA_RATELIMIT_READ_PERIOD_MS    default 100
KAPPA_RATELIMIT_READ_BURST        default 200
KAPPA_RATELIMIT_WRITE_PERIOD_MS   default 200
KAPPA_RATELIMIT_WRITE_BURST       default 50
KAPPA_RATELIMIT_ADMIN_PERIOD_MS   default 1000
KAPPA_RATELIMIT_ADMIN_BURST       default 10
```

## Key dependency versions (source-verified)

```
dcbor 0.25 (fork with derive macros)
rand_core 0.10, getrandom 0.4
sha2 0.11, blake3 1, sha1-checked 0.10
ed25519-dalek 3 (rand_core feature)
p256/k256 0.14
frost-core/frost-ed25519/frost-p256/frost-secp256k1 3.0.0
dashmap 6, governor 0.6
redb 4, akd 0.12
topcoat 0.4 (fork: usrbinkat/feat/trailing-slash-tolerance)
```

frost 3.0.0 re-exports rand_core 0.6 (not 0.10). RNG for frost operations
uses frost's re-exported OsRng gated behind the getrandom feature on
rand_core 0.6.

---historical---

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
