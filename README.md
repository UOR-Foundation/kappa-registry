# kappa-registry

A single-binary server that speaks Docker, Git, S3, Nix, and AT Protocol,
storing everything in one content-addressed database. One process, one port,
one data directory.

Five standard network protocols connect to the same server. Each speaks its
native wire format. Each stores to the same substrate. Content shared across
protocols is stored once.

| Protocol | Client | Example |
|---|---|---|
| OCI | `docker push`, `skopeo`, `crane` | `docker push registry:5000/myorg/app:v1` |
| Git | `git push`, `git clone` | `git push http://registry:5000/myorg/repo` |
| S3 | `aws s3`, any S3 SDK | `aws s3 cp file.txt s3://bucket/key --endpoint-url http://registry:5000` |
| Nix | `nix copy` | `nix copy --to http://registry:5000/nix /nix/store/...` |
| AT Protocol | any XRPC client | `POST /xrpc/com.atproto.server.createAccount` |

A sixth protocol surface, kappa-distribution, extends OCI with typed edges,
algebraic composition, multi-object transactions, delta bundles, set
reconciliation, and monotonic sequences.

All six share one identity system: cryptographic anchors, delegation chains,
key rotation with continuity, and handle verification. Authorization is
capability-edge based with delegation chain walks up to five hops.

---

## Quick start

```bash
cargo build --release
./scripts/service.sh --start
```

The server starts on `127.0.0.1:5000`. Data is stored in `./data` by default.
On first start it generates an Ed25519 signing key, bootstraps system
namespaces (`_root`, `_nix`, `_system`, `_admin`, `_aliases`, `_handles`),
and begins serving all protocols.

```bash
./scripts/service.sh --stop       # graceful shutdown
./scripts/service.sh --status     # pid, store path, log path
./scripts/service.sh --logs       # print log file
./scripts/service.sh --clean      # remove pid and log files
```

Override the listen address:

```bash
KAPPA_LISTEN_ADDR=0.0.0.0:5000 ./scripts/service.sh --start
```

### Data and persistence

All state lives under `KAPPA_STORE_ROOT` (default `./data`):

- `blobs/` -- content-addressed object storage
- `state.redb` -- database (tags, edges, sequences, metadata, namespaces, epochs)
- `keys/` -- Ed25519 signing key with BLAKE3 integrity checking
- `staging/` -- temporary upload files (cleaned on restart)

**Back up `blobs/`, `state.redb`, and `keys/`.** The signing key is the
node's identity. Losing it means losing all capability edges, delegation
chains, and epoch signatures. The key is never regenerated silently; a
corrupted keystore fails hard on startup.

On restart, the server recovers epoch pointers, namespace state, and upload
sessions from the database. No data loss on clean shutdown or `kill -9`.

---

## OCI distribution-spec

OCI distribution-spec 1.1 conformant. Standard endpoints at `/v2/{namespace}/...`.

### Push and pull

```bash
# Push
skopeo copy --dest-tls-verify=false \
  docker://docker.io/library/alpine:latest \
  docker://127.0.0.1:5000/test/alpine:latest

# Inspect
skopeo inspect --tls-verify=false docker://127.0.0.1:5000/test/alpine:latest

# Pull
skopeo copy --src-tls-verify=false \
  docker://127.0.0.1:5000/test/alpine:latest \
  oci:/tmp/pulled-image:latest
```

### Blob operations

```bash
content='hello from kappa'
digest="sha256:$(printf '%s' "$content" | sha256sum | cut -d ' ' -f 1)"

# Monolithic PUT
curl -X PUT \
  -H 'Content-Type: application/octet-stream' \
  --data-binary "$content" \
  "http://127.0.0.1:5000/v2/example/blobs/$digest"

# GET
curl "http://127.0.0.1:5000/v2/example/blobs/$digest"

# HEAD (size without body)
curl -I "http://127.0.0.1:5000/v2/example/blobs/$digest"

# Range request
curl -H "Range: bytes=0-4" "http://127.0.0.1:5000/v2/example/blobs/$digest"

# DELETE
curl -X DELETE "http://127.0.0.1:5000/v2/example/blobs/$digest"
```

### Chunked upload

```bash
# Start
upload_url=$(curl -s -D - -X POST \
  "http://127.0.0.1:5000/v2/example/blobs/uploads/" \
  | grep -i location | tr -d '\r' | awk '{print $2}')

# Append chunks
curl -X PATCH -H "Content-Type: application/octet-stream" \
  --data-binary @chunk1.bin "$upload_url"

# Complete with digest
curl -X PUT "$upload_url&digest=$digest"
```

Upload sessions expire after `KAPPA_UPLOAD_TIMEOUT` seconds (default 3600).
Recovery via `GET` on the upload URL returns bytes received.

### Manifests and tags

```bash
# Push manifest by tag
curl -X PUT \
  -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
  --data-binary @manifest.json \
  "http://127.0.0.1:5000/v2/example/manifests/latest"

# Push manifest by digest
curl -X PUT \
  -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' \
  --data-binary @manifest.json \
  "http://127.0.0.1:5000/v2/example/manifests/$digest"

# Get manifest
curl "http://127.0.0.1:5000/v2/example/manifests/latest"

# Tag list
curl "http://127.0.0.1:5000/v2/example/tags/list"

# Tag list with pagination
curl "http://127.0.0.1:5000/v2/example/tags/list?n=10&last=v1.0"
```

### Referrers

```bash
# List referrers (signatures, attestations) for a manifest
curl "http://127.0.0.1:5000/v2/example/referrers/$digest"

# Filter by artifact type
curl "http://127.0.0.1:5000/v2/example/referrers/$digest?artifactType=application/vnd.cncf.notary.signature"
```

### Content filters and schema validation

```bash
# Register a schema
curl -X PUT \
  -H 'Content-Type: application/json' \
  --data-binary @schema.json \
  "http://127.0.0.1:5000/v2/example/schemas/manifests"

# Register a deny filter
curl -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"action":"deny","match":{"mediaType":"application/x-tar"}}' \
  "http://127.0.0.1:5000/v2/example/filters/no-tar"
```

Filters and schemas are evaluated **before** storage. Rejected content never
enters the blob store.

### Garbage collection

```bash
# Pin an object as a GC root
curl -X POST -d '{"kappa":"sha256:abc..."}' \
  "http://127.0.0.1:5000/v2/example/gc/pin"

# Trigger sweep
curl -X POST "http://127.0.0.1:5000/v2/example/gc/sweep"

# Check status
curl "http://127.0.0.1:5000/v2/example/gc/status"
```

GC traces from tagged manifests and pinned objects through typed edges.
Tagged images survive. Orphaned layers from deleted manifests are collected.

---

## Git smart HTTP

Smart HTTP v1 and v2 with Git LFS. Signal-based protocol detection: no
`.git` URL suffix required.

### Push and clone

```bash
# Push a repository
git remote add kappa http://localhost:5000/myorg/myrepo
git push -u kappa main

# Clone
git clone http://localhost:5000/myorg/myrepo /tmp/cloned

# Verify
diff -r . /tmp/cloned
```

### Incremental fetch

```bash
# Make changes and push
echo "update" >> file.txt && git commit -am "update" && git push

# Fetch from another clone
cd /tmp/cloned && git fetch origin && git merge origin/main
```

Only new objects are transferred. The server computes the need set by
walking the commit graph from wanted refs and excluding objects reachable
from common ancestors.

### Nested namespaces

GitLab-style nesting at any depth:

```bash
git clone http://localhost:5000/myorg/team/sub/project
```

The namespace is everything before the Git operation suffix (`/info/refs`,
`/git-upload-pack`, etc.).

### SHA-256 repositories

```bash
# Initialize a SHA-256 repository
git init --object-format=sha256 myrepo
cd myrepo
git remote add kappa http://localhost:5000/sha256-repo
echo "content" > file.txt && git add . && git commit -m "init"
git push -u kappa main
```

SHA-256 repositories use 64-character OIDs and 32-byte tree entries.
The object format is stored per-repository and advertised in the
capability handshake.

### Git LFS

```bash
git lfs track "*.bin"
git add .gitattributes large.bin
git commit -m "add binary"
git push
```

LFS objects are served through the batch API at `/info/lfs/objects/batch`.
Download and upload URLs point to the registry's own blob endpoints. No
separate LFS storage backend.

### Hooks

Pre-receive hooks run before ref updates. Store a script blob and tag it
under `_hooks/pre-receive` in the namespace:

```bash
# The hook receives on stdin: {old_oid} {new_oid} {ref_name}
# Exit non-zero to reject the push
```

Post-receive hooks run fire-and-forget in a background thread after ref
updates succeed.

### Shallow and partial clone

```bash
# Shallow clone (depth-limited)
git clone --depth 1 http://localhost:5000/myorg/repo

# Partial clone (no blobs until checkout)
git clone --filter=blob:none http://localhost:5000/myorg/repo
```

---

## S3-compatible API

S3-compatible object storage with SigV4 authentication.

### Setup

```bash
# Configure endpoint
export AWS_ENDPOINT_URL=http://localhost:5000
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
```

For unauthenticated access during development:

```bash
export AWS_ENDPOINT_URL=http://localhost:5000
alias s3='aws --no-sign-request s3'
alias s3api='aws --no-sign-request s3api'
```

### Bucket operations

```bash
# Create
aws s3 mb s3://mybucket

# List all buckets
aws s3 ls

# Head (check existence)
aws s3api head-bucket --bucket mybucket

# Delete (must be empty)
aws s3 rb s3://mybucket
```

### Object CRUD

```bash
# Upload
aws s3 cp file.txt s3://mybucket/dir/file.txt

# Download
aws s3 cp s3://mybucket/dir/file.txt /tmp/downloaded.txt

# List
aws s3 ls s3://mybucket/dir/

# List recursively
aws s3 ls s3://mybucket/ --recursive

# Head (metadata without body)
aws s3api head-object --bucket mybucket --key dir/file.txt

# Delete
aws s3 rm s3://mybucket/dir/file.txt
```

### Multipart upload

The aws CLI uses multipart for files larger than 8 MB by default:

```bash
aws s3 cp large-file.bin s3://mybucket/large-file.bin
```

Per-part ETag validation on `CompleteMultipartUpload`. Composite ETag
format: `md5(md5(part1)||md5(part2)||...)-N`.

Per-part checksums (CRC32C, CRC64-NVME) are computed during upload and
combinable for whole-object verification.

### Batch delete

```bash
aws s3api delete-objects --bucket mybucket --delete '{
  "Objects": [
    {"Key": "file1.txt"},
    {"Key": "file2.txt"}
  ]
}'
```

### Copy

```bash
aws s3 cp s3://mybucket/source.txt s3://mybucket/dest.txt
aws s3 cp s3://source-bucket/key s3://dest-bucket/key
```

### Object versioning

```bash
# Enable versioning
aws s3api put-bucket-versioning \
  --bucket mybucket \
  --versioning-configuration Status=Enabled

# Upload creates a version
aws s3 cp file.txt s3://mybucket/file.txt

# Delete inserts a delete marker (object appears deleted, versions retained)
aws s3 rm s3://mybucket/file.txt

# List versions
aws s3api list-object-versions --bucket mybucket

# Get specific version
aws s3api get-object --bucket mybucket --key file.txt \
  --version-id "version-id-here" /tmp/old-version.txt

# Permanently delete a version
aws s3api delete-object --bucket mybucket --key file.txt \
  --version-id "version-id-here"
```

### Object tagging

```bash
# Set tags (max 10 per object)
aws s3api put-object-tagging --bucket mybucket --key file.txt \
  --tagging 'TagSet=[{Key=env,Value=prod},{Key=team,Value=infra}]'

# Get tags
aws s3api get-object-tagging --bucket mybucket --key file.txt

# Delete tags
aws s3api delete-object-tagging --bucket mybucket --key file.txt
```

### Bucket policy

```bash
# Set policy
aws s3api put-bucket-policy --bucket mybucket --policy '{
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": "*"
  }]
}'

# Get policy
aws s3api get-bucket-policy --bucket mybucket

# Delete policy
aws s3api delete-bucket-policy --bucket mybucket
```

Statement matching supports `Effect` (Allow/Deny), `Action` (wildcard
and prefix matching), and implicit deny when statements exist but none
allows.

### Lifecycle expiration

```bash
aws s3api put-bucket-lifecycle-configuration --bucket mybucket \
  --lifecycle-configuration '{
  "Rules": [{
    "ID": "expire-old",
    "Status": "Enabled",
    "Expiration": {"Days": 30},
    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
  }]
}'
```

The background task evaluates lifecycle rules at `KAPPA_LIFECYCLE_INTERVAL_SECS`
(default 86400, 24 hours).

### Virtual-hosted-style routing

Set `KAPPA_S3_BASE_DOMAIN` to enable subdomain-based bucket routing:

```bash
KAPPA_S3_BASE_DOMAIN=s3.registry.local ./scripts/service.sh --start

# mybucket.s3.registry.local:5000/key -> /mybucket/key
curl http://mybucket.s3.registry.local:5000/mykey
```

### SigV4 authentication

Every S3 request is authenticated via AWS Signature Version 4:

- Header authentication (`Authorization: AWS4-HMAC-SHA256 ...`)
- Presigned URLs with expiration
- Chunk signature chaining for streaming uploads
- Trailer signatures

Configure credentials via `KAPPA_AUTH_TOKENS` (format: `token=anchor`).
Credential rotation with grace period is supported.

---

## Nix binary cache

Nix binary cache protocol with narinfo codec, NAR verification, and
compression-transparent serving.

### Push a closure

```bash
nix copy --to 'http://localhost:5000/nix' \
  $(nix build nixpkgs#hello --print-out-paths --no-link)
```

### Configure as a substituter

In `nix.conf` or `configuration.nix`:

```
substituters = http://registry:5000/nix
```

The server responds to:

- `GET /nix-cache-info` -- store directory, priority, mass query support
- `GET /{hash}.narinfo` -- narinfo with StorePath, NarHash, URL, signatures
- `HEAD /{hash}.narinfo` -- existence check
- `PUT /{hash}.narinfo` -- store narinfo
- `GET /nar/{path}` -- compressed NAR download
- `PUT /nar/{path}` -- NAR upload

### Verification

NarHash is verified after decompression (zstd, xz, bzip2, or uncompressed).
The server accepts narinfo-before-NAR and NAR-before-narinfo upload ordering.
Verification runs at whichever PUT completes the pair.

Failed verification removes the narinfo tag. A narinfo whose NAR never
arrives is an orphan tag, collected by GC.

### Reference scanning

On NAR upload, the server scans for `/nix/store/{32-nix-base32-chars}`
patterns and creates dependency edges. Closure computation becomes an
edge traversal rather than recursive narinfo fetching.

### Compression-transparent serving

NARs are stored as compressed archives. The server serves compressed bytes
directly to `nix build` clients (zero-copy, streaming) while also knowing
the content by its uncompressed NarHash for verification purposes.

### Provenance chain

Each narinfo upload creates an assertion edge from the signing key's
anchor to the narinfo blob, recording which key signed which package.
The chain: signing key -> assertion -> narinfo -> dependency edges.

### Trusted keys

Configure trusted Nix signing keys:

```bash
KAPPA_NIX_TRUSTED_KEYS="cache.nixos.org-1:base64pubkey,my-key:base64pubkey"
```

Keys are resolved to identity anchors via the resolver registry.

---

## AT Protocol

AT Protocol support requires the `atproto` feature flag:

```bash
cargo build --release --features atproto
```

Without this flag, all `/xrpc/` endpoints return 404.

### Account creation

```bash
curl -X POST http://localhost:5000/xrpc/com.atproto.server.createAccount \
  -H 'Content-Type: application/json' \
  -d '{"handle": "alice.example.com", "password": "secret"}'
```

Returns `accessJwt`, `refreshJwt`, `did`, and `handle`. Creates the DID
namespace, initializes an empty Merkle Search Tree, creates the initial
signed commit, and registers credentials.

If no DID is provided, a deterministic `did:plc:` is generated from the
handle.

### Session management

```bash
# Create session
curl -X POST http://localhost:5000/xrpc/com.atproto.server.createSession \
  -H 'Content-Type: application/json' \
  -d '{"identifier": "did:plc:...", "password": "secret"}'

# Get session info
curl http://localhost:5000/xrpc/com.atproto.server.getSession \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Refresh session
curl -X POST http://localhost:5000/xrpc/com.atproto.server.refreshSession \
  -H "Authorization: Bearer $REFRESH_TOKEN"

# Delete session
curl -X POST http://localhost:5000/xrpc/com.atproto.server.deleteSession \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

Sessions are DPoP-bound per RFC 9449. Write endpoints verify the ES256
signature on the DPoP proof JWT, check method and URI binding, token hash
binding, key binding, JTI replay prevention, and timestamp freshness.

Bearer tokens are also accepted for backward compatibility.

### Record CRUD

```bash
# Create record
curl -X POST http://localhost:5000/xrpc/com.atproto.repo.createRecord \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "repo": "did:plc:...",
    "collection": "app.bsky.feed.post",
    "record": {"text": "Hello from kappa-registry", "createdAt": "2026-01-01T00:00:00Z"}
  }'

# Get record
curl "http://localhost:5000/xrpc/com.atproto.repo.getRecord?repo=did:plc:...&collection=app.bsky.feed.post&rkey=..."

# List records
curl "http://localhost:5000/xrpc/com.atproto.repo.listRecords?repo=did:plc:...&collection=app.bsky.feed.post"

# Update record
curl -X POST http://localhost:5000/xrpc/com.atproto.repo.putRecord \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "repo": "did:plc:...",
    "collection": "app.bsky.feed.post",
    "rkey": "...",
    "record": {"text": "Updated post", "createdAt": "2026-01-01T00:00:00Z"}
  }'

# Delete record
curl -X POST http://localhost:5000/xrpc/com.atproto.repo.deleteRecord \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"repo": "did:plc:...", "collection": "app.bsky.feed.post", "rkey": "..."}'
```

Every record mutation rebuilds the Merkle Search Tree and creates a new
signed commit, maintaining a valid commit chain.

### Batch writes

```bash
curl -X POST http://localhost:5000/xrpc/com.atproto.repo.applyWrites \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "repo": "did:plc:...",
    "writes": [
      {"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "value": {"text": "post 1"}},
      {"$type": "com.atproto.repo.applyWrites#create", "collection": "app.bsky.feed.post", "value": {"text": "post 2"}}
    ]
  }'
```

One MST rebuild and one commit per batch, not per write.

### Blob upload

```bash
curl -X POST http://localhost:5000/xrpc/com.atproto.repo.uploadBlob \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: image/png' \
  --data-binary @image.png
```

### Repository export

```bash
# Full export as CAR file
curl "http://localhost:5000/xrpc/com.atproto.sync.getRepo?did=did:plc:..." \
  -o repo.car

# Incremental export (only blocks since a previous revision)
curl "http://localhost:5000/xrpc/com.atproto.sync.getRepo?did=did:plc:...&since=rev-tid" \
  -o delta.car
```

The CAR export walks the MST depth-first via CID-to-kappa bridge tags,
collecting all reachable MST nodes and record blobs. Incremental sync
builds an exclusion set from the `since` commit's MST and exports only
the difference.

### Firehose

```bash
# WebSocket subscription
websocat ws://localhost:5000/xrpc/com.atproto.sync.subscribeRepos

# With cursor for resume
websocat "ws://localhost:5000/xrpc/com.atproto.sync.subscribeRepos?cursor=42"
```

DAG-CBOR binary frames by default. Four event types: `#commit`, `#handle`,
`#identity`, `#tombstone`. JSON text frames available via `force_json`
configuration for debugging.

Backpressure: if a subscriber falls behind by more than `max_lag` events
(default 10000), the server sends an `OutdatedCursor` info frame and
closes the connection.

### Handle resolution

```bash
curl "http://localhost:5000/xrpc/com.atproto.identity.resolveHandle?handle=alice.example.com"
```

Resolves via the resolver registry (WebFinger, DNS TXT, PLC directory)
then falls back to the local handle registry.

### Handle update

```bash
curl -X POST http://localhost:5000/xrpc/com.atproto.identity.updateHandle \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"handle": "newalice.example.com"}'
```

### Server description

```bash
curl http://localhost:5000/xrpc/com.atproto.server.describeServer
```

### Crawl notification

```bash
curl -X POST http://localhost:5000/xrpc/com.atproto.sync.requestCrawl \
  -H 'Content-Type: application/json' \
  -d '{"hostname": "relay.example.com"}'
```

Fire-and-forget notification to a relay.

---

## kappa-distribution extensions

Extensions to OCI at `/v2/{namespace}/...`.

### Typed edges

```bash
# Create edge
curl -X PUT \
  -H 'Content-Type: application/json' \
  -d '{"source": "sha256:aaa...", "target": "sha256:bbb...", "relation": "refers-to"}' \
  "http://127.0.0.1:5000/v2/example/edges/"

# Query outbound edges
curl "http://127.0.0.1:5000/v2/example/edges/sha256:aaa...?direction=outbound"

# Query inbound edges
curl "http://127.0.0.1:5000/v2/example/edges/sha256:bbb...?direction=inbound"

# Filter by relation
curl "http://127.0.0.1:5000/v2/example/edges/sha256:aaa...?direction=outbound&relation=refers-to"

# Delete edge
curl -X DELETE "http://127.0.0.1:5000/v2/example/edges/sha256:edge-kappa..."

# Graph diff (have/want)
curl -X POST \
  -H 'Content-Type: application/json' \
  -d '{"have": ["sha256:aaa..."], "want": ["sha256:bbb..."]}' \
  "http://127.0.0.1:5000/v2/example/edges/_diff"
```

Seventeen relation types: `owns`, `composed-of`, `assertion`, `revocation`,
`capability`, `recovery-share`, `epoch-root`, `akd-tree-node`,
`chunk-manifest`, `witness-receipt`, `offload-receipt`, `derived-from`,
`certified-by`, `evidence-provenance`, `section-of`, `refers-to`,
`delegation`.

### Tag operations

```bash
# Conditional tag update (CAS)
curl -X PUT \
  -H "If-Match: 3" \
  -d '{"kappa": "sha256:new..."}' \
  "http://127.0.0.1:5000/v2/example/tags/latest"

# Create-if-absent
curl -X PUT \
  -H "If-None-Match: *" \
  -d '{"kappa": "sha256:abc..."}' \
  "http://127.0.0.1:5000/v2/example/tags/v1.0"

# Symbolic reference
curl -X PUT "http://127.0.0.1:5000/v2/example/tags/HEAD?symref=latest"

# Read raw value (no symbolic resolution)
curl "http://127.0.0.1:5000/v2/example/tags/HEAD?raw=true"

# Atomic batch update
curl -X POST \
  -H 'Content-Type: application/json' \
  -d '[{"name":"v1","kappa":"sha256:aaa...","expected_version":1},
       {"name":"v2","kappa":"sha256:bbb...","expected_version":null}]' \
  "http://127.0.0.1:5000/v2/example/tags/_batch"

# Delete tags by prefix
curl -X DELETE "http://127.0.0.1:5000/v2/example/tags/_prefix?prefix=temp/"
```

### Algebraic composition

```bash
curl -X POST \
  -H 'Content-Type: application/json' \
  -d '{"a": "sha256:aaa...", "b": "sha256:bbb..."}' \
  "http://127.0.0.1:5000/v2/example/compose/g2"
```

Operations: `g2`, `f4`, `e6`, `e7`, `e8`.

### Multi-object transactions

```bash
# Begin
txn_id=$(curl -s -X POST "http://127.0.0.1:5000/v2/example/_transaction/begin" | jq -r .id)

# Stage objects
curl -X PUT --data-binary @obj1 \
  "http://127.0.0.1:5000/v2/example/_transaction/$txn_id/sha256:obj1..."

curl -X PUT --data-binary @obj2 \
  "http://127.0.0.1:5000/v2/example/_transaction/$txn_id/sha256:obj2..."

# Atomic commit
curl -X POST "http://127.0.0.1:5000/v2/example/_transaction/$txn_id/commit"

# Or abort
curl -X DELETE "http://127.0.0.1:5000/v2/example/_transaction/$txn_id"
```

### Bundles

```bash
# Create bundle (with optional delta compression)
curl -X POST \
  -d '{"roots": ["sha256:aaa..."], "delta": true}' \
  "http://127.0.0.1:5000/v2/example/_bundle/create" \
  -o bundle.kbnd

# Ingest bundle
curl -X POST --data-binary @bundle.kbnd \
  "http://127.0.0.1:5000/v2/example/_bundle/ingest"
```

### Set reconciliation

```bash
curl -X POST \
  -H 'Content-Type: application/json' \
  -d '{"type": "fingerprint", "lower": "", "upper": "~"}' \
  "http://127.0.0.1:5000/v2/example/_reconcile"
```

Range-based set reconciliation using XOR-monoid fingerprints for
O(difference) federation sync.

### Namespace root and proofs

```bash
# Root hash
curl "http://127.0.0.1:5000/v2/example/_root"

# Signed root
curl "http://127.0.0.1:5000/v2/example/_root?signed=true"

# Inclusion proof for a tag
curl "http://127.0.0.1:5000/v2/example/_root/proof/latest"
```

### Monotonic sequences

```bash
# Increment and return
curl -X POST "http://127.0.0.1:5000/v2/example/_sequence/build-number/next"

# Read current value
curl "http://127.0.0.1:5000/v2/example/_sequence/build-number"
```

### SSE event stream

Tag mutations emit Server-Sent Events:

```bash
curl -N "http://127.0.0.1:5000/v2/example/_events"
```

### WebSocket CRDT

Collaborative state via WebSocket:

```bash
websocat ws://localhost:5000/v2/example/_crdt/doc1/_ws
```

---

## Identity

### Node identity

```bash
curl http://localhost:5000/identity/whoami
```

Returns the node's anchor, algorithm, trust position, epoch, and
self-assertions.

### Anchors

An anchor is `sha256(dCBOR(algorithm || public_key_bytes))`. Deterministic,
offline, no registry needed. Three algorithms: Ed25519, P-256, K-256.
FROST threshold signatures (arbitrary t-of-n) for all three.

### Assertions

```bash
# Assert a claim
curl -X POST http://localhost:5000/v2/{ns}/_identity/assert \
  -H 'Content-Type: application/json' \
  -d '{"subject": "sha256:...", "facet": "key/signing", "value": "..."}'

# Resolve assertions about a subject
curl "http://localhost:5000/v2/{ns}/_identity/resolve?subject=sha256:...&facet=key/signing"

# Revoke an assertion
curl -X POST http://localhost:5000/v2/{ns}/_identity/revoke \
  -H 'Content-Type: application/json' \
  -d '{"assertion_kappa": "sha256:...", "reason": "superseded"}'
```

Multiple assertions about the same subject from different asserters are
not conflicts. They are distinguishable facts. Resolution returns all
of them unmerged. The substrate does not score, merge, or pick winners.

### Identity bindings

```bash
# Bind an external identifier to an anchor
curl -X POST http://localhost:5000/identity/binding \
  -H 'Content-Type: application/json' \
  -d '{"source": "user@example.com", "target": "sha256:anchor...", "method": "email-link", "trust_level": 2, "verified_at_ms": 1234567890}'

# Query bindings for an identifier
curl http://localhost:5000/identity/binding/user@example.com

# List all bindings for an anchor
curl http://localhost:5000/identity/binding/asserter/sha256:anchor...

# Delete binding
curl -X DELETE http://localhost:5000/identity/binding \
  -d '{"source": "user@example.com", "target": "sha256:anchor..."}'
```

### Identity succession (key rotation)

```bash
# Record key rotation
curl -X POST http://localhost:5000/identity/succession \
  -H 'Content-Type: application/json' \
  -d '{"old_anchor": "sha256:old...", "new_anchor": "sha256:new...", "reason": "rotation", "effective_at_ms": 1234567890, "old_signature": "...", "new_signature": "..."}'

# Resolve to current anchor
curl http://localhost:5000/identity/succession/sha256:old...

# Full chain
curl http://localhost:5000/identity/succession/sha256:old.../chain
```

Key rotation creates a watermark. `KeyCompromise` voids all assertions
from the old anchor. Ordinary rotation voids assertions before
`effective_at_ms`. Historical assertions remain queryable by timestamp.

### Handle registry

```bash
# Claim a handle
curl -X POST http://localhost:5000/identity/handle/claim \
  -H 'Content-Type: application/json' \
  -d '{"handle": "alice.example.com", "protocol": "atproto", "anchor": "sha256:..."}'

# Lookup
curl http://localhost:5000/identity/handle/atproto/alice.example.com

# Reverse lookup (all handles for an anchor)
curl http://localhost:5000/identity/anchor/sha256:.../handles

# Delete
curl -X DELETE http://localhost:5000/identity/handle/atproto/alice.example.com
```

A background task re-verifies handles at `KAPPA_HANDLE_VERIFY_INTERVAL_SECS`
(default 3600) via DNS TXT, WebFinger, or HTTP well-known. Handles that
fail verification transition to `Unverified` but are not deleted, allowing
retry on the next cycle.

### Absence proofs

```bash
curl "http://localhost:5000/v2/{ns}/_identity/absence?subject=sha256:...&facet=key/signing"
```

Mathematical proof that a specific asserter has NOT made an assertion
about a subject on a facet at a specific epoch. Transferable and
offline-verifiable.

### Delegation

Delegation edges grant scoped, time-bounded authority:

```bash
curl -X PUT \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "sha256:delegator...",
    "target": "sha256:delegate...",
    "relation": "delegation",
    "metadata": {
      "namespaces": ["myorg/myrepo"],
      "operations": ["read", "write"],
      "expires_at_ms": 1735689600000,
      "delegation_depth": 1
    }
  }' \
  "http://127.0.0.1:5000/v2/example/edges/"
```

Narrowing invariant: redelegation may only narrow scope, shorten TTL,
and decrement depth. Depth is enforced at creation and evaluation.
Revoking a delegation cascades to all downstream delegates.

---

## Federation

### Epoch probes

Configure federation peers:

```bash
KAPPA_FEDERATION_PEERS=http://peer1:5000,http://peer2:5000 \
KAPPA_PROBE_INTERVAL_SECS=60 \
./scripts/service.sh --start
```

The background probe task sends `GET /v2/_root?signed=true` to each peer,
verifies the Ed25519 signature over the epoch fingerprint, and detects
equivocation (same epoch number, different root hash).

Trust position updates: `Unprobed` -> `Federated` (all probes pass) or
`Degraded` (any probe fails). One fault degrades. No averaging, no quorum.

### Set reconciliation

Peers compare namespace roots and transfer only the difference via RBSR
(range-based set reconciliation with XOR-monoid fingerprint trees).

---

## TLS

```bash
KAPPA_TLS_CERT=/path/to/cert.pem \
KAPPA_TLS_KEY=/path/to/key.pem \
./scripts/service.sh --start
```

ALPN negotiation for HTTP/2 and HTTP/1.1 via rustls.

### Mutual TLS

```bash
KAPPA_TLS_CERT=/path/to/cert.pem \
KAPPA_TLS_KEY=/path/to/key.pem \
KAPPA_TLS_CLIENT_CA=/path/to/client-ca.pem \
./scripts/service.sh --start
```

---

## Configuration reference

All configuration is via environment variables.

### Server

| Variable | Default | Description |
|---|---|---|
| `KAPPA_LISTEN_ADDR` | `127.0.0.1:5000` | TCP listen address |
| `KAPPA_STORE_ROOT` | `./data` | Data directory (blobs, database, keys) |
| `KAPPA_REQUEST_TIMEOUT_SECS` | `300` | Per-request timeout |
| `KAPPA_MAX_API_BODY_BYTES` | `4194304` | API body limit (4 MiB) |
| `KAPPA_PROXY_TRUSTED_HEADERS` | (unset) | Trusted proxy header name |
| `KAPPA_CORS_ALLOWED_ORIGINS` | `*` | CORS origins |

### Storage

| Variable | Default | Description |
|---|---|---|
| `KAPPA_MAX_BLOB_SIZE` | `268435456` | Maximum blob size (256 MiB) |
| `KAPPA_UPLOAD_TIMEOUT` | `3600` | Upload session timeout (seconds) |
| `KAPPA_MAX_TRANSACTIONS` | `64` | Maximum concurrent transactions |
| `KAPPA_MAX_STAGING_BYTES` | `268435456` | Global staging byte limit (256 MiB) |
| `KAPPA_SIGNING_ALGORITHM` | `ed25519` | Node signing key algorithm |
| `KAPPA_FSYNC` | `true` | fsync on blob write |
| `KAPPA_DISK_PRESSURE_THRESHOLD_MB` | `1024` | Reject writes below this free space |

### TLS

| Variable | Default | Description |
|---|---|---|
| `KAPPA_TLS_CERT` | (unset) | TLS certificate path |
| `KAPPA_TLS_KEY` | (unset) | TLS private key path |
| `KAPPA_TLS_CLIENT_CA` | (unset) | mTLS client CA path |

### Authentication

| Variable | Default | Description |
|---|---|---|
| `KAPPA_AUTH_TOKENS` | (unset) | Bearer tokens (`token=anchor,...` or `@filepath`) |
| `KAPPA_AUTH_REQUIRED` | `false` | Require authentication on all requests |
| `KAPPA_ROOT_TOKEN` | (unset) | Root token with `_root` delegation (`token=anchor`) |

### S3

| Variable | Default | Description |
|---|---|---|
| `KAPPA_S3_BASE_DOMAIN` | (unset) | Virtual-hosted-style domain |
| `KAPPA_LIFECYCLE_INTERVAL_SECS` | `86400` | Lifecycle evaluation interval |

### Nix

| Variable | Default | Description |
|---|---|---|
| `KAPPA_NIX_PRIORITY` | `30` | Binary cache priority |
| `KAPPA_NIX_TRUSTED_KEYS` | (unset) | Trusted keys (`name:base64pubkey,...`) |

### Identity and federation

| Variable | Default | Description |
|---|---|---|
| `KAPPA_PLC_DIRECTORY_URL` | `https://plc.directory` | PLC directory for DID resolution |
| `KAPPA_FEDERATION_PEERS` | (unset) | Peer URLs (comma-separated) |
| `KAPPA_PROBE_INTERVAL_SECS` | `60` | Federation probe interval |
| `KAPPA_HANDLE_VERIFY_INTERVAL_SECS` | `3600` | Handle re-verification interval |
| `KAPPA_HANDLE_TTL_MS` | `86400000` | Handle verification TTL (24h) |
| `KAPPA_PDS_HOSTNAME` | (unset) | AT Protocol PDS hostname for requestCrawl |

### Rate limiting

| Variable | Default | Description |
|---|---|---|
| `KAPPA_RATELIMIT_READ_PERIOD_MS` | `0` | Read rate limit period (0 = disabled) |
| `KAPPA_RATELIMIT_READ_BURST` | `1000` | Read rate limit burst |
| `KAPPA_RATELIMIT_WRITE_PERIOD_MS` | `0` | Write rate limit period |
| `KAPPA_RATELIMIT_WRITE_BURST` | `200` | Write rate limit burst |
| `KAPPA_RATELIMIT_ADMIN_PERIOD_MS` | `0` | Admin rate limit period |
| `KAPPA_RATELIMIT_ADMIN_BURST` | `50` | Admin rate limit burst |

---

## Building

Requires Rust 1.95+. The Nix flake provides a hermetic toolchain.

```bash
nix develop
cargo build --release
```

### Quality gates

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

All three must pass with zero warnings before any commit.

### Feature flags

| Flag | Default | Description |
|---|---|---|
| `oci` | yes | OCI distribution-spec endpoints |
| `identity-http` | yes | Identity HTTP endpoints |
| `distribution` | yes | kappa-distribution extension endpoints |
| `git` | yes | Git smart HTTP protocol |
| `s3` | yes | S3-compatible API |
| `nix` | yes | Nix binary cache protocol |
| `atproto` | **no** | AT Protocol XRPC endpoints |
| `veilid` | no | Veilid transport for federation |

Enable AT Protocol:

```bash
cargo build --release --features atproto
```

Enable all features:

```bash
cargo build --release --features "oci,identity-http,distribution,git,s3,nix,atproto"
```

---

## Testing

```bash
# Unit and integration tests
cargo test --workspace

# Include AT Protocol tests
cargo test --workspace --features atproto

# kappa-distribution conformance (187 tests)
./scripts/conformance.sh

# OCI distribution-spec conformance (1032 tests)
./scripts/oci-conformance.sh

# Protocol end-to-end tests
./scripts/git-e2e.sh      # git push/clone/fetch roundtrip
./scripts/s3-e2e.sh       # S3 bucket ops + object CRUD
./scripts/nix-e2e.sh      # nix copy + narinfo/NAR verification
```

---

## Crate structure

```
kappa-core              substrate: store trait, types, crypto, identity primitives
kappa-store-redb        production store: redb tables, filesystem blobs, encryption
kappa-server            HTTP server, middleware, route handlers, resolvers
kappa-module-oci        OCI distribution-spec handlers
kappa-module-distribution  kappa-distribution extension handlers
kappa-module-git        Git smart HTTP: pack ingest/gen, refs, hooks, LFS
kappa-module-s3         S3 ListObjectsV2, XML encoding
kappa-module-nix        Nix narinfo codec, NAR verification, key format
kappa-module-identity   identity HTTP endpoints, handle registry
kappa-module-atproto    MST, CAR, TID, CID, commits, XRPC, sessions, firehose
kappa-akd               append-only key directory for absence proofs
kappa-conformance       conformance tests, compile-fail tests
kappa-reconcile         RBSR set reconciliation
kappa-transport-veilid  Veilid transport for federation
kappa-types             shared type re-exports
```

Protocol modules are pure format codecs with no store dependency (except
kappa-module-identity and kappa-module-distribution which use store types
directly). The server bridges codecs to the substrate.

---

## Documentation

- **Design reference:** [`docs/kappa-registry.md`](docs/kappa-registry.md)
  covers content addressing, the substrate primitives, namespaces, the full
  identity model, trust, authorization, federation, and all six protocols
  in detail.

- **API reference:** interactive documentation at `/docs` and OpenAPI 3.1
  spec at `/openapi.json` when the server is running.

- **Identity:** `curl http://localhost:5000/identity/whoami` returns the
  node anchor, algorithm, trust position, and self-assertions.

---

## License

MIT OR Apache-2.0
