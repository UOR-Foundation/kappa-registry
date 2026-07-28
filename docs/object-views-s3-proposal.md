# Proposal: shared object views and S3 compatibility

Status: draft proposal

## Summary

Add a protocol-independent object layer above the Kappa content store. Kappa
`/v2/` and S3 become views over the same namespace data, while the content
itself remains addressed by immutable Kappa labels.

This proposal deliberately does not make `s3/` part of a namespace name. An
S3 bucket is a durable binding to a logical namespace.

## Goals

- Preserve Kappa content addressing and deduplication.
- Allow Kappa and S3 to resolve the same underlying content.
- Support S3 keys, metadata, versions, delete markers, and object tags.
- Make large-object reads and writes streamable.
- Provide reusable view capabilities for future interfaces such as FUSE.
- Keep the existing Kappa API behavior stable during migration.

## Non-goals for the first implementation

- Full implementation of every S3 management or analytics feature.
- S3 Control, S3 Tables, S3 Vectors, Outposts, or access-point services.
- Distributed storage or horizontal deployment.
- Replacing `KappaStore` in one change.

## Canonical model

The content plane remains global and immutable:

```text
Kappa label -> bytes
```

Named objects are mutable references in a namespace:

```text
(namespace, key) -> current version -> Kappa label
```

Versioned history is retained separately:

```text
(namespace, key, version_id)
    -> Kappa label + metadata + tags + timestamps + delete-marker state
```

Overwriting a Kappa-style pointer does not overwrite content. Repeated writes
of identical bytes still receive distinct S3 version IDs when versioning is
enabled.

S3 keys should not automatically become Kappa tags in every case. They should
be typed object records so that S3 listing, metadata, and authorization cannot
accidentally expose unrelated Kappa tags. A compatibility mapping may use the
existing mutable tag machinery for simple current pointers, but S3 membership
and metadata remain explicit.

## Namespace and bucket bindings

Add a durable bucket catalog:

```text
bucket name
logical namespace
owner
region
versioning state
public/private policy
bucket configuration
```

The default binding is `bucket name -> namespace with the same name`, but the
mapping is persisted and may be overridden. Visibility is a policy on the
bucket binding, not encoded in the namespace name.

Buckets are private by default. Anonymous `GET`/`HEAD` requires explicit
public-read policy; anonymous writes are never enabled by default.

## View capabilities

Avoid one protocol-shaped mega-trait. Define capability-oriented interfaces:

```rust
trait ObjectReadableView {
    fn stat(...);
    fn read(...);
    fn list(...);
}

trait ObjectWritableView: ObjectReadableView {
    fn put(...);
    fn delete(...);
    fn copy(...);
}

trait VersionedView { ... }
trait MultipartView { ... }
```

The existing `KappaStore` remains a low-level persistence interface. A new
object repository should own namespace/key/version resolution and use the
content store for Kappa-addressed bytes.

## Namespace roots and garbage collection

Namespace roots must include canonical typed leaves for both existing Kappa
records and view objects, for example:

```text
kappa-tag:<name>
s3-object:<key>:<version>
```

Metadata and object-tag changes therefore change the namespace root. Garbage
collection must retain every Kappa label referenced by a current or historical
object version, as well as existing Kappa reachability roots.

## S3 implementation phases

1. Add canonical object/version types and durable index records.
2. Add streaming content reads and writes.
3. Add bucket catalog and namespace bindings.
4. Add S3 routing for path-style and virtual-hosted-style requests.
5. Implement `HeadBucket`, `PutObject`, `GetObject`, `HeadObject`,
   `DeleteObject`, `ListObjectsV2`, and `CopyObject`.
6. Add XML errors, S3 headers, checksums, ranges, and conditional requests.
7. Add SigV4 header and presigned URL authentication.
8. Add durable multipart uploads.
9. Add S3 versioning, delete markers, and `ListObjectVersions`.
10. Add bucket/object configuration subresources and advanced operations as
    separate compatibility issues.

## Compatibility acceptance criteria

- Existing Kappa integration tests remain green.
- A Kappa client and an S3 client can read the same content.
- Overwriting an object updates its pointer without deleting the old blob.
- Two keys can reference identical bytes with different metadata.
- S3 metadata and version records participate in namespace roots.
- GC preserves all referenced current and historical versions.
- Private buckets require SigV4; public buckets permit only configured
  anonymous operations.
- Basic operations work with AWS CLI, boto3, the AWS Rust SDK, MinIO, and
  rclone.

## Follow-up

FUSE is a separate view implementation over the same object repository. Its
design is documented in `docs/fuse-view-proposal.md` and should depend on the
capability interfaces established here.
