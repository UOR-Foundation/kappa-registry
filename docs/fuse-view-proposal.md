# Follow-up proposal: FUSE view

Status: draft follow-up to `object-views-s3-proposal.md`

## Summary

Implement a feature-gated FUSE adapter over the shared object repository. FUSE
will provide filesystem-shaped access to the same namespace data exposed by
the Kappa and S3 views.

FUSE is not simply another S3 endpoint. It needs filesystem capabilities such
as open handles, offsets, directories, close-time commit, rename, and unlink.
Those capabilities should remain separate from S3-specific multipart and
versioning interfaces.

## Proposed mapping

- Mount one logical namespace at a time.
- Map object keys to file paths.
- Synthesize directories from `/`-delimited keys.
- Map object metadata to extended attributes where the host supports them.
- Resolve reads through the same Kappa label and object-version records used by
  S3.

Example:

```text
FUSE path: /photos/2026/image.jpg
S3 key:    photos/2026/image.jpg
Kappa:     sha256:<content digest>
```

## Capability interface

Add a filesystem-specific capability rather than expanding the object view
trait with POSIX behavior:

```rust
trait FilesystemView {
    fn getattr(...);
    fn readdir(...);
    fn open(...);
    fn read(...);
    fn write(...);
    fn flush(...);
    fn release(...);
    fn unlink(...);
    fn rename(...);
}
```

The repository remains responsible for durable object identity, metadata,
versioning, and atomic publication. The FUSE adapter translates filesystem
operations into repository operations.

## Initial scope

The first FUSE implementation should support:

- `stat` and directory listing.
- Open and read.
- Read-only mounting or atomic write-on-close.
- Unlink as removal of the current namespace pointer.
- Cross-view reads verified against Kappa and S3.

Writes must never mutate Kappa content in place. A write stages a new object,
computes its Kappa label, and atomically replaces the current pointer.

## Deferred filesystem behavior

- Random in-place writes.
- POSIX permissions as authoritative access policy.
- Hard links and file locking.
- Cross-namespace rename.
- Native presentation of every historical object version.
- Full xattr round-tripping on platforms without reliable xattr support.

## Acceptance criteria

- FUSE reads resolve the same bytes as Kappa and S3.
- A committed FUSE write is visible through S3 and Kappa.
- A FUSE unlink changes namespace reachability without immediately deleting
  shared content.
- Namespace roots and GC account for FUSE-created records.
- The adapter is feature-gated and does not add a mandatory platform-specific
  dependency to the default build.
