//! Operation-owned execution contract.
//!
//! An execution owns one private, backend-local view of a namespace. Its
//! writes become visible only through consuming publication, which installs
//! state changes, their mutation ledger, the operation receipt, and the signed
//! epoch together. Dropping or aborting an execution discards all of it.
//!
//! Content enters in two steps. [`ContentPreparation::prepare_content`] runs
//! outside any writer: it streams the bytes, verifies or computes their
//! identity under every mandatory axis, and produces a [`PreparedContent`]
//! whose external representation, if any, is already durable.
//! [`ExecutionWrites::content_install`] then records that representation
//! inside the execution, so the writer is held only for the index row and
//! the ledger mutation, never for byte transfer. A prepared value that is
//! never installed releases its storage when dropped. An inline
//! representation is ready for installation but durable only with the
//! epoch's commit.
//!
//! The view traits are deliberately not `Sync`: a backend may confine an
//! execution to the blocking worker that created it. Publication outcomes
//! whose durability is unknown are reported through
//! `StoreError::PublicationRecoveryRequired` and
//! `StoreError::PublicationIndeterminate`; callers must route those to service
//! recovery rather than retrying through the same backend handle. A
//! publication known not to be published whose signing coordinate is
//! consumed is `StoreError::PublicationRetained`: the backend keeps it, its
//! namespace refuses other publications, and
//! [`ExecutionStore::resolve_publication`] advances it.

use kappa_types::{
    Axis, ClockMs, EdgeInput, EpochRoot, IngestResult, Kappa, NamespaceRef, OperationReceipt, Page,
    PageRequest, ProtocolId, RetainedPublication, StoreError, TagEntry, TagUpdate, VerifiedContent,
    WorkMeter,
    identity::{
        DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord,
        PrekeyBinding, Revocation, RevocationCommitment, Succession, TrustPosition, Watermark,
    },
};

use crate::time::Clock;
use crate::traits::NamespaceInfo;

/// Maps a keyed lookup's `NotFound` to `Ok(None)`.
///
/// Absence is a value, not a failure: it leaves the execution usable, while
/// every other error still latches it. Backends apply this one rule to their
/// keyed reads.
pub fn absent<T>(result: Result<T, StoreError>) -> Result<Option<T>, StoreError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(StoreError::NotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// How the identity of prepared content is established.
#[derive(Clone, Debug)]
pub enum ContentIdentity {
    /// The stream must hash to this identity under its axis.
    Verified(Kappa),
    /// The identity is computed under `axis` from the stream.
    Computed(Axis),
    /// The stream is `algorithm`-compressed bytes of content whose identity
    /// and decompressed size are given; the backend proves the
    /// decompression before admitting it and represents the compressed
    /// bytes.
    Compressed {
        identity: Kappa,
        algorithm: String,
        uncompressed_size: u64,
    },
}

/// Bounds the preparation of one piece of content.
#[derive(Clone, Copy, Debug)]
pub struct PreparationBounds {
    /// Largest stored size admitted.
    pub maximum: u64,
    /// Monotonic deadline by which the representation must be ready and,
    /// for external content, durable.
    pub deadline: std::time::Instant,
}

/// Content prepared outside the writer, ready for `content_install`.
///
/// The primary identity carries the representation; every other mandatory
/// axis is installed as an alias of it. Dropping an uninstalled value
/// releases whatever storage the preparation holds.
pub trait PreparedContent: Send {
    /// Identity under the requested axis.
    fn identity(&self) -> &Kappa;
    /// Identities under the store's other mandatory axes.
    fn aliases(&self) -> &[Kappa];
    /// Logical size of the content.
    fn total_size(&self) -> u64;
    /// Protocol entity tag of an assembled upload (S3 composite `ETag`),
    /// when the preparation produced one.
    fn etag(&self) -> Option<&str>;
    /// Backend downcast point.
    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any + Send>;
}

/// Verified evidence that the ordered `components` concatenate to the
/// bytes of `identity`.
///
/// `identity` is under its own axis and `aliases` under the store's other
/// mandatory axes; the evidence is taken for the frozen generation
/// `generation` of resource `incarnation` in `namespace`.
///
/// Only `resource::prepare_composition` constructs one, after streaming
/// every selected member through the store, verifying each against its
/// committed identity and length, and hashing the whole under every axis.
/// Protocol code cannot assemble one from digests it computed itself, so
/// `content_compose` never installs an identity nobody verified.
#[derive(Clone, Debug)]
pub struct CompositionEvidence {
    namespace_id: Vec<u8>,
    incarnation: Vec<u8>,
    generation: Kappa,
    identity: Kappa,
    aliases: Vec<Kappa>,
    components: Vec<(Kappa, u64)>,
    total_bytes: u64,
}

impl CompositionEvidence {
    pub(crate) const fn new(
        namespace_id: Vec<u8>,
        incarnation: Vec<u8>,
        generation: Kappa,
        identity: Kappa,
        aliases: Vec<Kappa>,
        components: Vec<(Kappa, u64)>,
        total_bytes: u64,
    ) -> Self {
        Self {
            namespace_id,
            incarnation,
            generation,
            identity,
            aliases,
            components,
            total_bytes,
        }
    }

    pub fn namespace_id(&self) -> &[u8] {
        &self.namespace_id
    }
    pub fn incarnation(&self) -> &[u8] {
        &self.incarnation
    }
    pub const fn generation(&self) -> &Kappa {
        &self.generation
    }
    pub const fn identity(&self) -> &Kappa {
        &self.identity
    }
    pub fn aliases(&self) -> &[Kappa] {
        &self.aliases
    }
    pub fn components(&self) -> &[(Kappa, u64)] {
        &self.components
    }
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

/// Outcome of [`ExecutionWrites::content_retire`].
///
/// Retirement releases the execution namespace's admission of an identity
/// and nothing else: other namespaces' admissions of the same identity are
/// unaffected, and physical reclamation of the bytes is a separate decision
/// that checks every remaining admission, retained reader and preparation.
///
/// Only failures latch the execution: a retained or absent identity leaves
/// it usable, so one
/// candidate that gained a reference does not cancel unrelated retirements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retirement {
    /// This execution removed its namespace's admission of the identity.
    Retired,
    /// A reference of this namespace (tag, edge, pin, epoch head, or
    /// another representation) still names the identity; nothing changed.
    Retained,
    /// This namespace has no current admission of the identity in the
    /// execution's view; nothing changed. It says nothing about whether the
    /// identity was ever admitted here or is admitted elsewhere.
    Absent,
}

/// Preparation of content before an execution installs it. Holds no
/// writer; runs on a blocking worker.
pub trait ContentPreparation: Send + Sync {
    fn prepare_content(
        &self,
        identity: ContentIdentity,
        reader: &mut dyn std::io::Read,
        bounds: PreparationBounds,
    ) -> Result<Box<dyn PreparedContent>, StoreError>;
}

/// Reads observed through an execution, including its own private writes.
/// Keyed reads report absence as `None`; only failures latch the execution.
pub trait ExecutionReads {
    fn namespace(&self) -> &NamespaceRef;
    fn now(&self) -> ClockMs;
    /// Resolves symbolic references. A dangling reference is absent; a
    /// reference cycle is a failure.
    fn tag_get(&self, name: &str) -> Result<Option<TagEntry>, StoreError>;
    fn tag_get_raw(&self, name: &str) -> Result<Option<TagEntry>, StoreError>;
    fn namespace_info(&self) -> Result<Option<NamespaceInfo>, StoreError>;
    fn sequence_current(&self, name: &str) -> Result<u64, StoreError>;
    fn namespace_get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    fn blob_meta_get(&self, identity: &Kappa, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    /// Verified content, bounded before allocation. Exceeding `maximum` or
    /// failing verification is a failure; a missing identity is absent.
    fn blob_get_verified(
        &self,
        identity: &Kappa,
        maximum: u64,
    ) -> Result<Option<Vec<u8>>, StoreError>;
    fn handle_get(
        &self,
        protocol: &ProtocolId,
        handle: &str,
    ) -> Result<Option<HandleRecord>, StoreError>;
    fn handle_list_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<HandleRecord>, StoreError>;
    /// Edges of the execution's namespace matching `query`, including the
    /// execution's own puts and deletes, paged like `EdgeStore::edge_query`.
    fn edge_query(
        &self,
        query: &kappa_types::EdgeQuery,
        page: &PageRequest,
    ) -> Result<Page<kappa_types::Edge>, StoreError>;
    /// The session under `token`, live at the execution's time:
    /// `(anchor, metadata)`, or absent when there is no such session or it
    /// has expired.
    ///
    /// The read is recorded as an authorization dependency of
    /// the execution: publication is refused with `Conflict` when the
    /// session row observed here (present or absent) has changed by the
    /// time the execution publishes, so an execution authorized by a
    /// session a concurrent publication revoked does not publish under
    /// that authority.
    fn session_get(&self, token: &str) -> Result<Option<(Kappa, Vec<u8>)>, StoreError>;
    /// The credential under `credential_id` as the execution observes it:
    /// `(anchor, current secret hash, grace)` with the grace filtered by
    /// the execution's time, or absent.
    ///
    /// Recorded as an authorization
    /// dependency exactly like `session_get`: a credential created,
    /// rotated or deleted by a concurrent publication after this read
    /// refuses the execution with `Conflict`, which is what makes a
    /// create-if-absent registration or a rotation decided here
    /// authoritative.
    fn credential_get(
        &self,
        credential_id: &str,
    ) -> Result<Option<crate::traits::identity::CredentialLookup>, StoreError>;
}

/// Mutations recorded into the execution's private ledger. Any failure
/// latches the execution; it can then only be aborted.
pub trait ExecutionWrites: ExecutionReads {
    fn tag_put(&mut self, name: &str, update: &TagUpdate) -> Result<(), StoreError>;
    fn tag_delete(&mut self, name: &str) -> Result<(), StoreError>;
    fn tag_batch_update(&mut self, updates: &[(String, TagUpdate)]) -> Result<(), StoreError>;
    fn edge_put(&mut self, input: &EdgeInput) -> Result<Kappa, StoreError>;
    fn edge_put_batch(&mut self, inputs: &[EdgeInput]) -> Result<Vec<Kappa>, StoreError>;
    fn edge_delete(&mut self, identity: &Kappa) -> Result<(), StoreError>;
    fn sequence_next(&mut self, name: &str) -> Result<u64, StoreError>;
    /// Create the execution's namespace under its display name and protocol
    /// scope. Alias admission runs under the execution's concurrency
    /// boundary, so a concurrent creator of the same alias conflicts.
    fn namespace_create(
        &mut self,
        owner: Option<&Kappa>,
        protocol: Option<&ProtocolId>,
    ) -> Result<(), StoreError>;
    fn namespace_transfer(&mut self, new_owner: &Kappa) -> Result<(), StoreError>;
    fn namespace_delete(&mut self) -> Result<(), StoreError>;
    /// Rename the execution namespace's alias within its protocol scope. The
    /// execution's namespace reference carries the new name afterwards.
    fn namespace_rename(&mut self, new_name: &str) -> Result<(), StoreError>;
    fn namespace_add_alias(
        &mut self,
        alias: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<(), StoreError>;
    fn namespace_put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError>;
    fn namespace_delete_meta(&mut self, key: &str) -> Result<(), StoreError>;
    fn binding_put(&mut self, binding: &IdentityBinding) -> Result<(), StoreError>;
    fn binding_delete(&mut self, source: &str, target: &Kappa) -> Result<(), StoreError>;
    fn assertion_put(&mut self, assertion: &IdentityAssertion) -> Result<Kappa, StoreError>;
    fn revocation_put(&mut self, revocation: &Revocation) -> Result<Kappa, StoreError>;
    fn watermark_put(&mut self, watermark: &Watermark) -> Result<Kappa, StoreError>;
    fn handle_put(&mut self, record: &HandleRecord) -> Result<(), StoreError>;
    /// False when the stored record no longer equals `expected`.
    fn handle_attest(&mut self, expected: &HandleRecord) -> Result<bool, StoreError>;
    fn handle_delete(&mut self, protocol: &ProtocolId, handle: &str) -> Result<(), StoreError>;
    fn device_binding_put(&mut self, binding: &DeviceBinding) -> Result<(), StoreError>;
    fn device_binding_revoke(
        &mut self,
        anchor: &Kappa,
        device_key: &[u8],
    ) -> Result<(), StoreError>;
    fn prekey_binding_put(&mut self, binding: &PrekeyBinding) -> Result<(), StoreError>;
    fn locator_put(&mut self, record: &LocatorRecord) -> Result<(), StoreError>;
    fn revocation_commitment_put(
        &mut self,
        commitment: &RevocationCommitment,
    ) -> Result<(), StoreError>;
    /// Publish a dual-signed succession record, index its successor, and
    /// commit its content identity to the ledger. Republishing the identical
    /// record is idempotent; a different successor for the same anchor
    /// conflicts.
    fn succession_put(
        &mut self,
        succession: &kappa_crypto::Verified<Succession>,
    ) -> Result<Kappa, StoreError>;
    /// Record a session under `token` for `anchor`, expiring at the encoded
    /// `expires_at_ms`. A session is an authorization grant: it is created,
    /// replaced and deleted only through a published execution, so the
    /// ledger carries every transition. Expiry is decided at read against
    /// the record; physical removal of expired rows is maintenance
    /// (`IdentityStore::session_evict`) and changes no authorization.
    fn session_put(
        &mut self,
        token: &str,
        anchor: &Kappa,
        expires_at_ms: i64,
        metadata: &[u8],
    ) -> Result<(), StoreError>;
    /// Delete the session under `token`. An absent token is a no-op.
    fn session_delete(&mut self, token: &str) -> Result<(), StoreError>;
    /// Record a credential for `anchor` under `credential_id`, with no
    /// rotation grace. The secret hash is stored as given.
    fn credential_put(
        &mut self,
        credential_id: &str,
        anchor: &Kappa,
        secret_hash: &[u8],
    ) -> Result<(), StoreError>;
    /// Rotate the credential's secret, keeping the previous one valid for
    /// `grace_period_ms` of physical time after the execution's time. The
    /// credential must be owned by `expected_owner`; a deadline that
    /// overflows is refused.
    fn credential_rotate(
        &mut self,
        credential_id: &str,
        expected_owner: &Kappa,
        new_secret_hash: &[u8],
        grace_period_ms: u64,
    ) -> Result<(), StoreError>;
    /// Delete the credential and its grace. An absent credential is a
    /// no-op.
    fn credential_delete(&mut self, credential_id: &str) -> Result<(), StoreError>;
    /// Set the node's trust position.
    fn trust_position_put(&mut self, position: &TrustPosition) -> Result<(), StoreError>;
    /// Install verified bytes the execution already holds (records it
    /// produces). Content from a request is prepared outside the writer
    /// and installed with `content_install`. Returns whether the identity
    /// was new.
    fn blob_put(&mut self, content: &VerifiedContent) -> Result<bool, StoreError>;
    fn blob_meta_put(
        &mut self,
        identity: &Kappa,
        key: &str,
        value: &[u8],
    ) -> Result<(), StoreError>;
    fn blob_meta_delete(&mut self, identity: &Kappa, key: &str) -> Result<(), StoreError>;
    /// Install prepared content and its aliases. An identity that already
    /// has a committed representation keeps it and the prepared storage is
    /// released. The result names the primary identity, whether it was
    /// new, and the aliases.
    fn content_install(
        &mut self,
        prepared: Box<dyn PreparedContent>,
    ) -> Result<IngestResult, StoreError>;
    /// Retire the representation of `identity` inside this execution, so
    /// the retirement commits with its epoch. The check that no committed
    /// reference (tag, edge, pin, epoch head, representation) names the
    /// identity runs here, under the writer, so no reference can be
    /// acquired between the check and the retirement. A retained or absent
    /// identity is reported without latching. The physical storage is
    /// reclaimed after the execution publishes, subject to reader and
    /// preparation protection.
    fn content_retire(&mut self, identity: &Kappa) -> Result<Retirement, StoreError>;
    /// Install the composite `evidence` describes: its identity over its
    /// ordered components, whose committed representations must exist
    /// with the evidenced lengths, and its aliases. The backend installs
    /// representation metadata selecting the components (manifest nodes
    /// when the membership exceeds one descriptor); it never assembles the
    /// payload. The components become retained by the composite.
    fn content_compose(
        &mut self,
        evidence: &CompositionEvidence,
    ) -> Result<IngestResult, StoreError>;
}

/// Committed publication of one execution.
#[derive(Debug, Clone)]
pub struct Published {
    pub epoch_number: u64,
    pub root: Kappa,
}

/// What [`ExecutionStore::resolve_publication`] found for a namespace.
#[derive(Debug)]
pub enum PublicationResolution {
    /// The namespace retains no publication.
    Clear,
    /// The retained publication was published; its signed root is the
    /// namespace's head.
    Published(Published),
    /// The publication remains retained: resumable, when the attempt was
    /// refused for lack of allowance or for an authorization or authority
    /// that may still be granted, or terminal.
    Retained(Box<RetainedPublication>),
}

/// Lifecycle owner. Consuming methods make publication and abort terminal.
pub trait Execution: ExecutionWrites {
    /// Bound publication by a monotonic deadline. A blocking worker cannot
    /// be cancelled by its caller's timeout; publishing after the deadline
    /// fails with `StoreError::DeadlineExceeded` and publishes nothing.
    fn set_deadline(&mut self, deadline: std::time::Instant);
    /// Publish an execution that carries no operation identity.
    fn publish(self: Box<Self>) -> Result<Published, StoreError>;
    /// Publish an operation execution together with its durable result.
    fn publish_result(self: Box<Self>, result: Vec<u8>) -> Result<Published, StoreError>;
    /// Discard every private write and release backend ownership.
    fn abort(self: Box<Self>) -> Result<(), StoreError>;
}

/// Outcome of admitting an operation identity.
pub enum OperationAdmission<'a> {
    /// No committed outcome exists; the caller owns a fresh execution.
    Execute(Box<dyn Execution + 'a>),
    /// The operation already committed; its authenticated result is returned
    /// without executing again.
    Replay {
        epoch: Box<EpochRoot>,
        receipt: OperationReceipt,
    },
}

/// Resolve a namespace, creating it when it does not exist.
///
/// Creation publishes in its own execution. A namespace created
/// concurrently under the same alias is resolved instead, so callers
/// converge on one namespace. The namespace identity is generated from one issued time; the creating
/// execution issues its own under the writer.
pub fn namespace_ensure<S: crate::traits::KappaStore + ?Sized>(
    store: &S,
    name: &str,
    owner: Option<&Kappa>,
    protocol: Option<&ProtocolId>,
    clock: &dyn Clock,
) -> Result<NamespaceRef, StoreError> {
    match store.namespace_resolve(name, protocol) {
        Err(StoreError::NotFound(_)) => {}
        resolved => return resolved,
    }
    let generated = NamespaceRef::generate(name, clock.now()?)?;
    let namespace = match protocol {
        Some(protocol) => generated.with_protocol(protocol.clone()),
        None => generated,
    };
    let mut execution = store.begin_execution(&namespace, clock)?;
    match execution.namespace_create(owner, protocol) {
        Ok(()) => {
            execution.publish()?;
            Ok(namespace)
        }
        Err(StoreError::Conflict(_) | StoreError::AlreadyExists(_)) => {
            execution.abort()?;
            store.namespace_resolve(name, protocol)
        }
        Err(error) => Err(error),
    }
}

/// Run `write` in one execution against `namespace`: publish when it reports
/// a change, abort otherwise, so a converged write publishes no epoch.
///
/// The execution holds the namespace's writer until this returns; call on
/// a blocking worker. Its time is issued from `clock` under that writer.
pub fn publish_if_changed<S: ExecutionStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    clock: &dyn Clock,
    write: impl FnOnce(&mut dyn Execution) -> Result<bool, StoreError>,
) -> Result<Option<Published>, StoreError> {
    let mut execution = store.begin_execution(namespace, clock)?;
    if write(&mut *execution)? {
        execution.publish().map(Some)
    } else {
        execution.abort()?;
        Ok(None)
    }
}

/// Admission of operation-owned executions. The only mutation entry point
/// that publishes authenticated history.
pub trait ExecutionStore: ContentPreparation + Send + Sync {
    /// Authenticated committed outcome for an operation, if any.
    fn resolve_operation(
        &self,
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        request: &Kappa,
    ) -> Result<Option<(EpochRoot, OperationReceipt)>, StoreError>;

    /// Admit an operation. Committed outcomes are resolved before a writer is
    /// acquired and rechecked under the execution's concurrency boundary. An
    /// executing operation issues its time from `clock` under the writer.
    fn begin_operation(
        &self,
        namespace: &NamespaceRef,
        identity: [u8; 32],
        request: Kappa,
        clock: &dyn Clock,
    ) -> Result<OperationAdmission<'_>, StoreError>;

    /// Open an execution without operation identity, for internal publishers
    /// such as bootstrap and maintenance tasks. Its time is issued from
    /// `clock` after the writer is acquired.
    fn begin_execution(
        &self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
    ) -> Result<Box<dyn Execution + '_>, StoreError>;

    /// Advance the publication `namespace` retains after its signing
    /// coordinate was consumed, from its recorded progress.
    ///
    /// Under the namespace's writer and the protection of the authority and
    /// every authorization row the publication depends on, the backend
    /// reads the current time from `clock` and checks the namespace
    /// instance, the predecessor, the authority, every recorded dependency
    /// and every temporal condition the authorization relied on, before any
    /// work. Each unit of work is admitted against `meter`, the fresh
    /// allowance of this call, before it starts; what earlier attempts
    /// consumed stays recorded with the publication. The signer is never
    /// invoked again for a coordinate it was invoked for, and the retained
    /// signed root is published unchanged.
    fn resolve_publication(
        &self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
        meter: &mut WorkMeter,
    ) -> Result<PublicationResolution, StoreError>;
}
