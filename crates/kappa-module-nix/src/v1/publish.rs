//! Narinfo admission and publication.
//!
//! A narinfo is parsed, checked against its URL, and every signature made
//! by a trusted key is verified before anything is written. Only a
//! `ValidNarinfo` can be written, so a rejected narinfo publishes nothing.
//! Its content, tag, NAR reverse index, edges, and signature metadata
//! publish in one execution of `_nix`. Signing-key bindings publish
//! afterwards, each in its signer's own namespace.

use kappa_handler::{HandlerError, Outcome, ResolvedIdentity};
use kappa_store::axis::Axis;
use kappa_store::clock::ClockMs;
use kappa_store::edge::{BuiltinRelation, EdgeInput, EdgeRelation, SemanticRelation, semantic};
use kappa_store::identity::{BindingMethod, IdentityBinding, TrustLevel};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::tag::TagUpdate;
use kappa_store::time::Clock;
use kappa_store::{Execution, KappaStore, Published, StoreError, absent, namespace_ensure};

use crate::narinfo::NarInfo;

/// Upper bound on a narinfo request body.
pub const MAX_NARINFO_BYTES: usize = 64 * 1024;

/// Tag naming the narinfo of a store path hash.
pub fn narinfo_tag(store_hash: &str) -> String {
    format!("narinfo:{store_hash}")
}

/// Tag naming the NAR at a cache path such as `abc.nar.zst`.
pub fn nar_tag(nar_path: &str) -> String {
    format!("nar:{nar_path}")
}

/// Namespace metadata key mapping a NAR path to the narinfo tag that names
/// it, read when the NAR arrives after its narinfo.
pub fn nar_ref_key(nar_path: &str) -> String {
    format!("_nar_ref/{nar_path}")
}

fn nix_asserter() -> Kappa {
    Kappa::sha256(b"_nix_protocol")
}

fn semantic_relation(iri: &str) -> EdgeRelation {
    EdgeRelation::Semantic(SemanticRelation(iri.into()))
}

/// Content identity of the uncompressed NAR a narinfo `NarHash` names.
/// Nix writes the digest in nixbase32; kappa labels carry it in hex.
pub fn nar_identity(nar_hash: &str) -> Result<Kappa, StoreError> {
    let hash = nix_derivation::NixHash::parse(nar_hash)
        .map_err(|error| StoreError::Rejected(format!("NarHash {nar_hash}: {error}")))?;
    Ok(Kappa::parse(&hash.to_nix_base16_string())?)
}

/// A narinfo that parsed and matches its URL, with syntactically valid
/// signatures that have not yet been checked against any key.
pub struct ParsedNarinfo {
    narinfo: NarInfo,
    bytes: Vec<u8>,
    nar: Kappa,
    signatures: Vec<(String, [u8; 64])>,
}

impl ParsedNarinfo {
    /// Parse `bytes` as the narinfo served at `url_hash`.
    ///
    /// # Errors
    ///
    /// `BadRequest` for non-UTF-8 or malformed narinfo, a store path whose
    /// hash differs from `url_hash`, a `NarHash` with no kappa axis, or a
    /// `Sig` line that is not `name:base64` of 64 bytes.
    pub fn parse(url_hash: &str, bytes: Vec<u8>) -> Result<Self, HandlerError> {
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            HandlerError::bad_request(format!("narinfo is not valid UTF-8: {error}"))
        })?;
        let narinfo = NarInfo::parse(text)
            .map_err(|error| HandlerError::bad_request(format!("narinfo parse error: {error}")))?;
        let store_hash = narinfo.store_path_hash();
        if url_hash != store_hash {
            return Err(HandlerError::bad_request(format!(
                "URL hash {url_hash} does not match store path hash {store_hash}"
            )));
        }
        let nar = nar_identity(&narinfo.nar_hash)
            .map_err(|error| HandlerError::bad_request(error.to_string()))?;
        let signatures = narinfo
            .signatures
            .iter()
            .map(|signature| {
                crate::sign::parse_signature(signature).map_err(|error| {
                    HandlerError::bad_request(format!(
                        "malformed narinfo signature {signature}: {error}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            narinfo,
            bytes,
            nar,
            signatures,
        })
    }

    /// Names of the keys that signed this narinfo, in `Sig` order.
    pub fn key_names(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::with_capacity(self.signatures.len());
        for (name, _) in &self.signatures {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }

    /// Verify every signature made by a key in `trusted` over the narinfo
    /// fingerprint. Signatures by other keys cannot be checked and are kept
    /// as unverified metadata, as a binary cache stores them for clients.
    ///
    /// # Errors
    ///
    /// `BadRequest` when a trusted key's signature does not verify;
    /// `Internal` when a trusted key itself is unusable.
    pub fn verify(
        self,
        trusted: &[(String, ResolvedIdentity)],
    ) -> Result<ValidNarinfo, HandlerError> {
        let fingerprint = self.narinfo.fingerprint();
        let mut signers: Vec<(String, ResolvedIdentity)> = Vec::new();
        for (name, signature) in &self.signatures {
            let Some((_, identity)) = trusted.iter().find(|(key, _)| key == name) else {
                continue;
            };
            let verifier = kappa_crypto::verifier_for(&identity.algorithm).map_err(|error| {
                HandlerError::internal(format!("nix signing key {name}: {error}"))
            })?;
            let valid = verifier
                .verify(&identity.public_key, fingerprint.as_bytes(), signature)
                .map_err(|error| {
                    HandlerError::internal(format!("nix signing key {name}: {error}"))
                })?;
            if !valid {
                return Err(HandlerError::bad_request(format!(
                    "narinfo signature by {name} does not verify"
                )));
            }
            if !signers.iter().any(|(key, _)| key == name) {
                signers.push((name.clone(), identity.clone()));
            }
        }
        Ok(ValidNarinfo {
            narinfo: self.narinfo,
            bytes: self.bytes,
            nar: self.nar,
            signers,
        })
    }
}

/// A narinfo admitted for publication: parsed, matched to its URL, and
/// carrying only signatures that verified or could not be checked.
pub struct ValidNarinfo {
    narinfo: NarInfo,
    bytes: Vec<u8>,
    nar: Kappa,
    signers: Vec<(String, ResolvedIdentity)>,
}

impl ValidNarinfo {
    pub const fn narinfo(&self) -> &NarInfo {
        &self.narinfo
    }

    /// The exact narinfo bytes received.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Identity of the uncompressed NAR this narinfo describes.
    pub const fn nar(&self) -> &Kappa {
        &self.nar
    }

    /// The NAR path relative to `nar/`.
    pub fn nar_path(&self) -> &str {
        self.narinfo
            .url
            .strip_prefix("nar/")
            .unwrap_or(&self.narinfo.url)
    }

    /// Trusted keys whose signatures verified.
    pub fn signers(&self) -> &[(String, ResolvedIdentity)] {
        &self.signers
    }

    pub fn tag(&self) -> String {
        narinfo_tag(&self.narinfo.store_path_hash())
    }
}

/// A NAR verified against its narinfo: the identity its tag pointed at and
/// the compressed form prepared under the uncompressed identity, for the
/// execution that publishes the narinfo to install.
pub struct VerifiedNar {
    pub tagged: Kappa,
    pub prepared: Option<Box<dyn kappa_store::PreparedContent>>,
}

/// Verify a NAR already stored under this narinfo's NAR path and prepare
/// it, outside any writer, as compressed content of its uncompressed
/// identity. `None` when the NAR has not arrived yet.
///
/// # Errors
///
/// `Rejected` when the stored NAR does not match the narinfo's `NarHash`
/// or references; store failures otherwise.
pub fn check_stored_nar(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    valid: &ValidNarinfo,
    deadline: std::time::Instant,
) -> Result<Option<VerifiedNar>, StoreError> {
    let Some(entry) = absent(store.tag_get(namespace, &nar_tag(valid.nar_path())))? else {
        return Ok(None);
    };
    let narinfo = &valid.narinfo;
    let nar_bytes = store.blob_get_in(namespace, &entry.kappa)?;
    crate::refs::decompress_and_verify(
        &nar_bytes,
        &narinfo.compression,
        &narinfo.nar_hash,
        &narinfo.references,
    )
    .map_err(|error| StoreError::Rejected(format!("NAR verification failed: {error}")))?;
    let prepared = store.prepare_content(
        kappa_store::ContentIdentity::Compressed {
            identity: valid.nar.clone(),
            algorithm: narinfo.compression.clone(),
            uncompressed_size: narinfo.nar_size,
        },
        &mut nar_bytes.as_slice(),
        kappa_store::PreparationBounds {
            maximum: nar_bytes.len() as u64,
            deadline,
        },
    )?;
    Ok(Some(VerifiedNar {
        tagged: entry.kappa,
        prepared: Some(prepared),
    }))
}

/// Edges from a narinfo: to the NAR it describes, to every store path it
/// references, and to its deriver.
fn narinfo_edges(valid: &ValidNarinfo, source: &Kappa, now: ClockMs) -> Vec<EdgeInput> {
    let asserter = nix_asserter();
    let edge = |target: Kappa, iri: &str| EdgeInput {
        source: source.clone(),
        target,
        relation: semantic_relation(iri),
        asserter: asserter.clone(),
        created_at_ms: now.as_i64(),
        metadata: None,
    };
    let narinfo = &valid.narinfo;
    let mut edges = vec![edge(valid.nar.clone(), semantic::COMPOSED_OF)];
    edges.extend(
        narinfo
            .references
            .iter()
            .filter(|basename| basename.len() > 32 && basename.as_bytes().get(32) == Some(&b'-'))
            .map(|basename| {
                let target = Kappa::sha256(format!("storepath:{}", &basename[..32]).as_bytes());
                edge(target, semantic::REFERENCES)
            }),
    );
    if let Some(deriver) = &narinfo.deriver {
        let target = Kappa::sha256(format!("deriver:{deriver}").as_bytes());
        edges.push(edge(target, semantic::DERIVED_FROM));
    }
    edges
}

/// Write a narinfo into `execution`: its content, tag, NAR reverse index,
/// edges, and signatures, and install the verified NAR's compressed form
/// under its uncompressed identity. `verified_nar` is what
/// `check_stored_nar` returned; the NAR tag must still point there.
///
/// Re-uploading the narinfo already published under its tag changes
/// nothing and is discarded.
///
/// # Errors
///
/// `Conflict` when the NAR tag changed after verification; store failures
/// otherwise.
pub fn write_narinfo(
    execution: &mut dyn Execution,
    valid: &ValidNarinfo,
    verified_nar: Option<&mut VerifiedNar>,
) -> Result<Outcome<Kappa>, HandlerError> {
    let nar_path = valid.nar_path();
    let current_nar = execution
        .tag_get(&nar_tag(nar_path))?
        .map(|entry| entry.kappa);
    if current_nar.as_ref() != verified_nar.as_ref().map(|nar| &nar.tagged) {
        return Err(HandlerError::Conflict {
            reason: format!("NAR {nar_path} changed during narinfo upload; retry"),
        });
    }
    let tag = valid.tag();
    let kappa = Kappa::sha256(&valid.bytes);
    if execution
        .tag_get_raw(&tag)?
        .is_some_and(|entry| entry.kappa == kappa && entry.symref.is_none())
    {
        return Ok(Outcome::Discard(kappa));
    }
    if let Some(prepared) = verified_nar.and_then(|nar| nar.prepared.take()) {
        execution.content_install(prepared)?;
    }
    // The narinfo is a record the execution holds in full; its bytes are
    // small and install inline.
    let content = kappa_store::VerifiedContent::compute(Axis::Sha256, &valid.bytes)?;
    execution.blob_put(&content)?;
    execution.tag_put(
        &tag,
        &TagUpdate::Set {
            kappa: kappa.clone(),
        },
    )?;
    execution.namespace_put_meta(&nar_ref_key(nar_path), tag.as_bytes())?;
    let edges = narinfo_edges(valid, &kappa, execution.now());
    execution.edge_put_batch(&edges)?;
    // Signatures are the cache's statement about its narinfo: namespace
    // metadata, published with it.
    for (index, signature) in valid.narinfo.signatures.iter().enumerate() {
        execution.namespace_put_meta(&signature_key(&kappa, index), signature.as_bytes())?;
    }
    Ok(Outcome::Publish(kappa))
}

/// Namespace metadata key of the `index`-th signature of narinfo `kappa`.
pub fn signature_key(kappa: &Kappa, index: usize) -> String {
    format!("_nix_sig/{kappa}/{index}")
}

/// Bind a verified signing key to its anchor and record its assertion of
/// the narinfo, in the anchor's namespace.
///
/// The binding is not part of the narinfo request's target (`_nix`): it
/// lives in the asserter's own namespace (D-8), a separate namespace that
/// must exist before its execution opens. `namespace_ensure` creates it in
/// its own epoch, converging with concurrent creators, and runs before
/// `begin_execution` so it never waits on a writer this call holds.
///
/// # Errors
///
/// Store failures; nothing from the failed execution is published.
pub fn bind_signer(
    store: &dyn KappaStore,
    key_name: &str,
    identity: &ResolvedIdentity,
    narinfo: &Kappa,
    clock: &dyn Clock,
) -> Result<(NamespaceRef, Published), StoreError> {
    let anchor = &identity.anchor;
    let namespace = namespace_ensure(store, &anchor.to_string(), Some(anchor), None, clock)?;
    let metadata = serde_json::to_vec(&serde_json::json!({ "nix_sig": key_name }))
        .map_err(|error| StoreError::Internal(format!("nix_sig metadata: {error}")))?;
    let mut execution = store.begin_execution(&namespace, clock)?;
    let now = execution.now();
    execution.binding_put(&IdentityBinding {
        source: key_name.to_string(),
        target: anchor.clone(),
        method: BindingMethod::SelfDeclared,
        trust_level: TrustLevel::Verified,
        verified_at_ms: Some(now.as_i64()),
        metadata: None,
    })?;
    execution.edge_put(&EdgeInput {
        source: anchor.clone(),
        target: narinfo.clone(),
        relation: EdgeRelation::Builtin(BuiltinRelation::Assertion),
        asserter: anchor.clone(),
        created_at_ms: now.as_i64(),
        metadata: Some(metadata),
    })?;
    let published = execution.publish()?;
    Ok((namespace, published))
}
