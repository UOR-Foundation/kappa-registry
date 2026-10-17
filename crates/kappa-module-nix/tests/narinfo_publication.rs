//! Narinfo admission and publication through operation-owned executions.

use kappa_crypto::Signer as _;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_handler::{HandlerError, Outcome, ResolvedIdentity, clock_at};
use kappa_module_nix::narinfo::NarInfo;
use kappa_module_nix::publish::{
    ParsedNarinfo, bind_signer, nar_ref_key, narinfo_tag, write_narinfo,
};
use kappa_module_nix::sign::format_signature;
use kappa_store::{BlobStore, EdgeStore, EpochStore, ExecutionStore, NamespaceStore, TagStore};
use kappa_store::{
    BuiltinRelation, ClockMs, Direction, EdgeQuery, EdgeRelation, Kappa, NamespaceRef, PageRequest,
    ProtocolId, SemanticRelation, StoreError, namespace_ensure, semantic,
};
use kappa_store_memory::{InMemoryStore, test_support};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const STORE_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REFERENCE: &str = "0z7sqj4pilbqyp45ix5b0mdgn9xlb024-libunistring-0.9.10";
const KEY_NAME: &str = "test-cache-1";

/// Timestamp at `physical_ms` with a zero logical counter.
const fn at(physical_ms: i64) -> ClockMs {
    ClockMs::from_raw(physical_ms << 16)
}

fn unsigned_narinfo() -> String {
    format!(
        "StorePath: /nix/store/{STORE_HASH}-hello\n\
         URL: nar/hello.nar.zst\n\
         Compression: zstd\n\
         NarHash: sha256:{}\n\
         NarSize: 100\n\
         References: {REFERENCE} {STORE_HASH}-hello\n\
         Deriver: 0n91syjwrhmng41f8d23ad0sl4a6ic4g-hello.drv\n",
        "0".repeat(52)
    )
}

/// Narinfo signed by `signer` over its fingerprint, or over `forged` when
/// that is nonempty.
fn signed_narinfo(
    signer: &Ed25519Signer,
    forged: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let unsigned = unsigned_narinfo();
    let fingerprint = NarInfo::parse(&unsigned)?.fingerprint();
    let message = if forged.is_empty() {
        fingerprint.as_bytes()
    } else {
        forged
    };
    let signature = signer.sign(message)?;
    Ok(format!(
        "{unsigned}Sig: {}\n",
        format_signature(KEY_NAME, &signature)
    )
    .into_bytes())
}

fn trusted(signer: &Ed25519Signer) -> Result<Vec<(String, ResolvedIdentity)>, StoreError> {
    let identity = ResolvedIdentity {
        anchor: Kappa::from_key("ed25519", signer.public_key())?,
        public_key: signer.public_key().to_vec(),
        algorithm: "ed25519".into(),
        service_endpoint: None,
        handle: Some(KEY_NAME.into()),
        evidence: None,
    };
    Ok(vec![(KEY_NAME.to_string(), identity)])
}

/// A store with the bootstrap `_nix` namespace.
fn nix_store() -> Result<(InMemoryStore, NamespaceRef), Box<dyn std::error::Error>> {
    let store = test_support::test_store()?.into_store();
    let protocol = ProtocolId::new("nix")?;
    let namespace = namespace_ensure(&store, "_nix", None, Some(&protocol), &clock_at(at(1_000))?)?;
    Ok((store, namespace))
}

fn sorted(mut kappas: Vec<Kappa>) -> Vec<Kappa> {
    kappas.sort();
    kappas
}

fn outbound(anchor: &Kappa, relation: EdgeRelation) -> EdgeQuery {
    EdgeQuery {
        anchor: anchor.clone(),
        direction: Direction::Outbound,
        relation: Some(relation),
        asserter: None,
    }
}

#[test]
fn narinfo_put_publishes_content_tag_and_reference_edges_in_one_epoch() -> TestResult {
    let (store, namespace) = nix_store()?;
    let signer = Ed25519Signer::from_bytes(&[7; 32])?;
    let valid = ParsedNarinfo::parse(STORE_HASH, signed_narinfo(&signer, b"")?)?
        .verify(&trusted(&signer)?)?;
    assert_eq!(valid.signers().len(), 1);
    let (before, _) = store.epoch_current(&namespace)?;

    let mut execution = store.begin_execution(&namespace, &clock_at(at(2_000))?)?;
    let Outcome::Publish(narinfo) = write_narinfo(&mut *execution, &valid, None)? else {
        return Err("a new narinfo must publish".into());
    };
    let published = execution.publish()?;

    assert_eq!(published.epoch_number, before + 1);
    assert_eq!(store.epoch_current(&namespace)?.0, before + 1);
    assert_eq!(
        store.tag_get(&namespace, &narinfo_tag(STORE_HASH))?.kappa,
        narinfo
    );
    assert_eq!(store.blob_get(&narinfo)?, valid.bytes());
    assert_eq!(
        store.namespace_get_meta(&namespace, &nar_ref_key("hello.nar.zst"))?,
        narinfo_tag(STORE_HASH).into_bytes()
    );
    let references = store.edge_query(
        &namespace,
        &outbound(
            &narinfo,
            EdgeRelation::Semantic(SemanticRelation(semantic::REFERENCES.into())),
        ),
        &PageRequest::first(16),
    )?;
    assert_eq!(
        sorted(
            references
                .items
                .iter()
                .map(|edge| edge.target().clone())
                .collect()
        ),
        sorted(vec![
            Kappa::sha256(b"storepath:0z7sqj4pilbqyp45ix5b0mdgn9xlb024"),
            Kappa::sha256(format!("storepath:{STORE_HASH}").as_bytes()),
        ])
    );
    let nar = store.edge_query(
        &namespace,
        &outbound(
            &narinfo,
            EdgeRelation::Semantic(SemanticRelation(semantic::COMPOSED_OF.into())),
        ),
        &PageRequest::first(16),
    )?;
    assert_eq!(
        nar.items
            .iter()
            .map(|edge| edge.target().clone())
            .collect::<Vec<_>>(),
        vec![valid.nar().clone()]
    );
    Ok(())
}

#[test]
fn republishing_the_same_narinfo_is_discarded() -> TestResult {
    let (store, namespace) = nix_store()?;
    let signer = Ed25519Signer::from_bytes(&[7; 32])?;
    let bytes = signed_narinfo(&signer, b"")?;
    let first = ParsedNarinfo::parse(STORE_HASH, bytes.clone())?.verify(&trusted(&signer)?)?;
    let mut execution = store.begin_execution(&namespace, &clock_at(at(2_000))?)?;
    let Outcome::Publish(_) = write_narinfo(&mut *execution, &first, None)? else {
        return Err("a new narinfo must publish".into());
    };
    let published = execution.publish()?;

    let second = ParsedNarinfo::parse(STORE_HASH, bytes)?.verify(&trusted(&signer)?)?;
    let mut execution = store.begin_execution(&namespace, &clock_at(at(3_000))?)?;
    let Outcome::Discard(_) = write_narinfo(&mut *execution, &second, None)? else {
        return Err("an unchanged narinfo must be discarded".into());
    };
    execution.abort()?;
    assert_eq!(store.epoch_current(&namespace)?.0, published.epoch_number);
    Ok(())
}

#[test]
fn narinfo_with_invalid_trusted_signature_publishes_nothing() -> TestResult {
    let (store, namespace) = nix_store()?;
    let signer = Ed25519Signer::from_bytes(&[7; 32])?;
    let parsed = ParsedNarinfo::parse(STORE_HASH, signed_narinfo(&signer, b"forged")?)?;
    let before = store.epoch_current(&namespace)?;

    let rejection = parsed.verify(&trusted(&signer)?);
    let Err(HandlerError::BadRequest { reason }) = rejection else {
        return Err("a forged trusted signature must be rejected".into());
    };
    assert_eq!(
        reason,
        format!("narinfo signature by {KEY_NAME} does not verify")
    );
    assert_eq!(store.epoch_current(&namespace)?, before);
    assert!(matches!(
        store.tag_get(&namespace, &narinfo_tag(STORE_HASH)),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn signature_by_untrusted_key_is_admitted_without_signer() -> TestResult {
    let signer = Ed25519Signer::from_bytes(&[7; 32])?;
    let valid =
        ParsedNarinfo::parse(STORE_HASH, signed_narinfo(&signer, b"forged")?)?.verify(&[])?;
    assert!(valid.signers().is_empty());
    assert_eq!(valid.narinfo().signatures.len(), 1);
    Ok(())
}

#[test]
fn malformed_signature_and_mismatched_url_are_rejected() -> TestResult {
    let malformed = format!("{}Sig: {KEY_NAME}:not-base64\n", unsigned_narinfo());
    assert!(matches!(
        ParsedNarinfo::parse(STORE_HASH, malformed.into_bytes()),
        Err(HandlerError::BadRequest { .. })
    ));
    let rejection = ParsedNarinfo::parse(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        unsigned_narinfo().into_bytes(),
    );
    let Err(HandlerError::BadRequest { reason }) = rejection else {
        return Err("a narinfo served under another hash must be rejected".into());
    };
    assert_eq!(
        reason,
        format!(
            "URL hash bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb does not match store path hash {STORE_HASH}"
        )
    );
    Ok(())
}

#[test]
fn signer_namespace_is_ensured_once_across_two_uploads() -> TestResult {
    let (store, _namespace) = nix_store()?;
    let signer = Ed25519Signer::from_bytes(&[7; 32])?;
    let (key_name, identity) = trusted(&signer)?
        .pop()
        .ok_or("trusted key fixture is empty")?;
    let first_narinfo = Kappa::sha256(b"first narinfo");
    let second_narinfo = Kappa::sha256(b"second narinfo");

    let (first_namespace, first) = bind_signer(
        &store,
        &key_name,
        &identity,
        &first_narinfo,
        &clock_at(at(2_000))?,
    )?;
    let (second_namespace, second) = bind_signer(
        &store,
        &key_name,
        &identity,
        &second_narinfo,
        &clock_at(at(3_000))?,
    )?;

    assert_eq!(first_namespace, second_namespace);
    assert_eq!(
        store.namespace_resolve(&identity.anchor.to_string(), None)?,
        first_namespace
    );
    assert_eq!(second.epoch_number, first.epoch_number + 1);
    let assertions = store.edge_query(
        &first_namespace,
        &outbound(
            &identity.anchor,
            EdgeRelation::Builtin(BuiltinRelation::Assertion),
        ),
        &PageRequest::first(16),
    )?;
    assert_eq!(
        sorted(
            assertions
                .items
                .iter()
                .map(|edge| edge.target().clone())
                .collect()
        ),
        sorted(vec![first_narinfo, second_narinfo])
    );
    Ok(())
}
