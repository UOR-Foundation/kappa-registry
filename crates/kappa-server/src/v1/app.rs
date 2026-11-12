//! Server assembly.
//!
//! [`build`] turns a [`Config`] into a [`Server`]: the persistent store, the
//! durable time authority, node identity, the layer chain, every protocol
//! module's routes and the background tasks. [`Server::serve`] serves it on
//! any bound [`Listener`] until a shutdown future completes, then winds down
//! what it started. The binary binds the configured address (TCP or TLS)
//! and serves; a test or benchmark harness serves the same assembly on an
//! ephemeral port in its own process. Every startup failure is a
//! [`StartError`] carrying its cause; nothing here exits the process.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use topcoat::router::{
    Compression, LayerFn, Listener, Path, Router, RouterBuilder, RouterService, internal_serve,
};

use kappa_handler::clock::{Clock, WallClock};
use kappa_store::delta::DeltaBudget;
use kappa_store::kappa::Kappa;
use kappa_store::traits::KappaStore;
use kappa_store_redb::PersistentStore;

use crate::config::Config;
use crate::{
    auth, bootstrap, detect, identity_directory, layers, namespace_routes, node_authority,
    ratelimit, resolvers, system_routes, tasks, time,
};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Publications the feed retains for firehose resumption.
const PUBLICATION_FEED_CAPACITY: usize = 4096;

/// Feed sequence numbers reserved per millisecond of start time.
const PUBLICATION_FEED_SEQUENCES_PER_MS: u64 = 1024;

/// Why the server could not be assembled.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("storage encryption root: {0}")]
    EncryptionRoot(#[source] BoxError),
    #[error("persistent store: {0}")]
    Store(#[source] BoxError),
    #[error("time authority: {0}")]
    Time(#[source] BoxError),
    #[error("store format version: {0}")]
    Version(#[source] BoxError),
    #[error("system namespace bootstrap: {0}")]
    Bootstrap(#[source] BoxError),
    #[error("keystore: {0}")]
    KeyStore(#[source] BoxError),
    #[error("node identity: {0}")]
    NodeIdentity(#[source] BoxError),
    #[error("KAPPA_ROOT_TOKEN anchor '{anchor}' is not a valid kappa: {reason}")]
    RootTokenAnchor { anchor: String, reason: String },
    #[error("DNS resolver from the system configuration: {0}")]
    Dns(#[source] BoxError),
    #[error("identity directory: {0}")]
    KeyDirectory(String),
}

fn boxed<E: Into<BoxError>>(error: E) -> BoxError {
    error.into()
}

/// Tasks the server owns; dropping them aborts every one.
struct Tasks(Vec<JoinHandle<()>>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// An assembled server, ready to serve.
pub struct Server {
    service: RouterService,
    tasks: Tasks,
    #[cfg(feature = "distribution")]
    crdt_manager: Arc<kappa_module_distribution::CrdtManager>,
    #[cfg(feature = "veilid")]
    veilid: Option<tasks::veilid::VeilidHandle>,
}

impl Server {
    /// Serve on `listener` until `shutdown` completes and in-flight
    /// requests drain (30 seconds at most), then persist open CRDT rooms,
    /// stop the background tasks and shut the Veilid transport down.
    pub async fn serve(
        self,
        listener: impl Listener,
        shutdown: impl Future<Output = ()>,
    ) -> std::io::Result<()> {
        let Self {
            service,
            tasks,
            #[cfg(feature = "distribution")]
            crdt_manager,
            #[cfg(feature = "veilid")]
            veilid,
        } = self;
        let served = internal_serve(listener, service, shutdown).await;
        #[cfg(feature = "distribution")]
        crdt_manager.shutdown().await;
        drop(tasks);
        #[cfg(feature = "veilid")]
        if let Some(handle) = veilid {
            tracing::info!("shutting down Veilid transport");
            handle.shutdown().await;
        }
        served
    }
}

/// Open the persistent store, offering every intact node key and letting
/// its authority history select the one that signs (see
/// [`node_authority::establish`]).
fn open_store(
    cfg: &Config,
    root_key: Option<&[u8; 32]>,
    authority: kappa_crypto::SigningAuthority,
    alternates: Vec<kappa_crypto::SigningAuthority>,
    require_history: bool,
) -> Result<PersistentStore, kappa_store::StoreError> {
    let mut store_config = kappa_store_redb::config::PersistentStoreConfig::new(
        cfg.store_root.join("blobs"),
        cfg.store_root.join("state.redb"),
        authority,
    )
    .with_alternates(alternates);
    if require_history {
        store_config = store_config.requiring_history();
    }
    store_config.fsync = cfg.fsync;
    store_config.encryption_key = root_key.copied();
    store_config.open_inventory_entries = cfg.inventory_batch;
    PersistentStore::new(store_config)
}

/// `KAPPA_ROOT_TOKEN`'s bearer token and the anchor it acts as.
fn root_token(cfg: &Config) -> Result<Option<(String, Kappa)>, StartError> {
    let Some((token, anchor_str)) = cfg
        .root_token
        .as_deref()
        .and_then(|root_token| root_token.split_once('='))
    else {
        return Ok(None);
    };
    let delegate = Kappa::parse(anchor_str).map_err(|error| StartError::RootTokenAnchor {
        anchor: anchor_str.to_owned(),
        reason: error.to_string(),
    })?;
    Ok(Some((token.to_owned(), delegate)))
}

/// Bearer tokens: the configured ones, plus `KAPPA_ROOT_TOKEN`'s delegate.
/// The delegate authorizes only through the `_root` delegation the node
/// publishes for it, which [`node_authority::NodeAuthority::reconcile`]
/// establishes before the server serves.
fn bearer_tokens(cfg: &Config, root: Option<&(String, Kappa)>) -> Vec<(String, Kappa)> {
    let mut tokens = cfg.auth_tokens.clone();
    if let Some((token, delegate)) = root
        && !tokens.iter().any(|(t, _)| t == token)
    {
        tokens.push((token.clone(), delegate.clone()));
    }
    tokens
}

fn detectors() -> kappa_handler::DetectorRegistry {
    let mut registry = kappa_handler::DetectorRegistry::new();
    registry.register(detect::SystemPathDetector);
    #[cfg(feature = "oci")]
    registry.register(kappa_module_oci::detect::OciPrefixDetector);
    #[cfg(feature = "git")]
    {
        registry.register(kappa_module_git::detect::GitHeaderDetector);
        registry.register(kappa_module_git::detect::GitPathDetector);
        registry.register(kappa_module_git::detect::GitDumbHttpDetector);
    }
    #[cfg(feature = "s3")]
    registry.register(kappa_module_s3::detect::S3HeaderDetector);
    #[cfg(feature = "nix")]
    registry.register(kappa_module_nix::detect::NixPathDetector);
    #[cfg(feature = "atproto")]
    registry.register(kappa_module_atproto::detect::XrpcDetector);
    registry
}

/// The layer chain. topcoat runs the last registered layer outermost, so
/// registration is innermost first.
fn layered(builder: RouterBuilder) -> RouterBuilder {
    builder
        .layer(LayerFn::new(
            None::<&Path>,
            layers::namespace::namespace_layer,
        ))
        .layer(LayerFn::new(Some("/"), layers::cache::cache_layer))
        .layer(LayerFn::new(
            Some("/"),
            layers::response_compliance::response_compliance_layer,
        ))
        .layer(LayerFn::new(
            Some("/"),
            layers::body_limit::body_limit_layer,
        ))
        .layer(LayerFn::new(
            Some("/"),
            layers::disk_pressure::disk_pressure_layer,
        ))
        .layer(LayerFn::new(
            Some("/"),
            layers::rate_limit::rate_limit_layer,
        ))
        .layer(LayerFn::new(Some("/"), layers::auth::auth_layer))
        .layer(LayerFn::new(Some("/"), layers::timeout::timeout_layer))
        .layer(LayerFn::new(Some("/"), layers::cors::cors_layer))
        .layer(LayerFn::new(
            Some("/"),
            layers::security_headers::security_headers_layer,
        ))
        .layer(LayerFn::new(
            Some("/"),
            layers::request_id::request_id_layer,
        ))
        .layer(LayerFn::new(
            Some("/"),
            layers::proxy_trust::proxy_trust_layer,
        ))
        .layer(LayerFn::new(
            Some("/"),
            layers::request_log::request_log_layer,
        ))
        .layer(LayerFn::new(Some("/"), layers::warning::warning_layer))
}

/// Background loops: eviction, content inventory, federation probing,
/// handle verification, namespace lifecycle and disk pressure, which also
/// registers its flag.
fn spawn_background(
    cfg: &Config,
    mut builder: RouterBuilder,
    store: &Arc<dyn KappaStore>,
    clock: &Arc<WallClock>,
    node_identity: &Arc<kappa_crypto::NodeIdentity>,
    resolver_registry: &Arc<kappa_handler::ResolverRegistry>,
    budget: &Arc<kappa_handler::StagingBudget>,
) -> (RouterBuilder, Vec<JoinHandle<()>>) {
    let mut spawned = vec![
        tokio::spawn(tasks::eviction::run_eviction_loop(
            store.clone(),
            clock.clone(),
            budget.clone(),
        )),
        tokio::spawn(tasks::handle_verify::run_handle_verify_loop(
            store.clone(),
            resolver_registry.clone(),
            clock.clone(),
            cfg.handle_verify_interval_secs,
            cfg.handle_ttl_ms,
        )),
        tokio::spawn(tasks::lifecycle::run_lifecycle_loop(
            store.clone(),
            clock.clone(),
            budget.clone(),
            cfg.lifecycle_interval_secs,
        )),
        tokio::spawn(tasks::inventory::run_inventory_loop(
            store.clone(),
            clock.clone(),
            cfg.inventory_interval_secs,
            cfg.inventory_batch,
            cfg.maintenance,
        )),
    ];
    if !cfg.federation_peers.is_empty() {
        spawned.push(tokio::spawn(tasks::federation::run_federation_probe_loop(
            store.clone(),
            clock.clone(),
            node_identity.clone(),
            cfg.federation_peers.clone(),
            cfg.probe_interval_secs,
        )));
    }
    if cfg.disk_pressure_threshold_mb > 0 {
        let pressure = Arc::new(tasks::disk_pressure::DiskPressure(
            std::sync::atomic::AtomicBool::new(false),
        ));
        builder = builder.app_context(pressure.clone());
        spawned.push(tokio::spawn(
            tasks::disk_pressure::run_disk_pressure_monitor(
                pressure,
                cfg.store_root.clone(),
                cfg.disk_pressure_threshold_mb * 1024 * 1024,
                cfg.disk_pressure_check_interval_secs,
            ),
        ));
    }
    (builder, spawned)
}

/// Start the Veilid transport when a storage directory is configured,
/// registering its transport and seeding configured federation peers.
#[cfg(feature = "veilid")]
async fn start_veilid(
    cfg: &Config,
    mut builder: RouterBuilder,
    store: &Arc<dyn KappaStore>,
    clock: &Arc<WallClock>,
    node_identity: &kappa_crypto::NodeIdentity,
) -> (RouterBuilder, Option<tasks::veilid::VeilidHandle>) {
    let Some(storage_dir) = cfg.veilid_storage_dir.clone() else {
        return (builder, None);
    };
    let namespace = cfg
        .veilid_namespace
        .clone()
        .unwrap_or_else(|| "kappa-registry".to_string());
    let self_id = match node_identity.anchor() {
        Ok(anchor) => anchor.to_string(),
        Err(error) => {
            tracing::warn!(%error, "Veilid transport not started: node identity unavailable");
            return (builder, None);
        }
    };
    tracing::info!(storage_dir = %storage_dir, namespace = %namespace, "starting Veilid transport");
    let handle = match tasks::veilid::start_veilid(
        storage_dir,
        namespace,
        cfg.veilid_insecure,
        store.clone(),
        clock.clone(),
        self_id,
        30,
    )
    .await
    {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(%error, "Veilid transport start failed");
            return (builder, None);
        }
    };
    builder = builder.app_context(handle.node().transport().clone());
    // Each configured peer is a hex-encoded Veilid route blob obtained out
    // of band; reconciliation contacts them on its first tick, and later
    // peers arrive through gossip, DHT reads and reconciliation metadata.
    let node = handle.node().node();
    let mut seeded = 0u32;
    for peer_blob_hex in &cfg.federation_peers {
        match hex::decode(peer_blob_hex.trim()) {
            Ok(blob) if !blob.is_empty() => {
                node.peers().write().cache_route(peer_blob_hex, blob);
                seeded += 1;
            }
            Ok(_) => tracing::warn!(
                entry = peer_blob_hex.as_str(),
                "federation peer bootstrap: empty blob after hex decode"
            ),
            Err(error) => tracing::warn!(
                entry = peer_blob_hex.as_str(),
                %error,
                "federation peer bootstrap: invalid hex, skipping"
            ),
        }
    }
    if seeded > 0 {
        tracing::info!(
            seeded,
            total = cfg.federation_peers.len(),
            "Veilid peers bootstrapped into PeerRegistry"
        );
    }
    tracing::info!("Veilid transport started");
    (builder, Some(handle))
}

/// Assemble the server `cfg` describes. `tls` states whether it will be
/// served over TLS, which the security headers depend on.
#[allow(
    clippy::too_many_lines,
    reason = "one sequential assembly: each step's state feeds the next"
)]
pub async fn build(cfg: &Config, tls: bool) -> Result<Server, StartError> {
    // The node's keys are acquired first and the store's committed
    // authority history selects the one that signs: a node that cannot
    // establish its identity cannot serve, and the store, the key store and
    // the live identity agree on one authority before anything signs.
    let key_store = Arc::new(
        kappa_crypto::keystore::KeyStore::new(cfg.store_root.join("keys"))
            .map_err(|error| StartError::KeyStore(boxed(error)))?,
    );
    let root_key = cfg
        .encryption_key_file
        .as_deref()
        .map(kappa_crypto::keystore::load_root_key)
        .transpose()
        .map_err(|error| StartError::EncryptionRoot(boxed(error)))?;
    let node_authority::Established {
        store: persistent_store,
        identity: node_identity,
        damaged,
        cleanup,
    } = node_authority::establish(
        &key_store,
        &cfg.signing_algorithm,
        |authority, alternates, require_history| {
            open_store(
                cfg,
                root_key.as_deref(),
                authority,
                alternates,
                require_history,
            )
        },
    )
    .map_err(|error| match error {
        crate::node_outcome::EstablishError::KeyStore(error) => {
            StartError::NodeIdentity(boxed(error))
        }
        crate::node_outcome::EstablishError::Store(error) => StartError::Store(boxed(error)),
    })?;
    drop(root_key);
    // Selection succeeded from intact keys; damage and unremoved entries are
    // operator-visible state that the next settlement repairs, not a reason
    // to refuse to serve under the committed authority.
    for damage in &damaged {
        tracing::warn!(%damage, "node key store damage found at startup");
    }
    if let Err(error) = &cleanup {
        tracing::warn!(%error, "node key store cleanup incomplete at startup; the next settlement repeats it");
    }
    let clock = time::initialize(persistent_store.clone())
        .await
        .map_err(|error| StartError::Time(boxed(error)))?;
    let reservation = tokio::spawn(time::renew(clock.clone()));
    let mut owned = Tasks(vec![reservation]);
    let store: Arc<dyn KappaStore> = persistent_store.clone();

    kappa_store::version::check_or_write_version(&cfg.store_root)
        .map_err(|error| StartError::Version(boxed(error)))?;
    bootstrap::create_system_namespaces(&*store, &*clock)
        .map_err(|error| StartError::Bootstrap(boxed(error)))?;
    let root = root_token(cfg)?;
    // A configured witness key that cannot be loaded is a configuration
    // error; an absent one leaves rotation refused, never unwitnessed.
    let witnesses: Arc<dyn crate::rotation_witness::RotationWitnesses> =
        match cfg.rotation_witness_key_file.as_deref() {
            Some(path) => Arc::new(
                crate::rotation_witness::KeyWitness::load(path)
                    .map_err(|error| StartError::NodeIdentity(boxed(error)))?,
            ),
            None => Arc::new(crate::rotation_witness::Unwitnessed),
        };
    let authority = Arc::new(node_authority::NodeAuthority::new(
        key_store.clone(),
        node_identity.clone(),
        persistent_store.clone(),
        clock.clone(),
        root.as_ref().map(|(_, delegate)| delegate.clone()),
        cfg.signing_algorithm.clone(),
        witnesses,
    ));
    // Every authority guarantee is reconciled before the node serves,
    // including what an interrupted rotation left behind. Authorization and
    // revocation are required to serve at all: requests are authorized
    // against the published grants, so serving before a retired
    // authority's grants are revoked would let them authorize. Custody and
    // key removal failures leave the committed key signing; they are
    // recorded, keep readiness false, and are retried by readiness.
    let follow_up = authority
        .reconcile()
        .map_err(|error| StartError::NodeIdentity(boxed(error)))?;
    for (guarantee, error) in follow_up.failures() {
        tracing::warn!(guarantee, %error, "node authority guarantee incomplete at startup");
    }
    if let Err(error) = follow_up.authorization {
        return Err(StartError::Bootstrap(boxed(error)));
    }
    if let Err(error) = follow_up.revocation {
        return Err(StartError::Bootstrap(boxed(error)));
    }
    // The staging budget projects every open and prepared resource the
    // store committed, so restart admits against what is already staged.
    let budget = Arc::new(kappa_handler::StagingBudget::new(
        cfg.max_transactions,
        cfg.max_staging_bytes,
    ));
    let staged = tokio::task::spawn_blocking({
        let budget = budget.clone();
        let store = store.clone();
        move || budget.rebuild(&*store)
    })
    .await
    .map_err(|error| StartError::Bootstrap(boxed(error)))?
    .map_err(|error| StartError::Bootstrap(boxed(error)))?;
    tracing::info!(
        resources = staged,
        bytes = budget.staged_bytes(),
        "staging budget rebuilt from committed resources"
    );

    // Event subscribers read authenticated history; the feed only wakes
    // them and orders this node's publications for the firehose. Its
    // sequence numbers start at this start's physical time in milliseconds
    // times 1024, so a firehose cursor from an earlier start is older than
    // every sequence this start assigns unless the earlier start assigned
    // more than 1024 per millisecond of its lifetime or the time authority
    // regressed; such a cursor is answered as outdated, never as current.
    let started_ms = clock
        .physical_now()
        .map_err(|error| StartError::Time(boxed(error)))?
        .as_millis();
    let first_sequence = u64::try_from(started_ms)
        .ok()
        .and_then(|ms| ms.checked_mul(PUBLICATION_FEED_SEQUENCES_PER_MS))
        .ok_or_else(|| StartError::Time(boxed("physical time outside the feed sequence range")))?;
    let publication_feed = Arc::new(kappa_handler::PublicationFeed::new(
        PUBLICATION_FEED_CAPACITY,
        first_sequence,
    ));
    // Registered by value: `rate_limit_layer` resolves `TieredRateLimiter`,
    // whose limiters are already shared through their own `Arc`s.
    let rate_limiter = cfg
        .rate_limit
        .is_enabled()
        .then(|| ratelimit::TieredRateLimiter::new(&cfg.rate_limit));
    let bearer_auth = Arc::new(auth::BearerAuth::new(
        bearer_tokens(cfg, root.as_ref()),
        cfg.auth_required,
    ));
    let dns_resolver = hickory_resolver::TokioResolver::builder_tokio()
        .and_then(hickory_resolver::ResolverBuilder::build)
        .map(Arc::new)
        .map_err(|error| StartError::Dns(boxed(error)))?;
    let resolver_registry = resolvers::build_registry(
        dns_resolver,
        &cfg.plc_directory_url,
        &cfg.rekor_url,
        u64::MAX,
        3600,
        60,
        300,
    );
    let outbound_client = Arc::new(
        topcoat::router::outbound::OutboundClient::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(format!("kappa-registry/{}", env!("CARGO_PKG_VERSION")))
            .build(),
    );

    let mut builder = layered(Router::builder().compression(Compression::off()))
        .app_context(store.clone())
        .app_context(clock.clone() as Arc<dyn Clock>);
    #[cfg(feature = "atproto")]
    {
        // The clock identifier only separates TID streams of distinct
        // nodes; it is derived once from the anchor the node started with.
        let anchor = node_identity
            .anchor()
            .map_err(|error| StartError::NodeIdentity(boxed(error)))?;
        let tids = kappa_module_atproto::tid::TidGenerator::new(&anchor.to_string());
        // Sessions and account credentials are epoch-governed rows of the
        // `_sessions` namespace, published through the store.
        let sessions = kappa_module_atproto::SessionStore::new(
            store.clone(),
            clock.clone() as Arc<dyn Clock>,
            kappa_module_atproto::session::SessionConfig::default(),
        )
        .map_err(|error| StartError::NodeIdentity(boxed(error)))?;
        builder = builder
            .app_context(Arc::new(tids))
            .app_context(Arc::new(sessions));
    }
    builder = builder
        .app_context(kappa_handler::MaxBlobSize(cfg.max_blob_size))
        .app_context(Arc::new(DeltaBudget::new(cfg.max_delta_bytes)))
        .app_context(budget.clone())
        .app_context(bearer_auth)
        .app_context(publication_feed)
        .app_context(layers::RequestTimeout(Duration::from_secs(
            cfg.request_timeout_secs,
        )))
        .app_context(layers::MaxApiBodyBytes(cfg.max_api_body_bytes))
        .app_context(Arc::new(detectors()))
        .app_context(outbound_client)
        .app_context(resolver_registry.clone());
    if let Some(proxy_header) = &cfg.proxy_trusted_header {
        builder = builder.app_context(layers::ProxyTrustConfig {
            trusted_header: Some(proxy_header.clone()),
        });
    }
    if tls {
        builder = builder.app_context(layers::TlsEnabled);
    }
    builder = builder
        .app_context(node_identity.clone())
        .app_context(authority);
    if let Some(limiter) = rate_limiter {
        builder = builder.app_context(limiter);
    }

    // Server routes: status, version check, health, OpenAPI and Scalar
    // documentation, and namespace lifecycle management.
    builder = namespace_routes::register(system_routes::register(builder));
    #[cfg(feature = "oci")]
    {
        builder = kappa_module_oci::register(builder);
    }
    #[cfg(feature = "identity-http")]
    {
        // Identity proofs require the directory; a node that cannot open
        // it must not serve identity routes without their proofs.
        let directory = identity_directory::open(store.clone(), clock.clone())
            .await
            .map_err(StartError::KeyDirectory)?;
        builder = kappa_module_identity::register(builder.app_context(directory));
    }
    // CRDT collaboration rooms persist their state when the last client
    // leaves and, for rooms still open, when the server stops.
    #[cfg(feature = "distribution")]
    let crdt_manager = Arc::new(kappa_module_distribution::CrdtManager::new(
        store.clone(),
        clock.clone(),
        &kappa_module_distribution::ws_crdt::CrdtConfig {
            max_rooms: cfg.crdt_max_rooms,
        },
    ));
    #[cfg(feature = "distribution")]
    {
        builder = kappa_module_distribution::register(builder.app_context(crdt_manager.clone()));
    }
    #[cfg(feature = "atproto")]
    {
        builder = kappa_module_atproto::register(builder);
    }
    #[cfg(feature = "git")]
    {
        builder = kappa_module_git::register(builder);
    }
    #[cfg(feature = "s3")]
    {
        builder = kappa_module_s3::register(builder);
    }
    #[cfg(feature = "nix")]
    {
        builder = kappa_module_nix::register(builder);
    }

    let (builder, spawned) = spawn_background(
        cfg,
        builder,
        &store,
        &clock,
        &node_identity,
        &resolver_registry,
        &budget,
    );
    owned.0.extend(spawned);
    #[cfg(feature = "veilid")]
    let (builder, veilid) = start_veilid(cfg, builder, &store, &clock, &node_identity).await;

    let service = RouterService::new(builder.build()).shutdown_timeout(Duration::from_secs(30));
    Ok(Server {
        service,
        tasks: owned,
        #[cfg(feature = "distribution")]
        crdt_manager,
        #[cfg(feature = "veilid")]
        veilid,
    })
}
