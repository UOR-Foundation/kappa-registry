//! In-process OCI registry: the module's routes over an in-memory store,
//! dispatched through the topcoat router without a socket.

use std::sync::Arc;

use topcoat::context::Cx;
use topcoat::router::{Body, LayerFn, LayerFuture, Next, Path, Router, to_bytes};

use kappa_handler::{Clock, ResolvedNamespace, clock_at};
use kappa_store::canonical::from_canonical;
use kappa_store::clock::CausalTime;
use kappa_store::traits::KappaStore;
use kappa_store::{EpochMutation, Kappa, NamespaceRef};
use kappa_store_memory::test_support::test_store;

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

pub struct Reply {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub text: String,
}

impl Reply {
    /// A response header as text; absent when the header is not set.
    pub fn header(&self, name: &str) -> Result<Option<&str>, Box<dyn std::error::Error>> {
        self.headers
            .get(name)
            .map(|value| value.to_str())
            .transpose()
            .map_err(Into::into)
    }
}

/// The router and the store it serves. The store retains its filesystem
/// scope, so clones of `store` outliving the registry stay usable.
pub struct Registry {
    router: Router,
    pub store: Arc<dyn KappaStore>,
}

/// Resolves the request's repository the way the server's namespace layer
/// does: an existing OCI namespace, or the name a first write creates.
fn resolve_repository<'a>(cx: &'a Cx, body: Body, next: Next<'a>) -> LayerFuture<'a> {
    Box::pin(async move {
        let path = topcoat::router::request::uri(cx).path().to_string();
        let name = path
            .strip_prefix("/v2/")
            .and_then(|rest| {
                ["/manifests/", "/tags/", "/blobs/", "/referrers/"]
                    .iter()
                    .find_map(|boundary| rest.find(boundary).map(|end| &rest[..end]))
            })
            .map(str::to_string);
        let store = kappa_handler::store(cx);
        let protocol = kappa_module_oci::protocol_id();
        let resolved = name.map_or(ResolvedNamespace::NoNamespace, |name| {
            store.namespace_resolve(&name, Some(protocol)).map_or_else(
                |_| ResolvedNamespace::NotFound {
                    name: name.clone(),
                    protocol: Some(protocol.clone()),
                },
                ResolvedNamespace::Exists,
            )
        });
        let cx = cx.with(resolved);
        next.run(&cx, body).await
    })
}

impl Registry {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let store: Arc<dyn KappaStore> = Arc::new(test_store()?.into_store());
        let clock: Arc<dyn Clock> =
            Arc::new(clock_at(CausalTime::new(1_700_000_000_000, 0)?.encoded())?);
        let router = kappa_module_oci::register(Router::builder())
            .layer(LayerFn::new(None::<&Path>, resolve_repository))
            .app_context(store.clone())
            .app_context(clock)
            .build();
        Ok(Self { router, store })
    }

    pub async fn send(
        &self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Reply, Box<dyn std::error::Error>> {
        let mut request = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .router
            .handle(request.body(Body::from(body.to_vec()))?)
            .await;
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX)
            .await
            .map_err(|error| format!("response body: {error}"))?;
        Ok(Reply {
            status: parts.status,
            headers: parts.headers,
            text: String::from_utf8(bytes.to_vec())?,
        })
    }

    pub fn repository(&self, name: &str) -> Result<Option<NamespaceRef>, kappa_store::StoreError> {
        kappa_store::absent(
            self.store
                .namespace_resolve(name, Some(kappa_module_oci::protocol_id())),
        )
    }

    /// Current epoch number of a repository; `None` before its first epoch.
    pub fn epoch(&self, ns: &NamespaceRef) -> Result<Option<u64>, kappa_store::StoreError> {
        Ok(kappa_store::absent(self.store.epoch_current(ns))?.map(|(number, _)| number))
    }

    /// The mutation ledger committed by one epoch.
    pub fn ledger(
        &self,
        ns: &NamespaceRef,
        number: u64,
    ) -> Result<Vec<EpochMutation>, Box<dyn std::error::Error>> {
        let root = self.store.epoch_get_by_number(ns, number)?;
        let epoch = self.store.epoch_get(&root)?;
        let ledger = self.store.blob_get_verified(epoch.ledger_root())?;
        Ok(from_canonical(&ledger)?)
    }

    pub fn tag(
        &self,
        ns: &NamespaceRef,
        name: &str,
    ) -> Result<Option<Kappa>, kappa_store::StoreError> {
        Ok(kappa_store::absent(self.store.tag_get(ns, name))?.map(|entry| entry.kappa))
    }
}

pub fn manifest(marker: &str) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2}},"layers":[],"annotations":{{"marker":"{marker}"}}}}"#
    )
    .into_bytes()
}

pub const MANIFEST_TYPE: (&str, &str) =
    ("content-type", "application/vnd.oci.image.manifest.v1+json");
