//! OCI distribution requests against the in-process server, each sent on a
//! connection its caller owns.
//!
//! A [`Connection`] is one HTTP/1.1 connection over one TCP stream, made
//! with hyper's connection-level client (`hyper::client::conn::http1`):
//! no pool, so nothing opens, reuses or replaces a connection behind the
//! caller, and a connection that fails fails its caller. `TCP_NODELAY` is
//! set on the stream, so a small request is never held back waiting for
//! the server to acknowledge the previous segment.
//!
//! Every response is checked for the work it claims: a content response
//! must be 200 with the expected `docker-content-digest` and exactly the
//! expected number of body bytes, all of which are read; a store must be
//! 201 (newly stored). Anything else fails the request.

use std::net::SocketAddr;

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE, HOST, HeaderName};
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

pub const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const LAYER_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

pub fn sha256_digest(content: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(content)))
}

/// `/v2/{namespace}/blobs/{digest}`.
pub fn blob_path(namespace: &str, digest: &str) -> String {
    format!("/v2/{namespace}/blobs/{digest}")
}

/// What a response must show for its request to have done its work.
#[derive(Debug, Clone)]
pub enum Expect {
    /// 200 carrying exactly this content.
    Content { digest: String, length: usize },
    /// 201: newly stored.
    Created,
}

impl Expect {
    fn check(
        &self,
        what: &str,
        status: StatusCode,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<(), String> {
        let want = match self {
            Self::Content { .. } => StatusCode::OK,
            Self::Created => StatusCode::CREATED,
        };
        if status != want {
            return Err(format!(
                "{what}: status {status}, expected {want}: {}",
                String::from_utf8_lossy(body)
            ));
        }
        if let Self::Content { digest, length } = self {
            let served = headers
                .get("docker-content-digest")
                .and_then(|value| value.to_str().ok());
            if served != Some(digest.as_str()) {
                return Err(format!("{what}: digest {served:?}, expected {digest}"));
            }
            if body.len() != *length {
                return Err(format!(
                    "{what}: {} body bytes, expected {length}",
                    body.len()
                ));
            }
        }
        Ok(())
    }
}

/// One request, in origin form, and the response it must receive.
#[derive(Debug, Clone)]
pub struct Call {
    method: Method,
    path: String,
    headers: Vec<(HeaderName, &'static str)>,
    body: Bytes,
    expect: Expect,
}

impl Call {
    pub const fn new(
        method: Method,
        path: String,
        headers: Vec<(HeaderName, &'static str)>,
        body: Bytes,
        expect: Expect,
    ) -> Self {
        Self {
            method,
            path,
            headers,
            body,
            expect,
        }
    }

    /// GET `path`, which must serve `stored`.
    pub fn get(path: String, accept: Option<&'static str>, stored: &Stored) -> Self {
        Self::new(
            Method::GET,
            path,
            accept.map(|value| (ACCEPT, value)).into_iter().collect(),
            Bytes::new(),
            Expect::Content {
                digest: stored.digest.clone(),
                length: stored.length,
            },
        )
    }

    /// Monolithic upload of `content` to its blob path in `namespace`,
    /// digested here, ahead of sending.
    pub fn put_blob(namespace: &str, content: Bytes) -> Self {
        let path = blob_path(namespace, &sha256_digest(&content));
        Self::new(Method::PUT, path, Vec::new(), content, Expect::Created)
    }
}

/// One HTTP/1.1 connection to the server.
pub struct Connection {
    sender: SendRequest<Full<Bytes>>,
    host: HeaderValue,
    driver: JoinHandle<hyper::Result<()>>,
}

impl Connection {
    /// Connect to `addr` and complete the HTTP/1 handshake.
    pub async fn open(addr: SocketAddr) -> Result<Self, String> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect {addr}: {e}"))?;
        stream
            .set_nodelay(true)
            .map_err(|e| format!("TCP_NODELAY on {addr}: {e}"))?;
        let (sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| format!("HTTP/1 handshake with {addr}: {e}"))?;
        let host = HeaderValue::from_str(&addr.to_string())
            .map_err(|e| format!("host header {addr}: {e}"))?;
        Ok(Self {
            sender,
            host,
            driver: tokio::spawn(connection),
        })
    }

    /// Send `call` and check its response, read in full.
    pub async fn call(&mut self, call: Call) -> Result<(), String> {
        let what = format!("{} {}", call.method, call.path);
        self.sender
            .ready()
            .await
            .map_err(|e| format!("{what}: connection: {e}"))?;
        let mut request = Request::builder()
            .method(call.method)
            .uri(&call.path)
            .header(HOST, self.host.clone());
        for (name, value) in &call.headers {
            request = request.header(name, *value);
        }
        let request = request
            .body(Full::new(call.body))
            .map_err(|e| format!("{what}: {e}"))?;
        let response = self
            .sender
            .send_request(request)
            .await
            .map_err(|e| format!("{what}: {e}"))?;
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|e| format!("{what}: body: {e}"))?
            .to_bytes();
        call.expect
            .check(&what, parts.status, &parts.headers, &body)
    }

    /// Close the connection and report how it ended.
    pub async fn close(self) -> Result<(), String> {
        // With the sender gone, the connection finishes and shuts the
        // stream down.
        drop(self.sender);
        self.driver
            .await
            .map_err(|e| format!("connection task: {e}"))?
            .map_err(|e| format!("connection: {e}"))
    }
}

/// A stored blob a GET can be checked against.
#[derive(Debug, Clone)]
pub struct Stored {
    pub digest: String,
    pub length: usize,
}

impl Stored {
    fn of(content: &[u8]) -> Self {
        Self {
            digest: sha256_digest(content),
            length: content.len(),
        }
    }
}

/// What the GET measurements read.
pub struct Seeded {
    /// One blob per measured size, in size order.
    pub blobs: Vec<(usize, Stored)>,
    /// The `latest` image manifest.
    pub manifest: Stored,
}

/// Upload `content` to `namespace` and describe what was stored.
async fn store(
    connection: &mut Connection,
    namespace: &str,
    content: Bytes,
) -> Result<Stored, String> {
    let stored = Stored::of(&content);
    connection.call(Call::put_blob(namespace, content)).await?;
    Ok(stored)
}

/// Create `namespace` and store one blob per size and an image manifest
/// tagged `latest` whose config and layer blobs exist, over one connection.
pub async fn seed(
    addr: SocketAddr,
    namespace: &'static str,
    sizes: &[usize],
) -> Result<Seeded, String> {
    let mut connection = Connection::open(addr).await?;
    connection
        .call(Call::new(
            Method::POST,
            format!("/v2/{namespace}/_namespace/create"),
            Vec::new(),
            Bytes::new(),
            Expect::Created,
        ))
        .await?;

    let mut blobs = Vec::with_capacity(sizes.len());
    for (seed, &size) in (900u64..).zip(sizes) {
        let content = Bytes::from(kappa_perf::bench::pattern(size, seed));
        blobs.push((size, store(&mut connection, namespace, content).await?));
    }

    let config = store(
        &mut connection,
        namespace,
        Bytes::from_static(br#"{"architecture":"amd64","os":"linux"}"#),
    )
    .await?;
    let layer = store(
        &mut connection,
        namespace,
        Bytes::from(kappa_perf::bench::pattern(4096, 990)),
    )
    .await?;
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "config": {
            "mediaType": CONFIG_TYPE,
            "digest": config.digest,
            "size": config.length,
        },
        "layers": [{
            "mediaType": LAYER_TYPE,
            "digest": layer.digest,
            "size": layer.length,
        }],
    });
    let manifest = Bytes::from(serde_json::to_vec(&manifest).map_err(|e| e.to_string())?);
    let stored = Stored::of(&manifest);
    connection
        .call(Call::new(
            Method::PUT,
            format!("/v2/{namespace}/manifests/latest"),
            vec![(CONTENT_TYPE, MANIFEST_TYPE)],
            manifest,
            Expect::Created,
        ))
        .await?;
    connection.close().await?;
    Ok(Seeded {
        blobs,
        manifest: stored,
    })
}
