use std::sync::Arc;

use kappa_handler::{ExternalIdentifierResolver, ResolveError, ResolvedIdentity, ResolverRegistry};

pub struct WebFingerResolver {
    client: reqwest::Client,
    registry: Arc<ResolverRegistry>,
    dns: Arc<hickory_resolver::TokioResolver>,
    ttl: u64,
}

impl WebFingerResolver {
    pub fn new(
        registry: Arc<ResolverRegistry>,
        dns: Arc<hickory_resolver::TokioResolver>,
        ttl: u64,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::limited(3))
            .pool_max_idle_per_host(8)
            .build()?;
        Ok(Self {
            client,
            registry,
            dns,
            ttl,
        })
    }

    async fn resolve_webfinger(&self, handle: &str) -> Result<Option<String>, ResolveError> {
        let url = format!(
            "https://{}/.well-known/webfinger?resource=acct:{}",
            handle, handle,
        );
        let resp = match self.client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::debug!(
                    handle = handle,
                    status = %r.status(),
                    "webfinger returned non-success",
                );
                return Ok(None);
            }
            Err(e) => {
                tracing::debug!(
                    handle = handle,
                    error = %e,
                    "webfinger request failed",
                );
                return Ok(None);
            }
        };
        let jrd: serde_json::Value = resp.json().await.map_err(|e| ResolveError::Parse {
            resolver: "webfinger".into(),
            reason: format!("{}: JRD parse: {}", handle, e),
        })?;

        let did = jrd.get("links").and_then(|l| l.as_array()).and_then(|arr| {
            arr.iter().find_map(|link| {
                let rel = link.get("rel")?.as_str()?;
                if rel == "self" {
                    link.get("href")
                        .and_then(|h| h.as_str())
                        .filter(|h| h.starts_with("did:"))
                        .map(|h| h.to_string())
                } else {
                    None
                }
            })
        });

        Ok(did)
    }

    async fn resolve_dns_txt(&self, handle: &str) -> Result<Option<String>, ResolveError> {
        let query = format!("_atproto.{}.", handle);
        let lookup = match self.dns.txt_lookup(&query).await {
            Ok(l) => l,
            Err(e) => {
                tracing::debug!(
                    handle = handle,
                    error = %e,
                    "DNS TXT lookup failed",
                );
                return Ok(None);
            }
        };
        Ok(did_from_txt_answers(lookup.answers()))
    }
}

/// The DID named by the first `did=` TXT record among `answers`. A TXT
/// record's value is the concatenation of its character-strings (one record
/// may be split into several 255-byte strings); answers of any other type,
/// such as the CNAMEs of a chain, are skipped.
fn did_from_txt_answers(answers: &[hickory_resolver::proto::rr::Record]) -> Option<String> {
    answers
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::TXT(txt) => Some(txt.txt_data.concat()),
            _ => None,
        })
        .find_map(|value| {
            String::from_utf8_lossy(&value)
                .trim()
                .trim_matches('"')
                .strip_prefix("did=")
                .map(str::to_owned)
        })
}

#[async_trait::async_trait]
impl ExternalIdentifierResolver for WebFingerResolver {
    fn id_type(&self) -> &str {
        "webfinger"
    }

    fn accepts(&self, identifier: &str) -> bool {
        if identifier.starts_with("did:") {
            return false;
        }
        identifier.contains('.') && !identifier.contains(' ')
    }

    async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, ResolveError> {
        let did = match self.resolve_webfinger(identifier).await? {
            Some(d) => Some(d),
            None => self.resolve_dns_txt(identifier).await?,
        };

        let Some(did) = did else { return Ok(None) };

        self.registry.resolve(&did).await
    }

    fn cache_ttl_secs(&self) -> u64 {
        self.ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_resolver() -> WebFingerResolver {
        let dns = Arc::new(
            hickory_resolver::TokioResolver::builder_tokio()
                .expect("dns resolver builder")
                .build()
                .expect("dns resolver"),
        );
        let registry = Arc::new(ResolverRegistry::new());
        WebFingerResolver::new(registry, dns, 300).expect("build webfinger resolver")
    }

    fn txt(name: &str, strings: &[&str]) -> hickory_resolver::proto::rr::Record {
        use hickory_resolver::proto::rr::rdata::TXT;
        use hickory_resolver::proto::rr::{Name, RData, Record};
        Record::from_rdata(
            name.parse::<Name>().expect("record name"),
            300,
            RData::TXT(TXT::new(strings.iter().map(|s| (*s).to_owned()).collect())),
        )
    }

    #[test]
    fn txt_did_is_read_from_the_record_value_across_split_strings() {
        use hickory_resolver::proto::rr::rdata::CNAME;
        use hickory_resolver::proto::rr::{Name, RData, Record};
        let name = "_atproto.alice.example.com.";
        let cname = Record::from_rdata(
            name.parse::<Name>().expect("record name"),
            300,
            RData::CNAME(CNAME("_atproto.example.net.".parse().expect("target"))),
        );
        let answers = [
            cname,
            txt(name, &["v=other"]),
            txt(name, &["did=did:plc:", "abc123"]),
        ];
        assert_eq!(
            did_from_txt_answers(&answers),
            Some("did:plc:abc123".to_owned())
        );
        assert_eq!(did_from_txt_answers(&answers[..2]), None);
    }

    #[test]
    fn accepts_domain_handle() {
        let resolver = test_resolver();
        assert!(resolver.accepts("alice.example.com"));
        assert!(resolver.accepts("user.bsky.social"));
    }

    #[test]
    fn rejects_did() {
        let resolver = test_resolver();
        assert!(!resolver.accepts("did:plc:abc123"));
        assert!(!resolver.accepts("did:web:example.com"));
    }

    #[test]
    fn rejects_local_name() {
        let resolver = test_resolver();
        assert!(!resolver.accepts("local-name"));
    }

    #[test]
    fn rejects_name_with_space() {
        let resolver = test_resolver();
        assert!(!resolver.accepts("alice .example.com"));
    }

    #[test]
    fn rejects_empty() {
        let resolver = test_resolver();
        assert!(!resolver.accepts(""));
    }

    #[tokio::test]
    async fn resolve_unknown_handle_returns_none() {
        let resolver = test_resolver();
        // Without a real network, both webfinger and DNS TXT fail
        // gracefully, returning Ok(None).
        let result = resolver.resolve("nonexistent.example.com").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
