//! A request client whose connection targets are policy-checked.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use reqwest::Url;

use crate::policy::AddressPolicy;

/// What went wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("address policy refused every resolved address for {0}")]
    AddressRefused(String),
    #[error("scheme {scheme}:// is not permitted")]
    Scheme { scheme: String },
    #[error("response body exceeded {} bytes", .0)]
    TooLarge(u64),
    #[error("unexpected status {status} for {url}")]
    Status { status: u16, url: String },
}

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Which addresses may be connected to. Defaults to [`AddressPolicy::DenyLocal`].
    pub policy: AddressPolicy,
    /// Total time allowed for a request, including the body.
    pub timeout: Duration,
    /// Time allowed to establish the connection.
    pub connect_timeout: Duration,
    /// `None` (the default) means a redirect is returned to the caller instead
    /// of being followed. When set, each hop re-resolves and is re-filtered.
    pub max_redirects: Option<usize>,
    /// Sent as `User-Agent`.
    pub user_agent: String,
    /// Bodies larger than this are refused rather than buffered.
    pub max_response_bytes: u64,
    /// Permit `http://` URLs. Off by default: identity and blob endpoints are
    /// HTTPS, and plaintext makes the response forgeable by anything on the
    /// path.
    pub allow_plaintext: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            policy: AddressPolicy::DenyLocal,
            timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            max_redirects: None,
            user_agent: concat!("rust-tools/egress/", env!("CARGO_PKG_VERSION")).to_owned(),
            max_response_bytes: 8 * 1024 * 1024,
            allow_plaintext: false,
        }
    }
}

/// An HTTP client that refuses to connect to addresses its policy disallows.
#[derive(Debug, Clone)]
pub struct Client {
    inner: reqwest::Client,
    policy: AddressPolicy,
    max_response_bytes: u64,
    allow_plaintext: bool,
}

impl Client {
    /// Build a client. Fails only if the underlying TLS backend cannot start.
    pub fn new(config: ClientConfig) -> Result<Self, Error> {
        let redirect = match config.max_redirects {
            None => Policy::none(),
            Some(0) => Policy::none(),
            Some(n) => Policy::limited(n),
        };
        let inner = reqwest::Client::builder()
            // The connection target check happens here, at connect time: the
            // addresses this resolver returns are the ones the connector dials,
            // so a second DNS answer cannot point the connection somewhere else.
            .dns_resolver(Arc::new(FilteredResolver {
                policy: config.policy,
            }))
            .redirect(redirect)
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .user_agent(config.user_agent)
            // A redirect target must not receive credentials meant for the
            // original origin.
            .referer(false)
            // Implicit proxies defeat the address policy: with a proxy
            // configured, the connection goes to the proxy and the proxy resolves
            // the destination, so nothing in this crate ever sees the address
            // that is eventually fetched. Requests must not be routed anywhere
            // this policy cannot inspect.
            .no_proxy()
            .build()?;
        Ok(Self {
            inner,
            policy: config.policy,
            max_response_bytes: config.max_response_bytes,
            allow_plaintext: config.allow_plaintext,
        })
    }

    /// Fetch `url`, returning the body, refusing redirects unless configured
    /// and refusing bodies over the configured cap.
    pub async fn get_bytes(&self, url: Url) -> Result<Vec<u8>, Error> {
        self.check_url(&url)?;
        let mut response = self.inner.get(url.clone()).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Status {
                status: status.as_u16(),
                url: url.to_string(),
            });
        }
        if let Some(len) = response.content_length() {
            if len > self.max_response_bytes {
                return Err(Error::TooLarge(len));
            }
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() as u64 + chunk.len() as u64 > self.max_response_bytes {
                return Err(Error::TooLarge(self.max_response_bytes));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Parse and fetch in one step.
    pub async fn get(&self, url: &str) -> Result<Vec<u8>, Error> {
        self.get_bytes(Url::parse(url)?).await
    }

    /// Scheme and literal-host checks.
    ///
    /// The resolver hook only runs when a name has to be resolved. A URL whose
    /// host is already an IP literal never reaches it — reqwest connects
    /// straight to that address — so a guard built only on the resolver would
    /// happily fetch `http://127.0.0.1/` or `http://169.254.169.254/`. The
    /// literal has to be checked here, before the request exists.
    fn check_url(&self, url: &Url) -> Result<(), Error> {
        match url.scheme() {
            "https" => {}
            "http" if self.allow_plaintext => {}
            other => {
                return Err(Error::Scheme {
                    scheme: other.to_owned(),
                });
            }
        }
        if let Some(host) = url.host_str() {
            // `host_str` keeps IPv6 addresses in brackets.
            let trimmed = host.trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip) = trimmed.parse::<IpAddr>() {
                if !self.policy.permits(ip) {
                    return Err(Error::AddressRefused(host.to_owned()));
                }
            }
        }
        Ok(())
    }

    /// The underlying client, for callers that need features this wrapper does
    /// not expose. The address policy still applies.
    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }
}

/// Resolves a name and drops any address the policy refuses.
struct FilteredResolver {
    policy: AddressPolicy,
}

impl Resolve for FilteredResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let lookup = tokio::net::lookup_host((host.as_str(), 0)).await;
            let addrs = match lookup {
                Ok(addrs) => addrs,
                Err(err) => {
                    return Err(Box::new(err) as Box<dyn std::error::Error + Send + Sync>);
                }
            };
            // Port 0 is replaced by the connector with the port from the URL.
            let permitted: Vec<SocketAddr> =
                addrs.filter(|addr| policy.permits(addr.ip())).collect();
            if permitted.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("address policy refused every address for {host}"),
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(permitted.into_iter()) as Addrs)
        })
    }
}
