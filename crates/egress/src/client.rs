//! A request client whose connection targets are policy-checked.

use std::net::IpAddr;
#[cfg(not(target_arch = "wasm32"))]
use std::net::SocketAddr;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
#[cfg(not(target_arch = "wasm32"))]
use reqwest::redirect::Policy;
use url::Url;

use crate::policy::AddressPolicy;

/// What went wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[cfg(not(target_arch = "wasm32"))]
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[cfg(target_arch = "wasm32")]
    #[error("request failed: {0}")]
    Request(String),
    #[error("unsupported configuration: {0}")]
    UnsupportedConfiguration(&'static str),
    #[cfg(target_arch = "wasm32")]
    #[error("request timed out after {0:?}")]
    Timeout(Duration),
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
    /// Time allowed to establish the connection. On Cloudflare Workers the
    /// connection phase is not observable, so this conservatively bounds
    /// the time until response headers instead.
    pub connect_timeout: Duration,
    /// `None` (the default) means a redirect is returned to the caller instead
    /// of being followed. When set, each hop re-resolves and is checked again.
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

/// A buffered HTTP response, including non-success responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status code.
    pub status: u16,
    /// The complete body, bounded by [`ClientConfig::max_response_bytes`].
    pub body: Vec<u8>,
}

/// An HTTP client with a configured address policy. Native connections are
/// filtered directly; the explicit Cloudflare backend relies on the platform
/// to enforce public-only routing for resolved addresses.
#[derive(Debug, Clone)]
pub struct Client {
    #[cfg(not(target_arch = "wasm32"))]
    inner: reqwest::Client,
    #[cfg(target_arch = "wasm32")]
    inner: crate::worker::CloudflareClient,
    policy: AddressPolicy,
    max_response_bytes: u64,
    allow_plaintext: bool,
}

impl Client {
    /// Build a native client. Fails only if the underlying TLS backend cannot start.
    ///
    /// On `wasm32`, this always returns [`Error::UnsupportedConfiguration`]. A
    /// Worker caller must explicitly opt in with `Client::new_cloudflare` after
    /// establishing that constructor's documented platform guarantees.
    pub fn new(config: ClientConfig) -> Result<Self, Error> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = config;
            Err(Error::UnsupportedConfiguration(
                "Client::new is unavailable on wasm32; use Client::new_cloudflare only with the required Cloudflare public-only platform configuration",
            ))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let redirect = match config.max_redirects {
                None | Some(0) => Policy::none(),
                Some(max) => {
                    let policy = config.policy;
                    let allow_plaintext = config.allow_plaintext;
                    Policy::custom(move |attempt| {
                        if attempt.previous().len() > max {
                            return attempt.error("too many redirects");
                        }
                        // A redirect is a second, attacker-chosen URL. Everything the
                        // first URL had to satisfy applies to it too — including the
                        // literal-host check, since reqwest does not resolve IP
                        // literals and would otherwise connect straight to one.
                        match check_url(policy, allow_plaintext, attempt.url()) {
                            Ok(()) => attempt.follow(),
                            Err(err) => attempt.error(RedirectRefused(err.to_string())),
                        }
                    })
                }
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
    }

    /// Build the explicitly platform-dependent Cloudflare Workers backend.
    ///
    /// The caller **MUST** run this only in a Cloudflare Worker configured with
    /// the `global_fetch_strictly_public` compatibility flag **and** public-only
    /// outbound routing. Calling this constructor is an assertion that both
    /// external requirements hold; the crate cannot inspect that configuration.
    ///
    /// Rust checks the URL scheme and literal IP hosts. It cannot observe or
    /// filter the addresses selected by Worker DNS resolution: resolved-address
    /// enforcement is delegated entirely to Cloudflare. A valid-looking
    /// hostname string is **not** evidence of connect-time DNS policy
    /// enforcement, and this backend does not claim native-equivalent SSRF
    /// guarantees. Do not use it without the platform requirements above.
    ///
    /// Only [`AddressPolicy::DenyLocal`] is supported. `AllowAll` is rejected
    /// because mandated public-only routing cannot provide its local-address
    /// opt-in. `max_redirects` must be `None` or `Some(0)`: Worker requests use
    /// manual redirect handling and return the redirect as a non-success
    /// response rather than following it. HTTP remains opt-in through
    /// `allow_plaintext`, with the same loss of transport integrity as native.
    ///
    /// `timeout` is one total deadline covering fetch and streaming the body;
    /// expiry aborts the request. Workers does not expose a separate connection
    /// phase, so `connect_timeout` is conservatively enforced until response
    /// headers arrive; a slow server may time out after connecting. Timeouts
    /// above the Worker timer range are rejected.
    #[cfg(target_arch = "wasm32")]
    pub fn new_cloudflare(config: ClientConfig) -> Result<Self, Error> {
        let inner = crate::worker::CloudflareClient::new(&config)?;
        Ok(Self {
            inner,
            policy: config.policy,
            max_response_bytes: config.max_response_bytes,
            allow_plaintext: config.allow_plaintext,
        })
    }

    /// Fetch `url`, returning its status and bounded body for every HTTP status.
    ///
    /// Unlike [`Client::get_bytes`], this does not turn non-2xx statuses into
    /// [`Error::Status`]. Redirects are still governed by `max_redirects`; with
    /// the default configuration, the redirect response itself is returned.
    pub async fn get_response(&self, url: Url) -> Result<Response, Error> {
        self.fetch(url, false).await
    }

    /// Fetch `url`, returning the body, refusing redirects unless configured
    /// and refusing bodies over the configured cap.
    pub async fn get_bytes(&self, url: Url) -> Result<Vec<u8>, Error> {
        self.fetch(url, true).await.map(|response| response.body)
    }

    async fn fetch(&self, url: Url, require_success: bool) -> Result<Response, Error> {
        self.check_url(&url)?;

        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut response = self.inner.get(url.clone()).send().await?;
            let status = response.status();
            // Preserve get_bytes' status-before-body behavior. get_response
            // deliberately buffers non-success bodies as well.
            if require_success && !status.is_success() {
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
            Ok(Response {
                status: status.as_u16(),
                body,
            })
        }

        #[cfg(target_arch = "wasm32")]
        {
            self.inner
                .get(url, require_success, self.max_response_bytes)
                .await
        }
    }

    /// Parse and fetch in one step.
    pub async fn get(&self, url: &str) -> Result<Vec<u8>, Error> {
        self.get_bytes(Url::parse(url)?).await
    }

    /// Scheme and literal-host checks, applied to the initial request and to
    /// every redirect hop.
    ///
    /// The resolver hook only runs when a name has to be resolved. A URL whose
    /// host is already an IP literal never reaches it — reqwest connects
    /// straight to that address — so a guard built only on the resolver would
    /// happily fetch `http://127.0.0.1/` or `http://169.254.169.254/`. The
    /// literal has to be checked here, before the request exists.
    fn check_url(&self, url: &Url) -> Result<(), Error> {
        check_url(self.policy, self.allow_plaintext, url)
    }
}

/// Resolves a name and refuses the complete answer set if any address is blocked.
#[cfg(not(target_arch = "wasm32"))]
struct FilteredResolver {
    policy: AddressPolicy,
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_answer_set(
    policy: AddressPolicy,
    host: &str,
    addrs: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, std::io::Error> {
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("resolution returned no addresses for {host}"),
        ));
    }
    if let Some(addr) = addrs.iter().find(|addr| !policy.permits(addr.ip())) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("address policy refused {host}: resolved to {}", addr.ip()),
        ));
    }
    Ok(addrs)
}

#[cfg(not(target_arch = "wasm32"))]
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
            // Reject the complete answer set if any address is blocked rather
            // than filtering out blocked addresses and dialing the remainder.
            let addrs = validate_answer_set(policy, &host, addrs.collect())
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Scheme and literal-host rules, applied to the initial request and to every
/// redirect hop.
fn check_url(policy: AddressPolicy, allow_plaintext: bool, url: &Url) -> Result<(), Error> {
    match url.scheme() {
        "https" => {}
        "http" if allow_plaintext => {}
        other => {
            return Err(Error::Scheme {
                scheme: other.to_owned(),
            });
        }
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) => {
            if !policy.permits(IpAddr::V4(ip)) {
                return Err(Error::AddressRefused(ip.to_string()));
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if !policy.permits(IpAddr::V6(ip)) {
                return Err(Error::AddressRefused(ip.to_string()));
            }
        }
        // Hostnames are policy-checked at connect time by FilteredResolver.
        Some(url::Host::Domain(_)) => {}
        None => return Err(Error::AddressRefused(url.to_string())),
    }
    Ok(())
}

/// Error surfaced through reqwest when a redirect target is refused.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RedirectRefused(String);

#[cfg(test)]
mod tests {
    use super::*;

    fn check(policy: AddressPolicy, allow_plaintext: bool, raw: &str) -> Result<(), Error> {
        check_url(
            policy,
            allow_plaintext,
            &Url::parse(raw).expect("test URL parses"),
        )
    }

    #[test]
    fn allows_https_to_a_public_name() {
        assert!(check(AddressPolicy::DenyLocal, false, "https://example.com/a").is_ok());
    }

    #[test]
    fn refuses_plaintext_unless_opted_in() {
        assert!(matches!(
            check(AddressPolicy::DenyLocal, false, "http://example.com/"),
            Err(Error::Scheme { .. })
        ));
        assert!(check(AddressPolicy::DenyLocal, true, "http://example.com/").is_ok());
    }

    #[test]
    fn refuses_other_schemes() {
        assert!(matches!(
            check(AddressPolicy::AllowAll, true, "ftp://example.com/"),
            Err(Error::Scheme { .. })
        ));
    }

    #[test]
    fn refuses_literal_local_hosts_at_any_hop() {
        // These are the targets that a resolver hook never sees, which is why
        // the check has to happen on the URL itself.
        for url in [
            "https://127.0.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/",
            "https://[fd00:ec2::254]/",
            "https://100.64.0.1/",
        ] {
            assert!(
                matches!(
                    check(AddressPolicy::DenyLocal, false, url),
                    Err(Error::AddressRefused(_))
                ),
                "{url} must be refused"
            );
        }
    }

    #[test]
    fn permits_literal_local_hosts_only_on_opt_in() {
        assert!(check(AddressPolicy::AllowAll, false, "https://127.0.0.1/").is_ok());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn validates_complete_answer_sets() {
        let public: SocketAddr = "1.1.1.1:0".parse().unwrap();
        let private: SocketAddr = "10.0.0.1:0".parse().unwrap();
        assert!(validate_answer_set(AddressPolicy::DenyLocal, "example.com", vec![]).is_err());
        assert_eq!(
            validate_answer_set(AddressPolicy::DenyLocal, "example.com", vec![public]).unwrap(),
            vec![public]
        );
        for addrs in [vec![public, private], vec![private, public]] {
            assert!(
                validate_answer_set(AddressPolicy::DenyLocal, "example.com", addrs.clone())
                    .is_err()
            );
            assert_eq!(
                validate_answer_set(AddressPolicy::AllowAll, "example.com", addrs.clone()).unwrap(),
                addrs
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn refuses_an_answer_set_containing_any_blocked_address() {
        let public = "1.1.1.1:0".parse().expect("public address parses");
        let private = "10.0.0.1:0".parse().expect("private address parses");
        let err = validate_answer_set(
            AddressPolicy::DenyLocal,
            "example.com",
            vec![public, private],
        )
        .expect_err("a public fallback must not legitimize a blocked answer");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("10.0.0.1"),
            "error should name the blocked answer: {err}"
        );
    }
}
