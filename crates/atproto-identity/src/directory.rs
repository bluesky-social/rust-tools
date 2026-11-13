//! Resolving DIDs to identities, with a small cache.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egress::{AddressPolicy, Client, ClientConfig};
use url::Url;

use crate::did::{Did, DidError};
use crate::document::{Document, Identity};

/// Resolution failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid DID: {0}")]
    Did(#[from] DidError),
    #[error("invalid endpoint URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("egress failed: {0}")]
    Egress(#[from] egress::Error),
    #[error("DID document was not JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("DID document id {found} does not match requested {requested}")]
    Mismatch { requested: String, found: String },
    #[error("no PDS endpoint in the DID document for {0}")]
    NoPds(String),
}

/// How a [`Directory`] behaves.
#[derive(Debug, Clone)]
pub struct DirectoryConfig {
    /// PLC directory base URL. Defaults to the public one.
    pub plc_url: Url,
    /// How long a resolved identity stays fresh.
    pub ttl: Duration,
    /// Maximum number of cached identities.
    pub capacity: usize,
    /// Addresses resolution may connect to. Defaults to `DenyLocal`; only
    /// relax it for tests and local development.
    pub address_policy: AddressPolicy,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Permit `http://` PLC endpoints. Off by default; only for tests and
    /// local development, where a plaintext stand-in directory is convenient.
    pub allow_plaintext: bool,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            plc_url: Url::parse("https://plc.directory").expect("literal URL"),
            ttl: Duration::from_secs(300),
            capacity: 10_000,
            address_policy: AddressPolicy::DenyLocal,
            timeout: Duration::from_secs(10),
            allow_plaintext: false,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    identity: Arc<Identity>,
    expires_at: Instant,
    generation: u64,
}

/// Resolves DIDs and caches the results.
///
/// The cache is per-instance and in-process; it holds resolved identities only,
/// never request bodies. `purge` drops one entry, for when a caller learns a
/// DID moved or was taken down and does not want to wait out the TTL.
#[derive(Debug)]
pub struct Directory {
    plc_url: Url,
    client: Client,
    ttl: Duration,
    capacity: usize,
    cache: Mutex<HashMap<Did, Entry>>,
    generation: AtomicU64,
}

impl Directory {
    /// A directory pointed at the public PLC directory with the default policy.
    pub fn new() -> Self {
        Self::with_config(DirectoryConfig::default()).expect("default client builds")
    }

    /// A directory with explicit configuration.
    pub fn with_config(config: DirectoryConfig) -> Result<Self, Error> {
        let client = Client::new(ClientConfig {
            policy: config.address_policy,
            timeout: config.timeout,
            allow_plaintext: config.allow_plaintext,
            ..ClientConfig::default()
        })?;
        Ok(Self {
            plc_url: config.plc_url,
            client,
            ttl: config.ttl,
            capacity: config.capacity.max(1),
            cache: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
        })
    }

    /// Resolve a DID, using the cache when the entry is still fresh.
    pub async fn lookup_did(&self, did: &Did) -> Result<Arc<Identity>, Error> {
        let generation = self.generation.load(Ordering::Relaxed);
        if let Some(hit) = self.cached(did, generation) {
            return Ok(hit);
        }
        let identity = Arc::new(self.resolve(did).await?);
        self.store(did.clone(), identity.clone(), generation);
        Ok(identity)
    }

    /// Resolve a DID and return its PDS endpoint.
    pub async fn lookup_pds(&self, did: &Did) -> Result<String, Error> {
        let identity = self.lookup_did(did).await?;
        identity
            .pds_endpoint()
            .map(|endpoint| endpoint.to_owned())
            .ok_or_else(|| Error::NoPds(did.to_string()))
    }

    /// Drop a cached identity immediately.
    pub fn purge(&self, did: &Did) {
        self.cache.lock().expect("directory cache lock").remove(did);
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of cached identities. Intended for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.cache.lock().expect("directory cache lock").len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn cached(&self, did: &Did, generation: u64) -> Option<Arc<Identity>> {
        let cache = self.cache.lock().expect("directory cache lock");
        let entry = cache.get(did)?;
        if entry.expires_at <= Instant::now() || entry.generation != generation {
            None
        } else {
            Some(entry.identity.clone())
        }
    }

    fn store(&self, did: Did, identity: Arc<Identity>, generation: u64) {
        let mut cache = self.cache.lock().expect("directory cache lock");
        if cache.len() >= self.capacity && !cache.contains_key(&did) {
            // Evict an arbitrary expired entry if there is one; otherwise drop
            // the first key. The cache is an optimisation, not a correctness
            // mechanism, so a simple policy is enough.
            let now = Instant::now();
            let expired = cache
                .iter()
                .find(|(_, entry)| entry.expires_at <= now)
                .map(|(key, _)| key.clone());
            match expired {
                Some(key) => {
                    cache.remove(&key);
                }
                None => {
                    if let Some(key) = cache.keys().next().cloned() {
                        cache.remove(&key);
                    }
                }
            }
        }
        cache.insert(
            did,
            Entry {
                identity,
                expires_at: Instant::now() + self.ttl,
                generation,
            },
        );
    }

    async fn resolve(&self, did: &Did) -> Result<Identity, Error> {
        let document_url = self.document_url(did)?;
        let bytes = self.client.get_bytes(document_url).await?;
        let document = Document::parse(&bytes)?;
        if document.id != did.as_str() {
            return Err(Error::Mismatch {
                requested: did.to_string(),
                found: document.id,
            });
        }
        Ok(Identity::from_document(did.clone(), document))
    }

    /// Where the DID document for `did` lives.
    fn document_url(&self, did: &Did) -> Result<Url, Error> {
        let url = match did.method() {
            "plc" => {
                let mut url = self.plc_url.clone();
                // `did:plc:abc` -> `{plc}/did:plc:abc`: one path segment holding
                // the whole DID. Splitting on ':' would produce
                // `{plc}/did/plc/abc`, which is a 404 — the colons are part of
                // the identifier, not separators.
                url.path_segments_mut()
                    .map_err(|_| Error::Url(url::ParseError::RelativeUrlWithCannotBeABaseBase))?
                    .pop_if_empty()
                    .push(did.as_str());
                url
            }
            "web" => {
                let host = did.as_str().trim_start_matches("did:web:");
                Url::parse(&format!("https://{host}/.well-known/did.json"))?
            }
            other => return Err(Error::Did(DidError::UnsupportedMethod(other.to_owned()))),
        };
        Ok(url)
    }
}

impl Default for Directory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> Directory {
        Directory::with_config(DirectoryConfig {
            plc_url: Url::parse("https://plc.directory").unwrap(),
            ..DirectoryConfig::default()
        })
        .expect("directory builds")
    }

    #[test]
    fn plc_document_url_keeps_the_did_as_one_segment() {
        let did = Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").unwrap();
        assert_eq!(
            dir().document_url(&did).unwrap().as_str(),
            "https://plc.directory/did:plc:ewvi7nxzyoun6zhxrhs64oiz"
        );
    }

    #[test]
    fn custom_plc_base_keeps_its_path() {
        let mut d = dir();
        d.plc_url = Url::parse("https://plc.internal.example/directory/").unwrap();
        let did = Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").unwrap();
        assert_eq!(
            d.document_url(&did).unwrap().as_str(),
            "https://plc.internal.example/directory/did:plc:ewvi7nxzyoun6zhxrhs64oiz"
        );
    }

    #[test]
    fn web_document_url_uses_well_known() {
        let did = Did::parse("did:web:example.com").unwrap();
        assert_eq!(
            dir().document_url(&did).unwrap().as_str(),
            "https://example.com/.well-known/did.json"
        );
    }
}
