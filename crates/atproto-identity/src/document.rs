//! The parts of a DID document we use.

use std::collections::HashMap;

use serde::Deserialize;

use crate::did::Did;

/// A service entry from a DID document.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ServiceEndpoint {
    /// Service id, e.g. `#atproto_pds`.
    pub id: String,
    /// Service type, e.g. `AtprotoPersonalDataServer`.
    #[serde(rename = "type")]
    pub service_type: String,
    /// Where the service lives.
    #[serde(rename = "serviceEndpoint")]
    pub endpoint: String,
}

/// A resolved identity: its DID, its declared handle, and its services.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The DID this document was resolved for.
    pub did: Did,
    /// The handle the document declares, if any. Not verified against the
    /// handle's own resolution; use this to locate, not to authenticate.
    pub handle: Option<String>,
    /// Services keyed by id.
    pub services: HashMap<String, ServiceEndpoint>,
}

impl Identity {
    /// The account's PDS endpoint, from the `#atproto_pds` service.
    pub fn pds_endpoint(&self) -> Option<&str> {
        self.services
            .get("#atproto_pds")
            .map(|service| service.endpoint.as_str())
    }

    /// Build from a parsed document, keeping only services whose shape is
    /// usable.
    pub(crate) fn from_document(did: Did, doc: Document) -> Self {
        let handle = doc
            .also_known_as
            .iter()
            .find_map(|aka| aka.strip_prefix("at://").map(|h| h.to_owned()));
        let services = doc
            .service
            .into_iter()
            .map(|service| (service.id.clone(), service))
            .collect();
        Self {
            did,
            handle,
            services,
        }
    }
}

/// A DID document, as far as we care.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Document {
    /// Must match the DID that was resolved.
    pub id: String,
    #[serde(default, rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
    #[serde(default)]
    pub service: Vec<ServiceEndpoint>,
}

impl Document {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &[u8] = br##"{
      "id": "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
      "alsoKnownAs": ["at://alice.example.com"],
      "service": [
        {"id": "#atproto_pds", "type": "AtprotoPersonalDataServer",
         "serviceEndpoint": "https://pds.example.com"},
        {"id": "#atproto_labeler", "type": "AtprotoLabeler",
         "serviceEndpoint": "https://labeler.example.com"}
      ]
    }"##;

    #[test]
    fn extracts_pds_endpoint_and_handle() {
        let doc = Document::parse(DOC).unwrap();
        let identity =
            Identity::from_document(Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").unwrap(), doc);
        assert_eq!(identity.pds_endpoint(), Some("https://pds.example.com"));
        assert_eq!(identity.handle.as_deref(), Some("alice.example.com"));
        assert_eq!(identity.services.len(), 2);
    }

    #[test]
    fn missing_pds_is_none() {
        let doc = Document::parse(br#"{"id":"did:plc:abc","service":[]}"#).unwrap();
        let identity = Identity::from_document(Did::parse("did:plc:abc").unwrap(), doc);
        assert_eq!(identity.pds_endpoint(), None);
    }
}
