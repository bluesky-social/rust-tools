//! DID parsing, limited to the methods we resolve.

use std::fmt;

/// A DID in one of the methods this crate can resolve.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Did(String);

/// Why a string is not a resolvable DID.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DidError {
    #[error("not a DID: {0}")]
    NotADid(String),
    #[error("unsupported DID method: {0}")]
    UnsupportedMethod(String),
    #[error("invalid DID: {0}")]
    Invalid(String),
}

impl Did {
    /// Parse a `did:plc:` or hostname-form `did:web:` identifier.
    pub fn parse(input: &str) -> Result<Self, DidError> {
        let mut parts = input.splitn(3, ':');
        if parts.next() != Some("did") {
            return Err(DidError::NotADid(input.to_owned()));
        }
        let method = parts
            .next()
            .ok_or_else(|| DidError::NotADid(input.to_owned()))?;
        let rest = parts
            .next()
            .ok_or_else(|| DidError::NotADid(input.to_owned()))?;
        if rest.is_empty() {
            return Err(DidError::Invalid(input.to_owned()));
        }
        match method {
            "plc" => {
                // PLC identifiers are 24 lowercase base32 characters. Accept any
                // non-empty alphanumeric run here: the directory is authoritative
                // about whether the identifier exists, and being stricter than
                // that would break on future lengths.
                if !rest
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                {
                    return Err(DidError::Invalid(input.to_owned()));
                }
            }
            "web" => {
                // Hostname form only: `did:web:example.com`. Path form
                // (`did:web:example.com:user:alice`) is deliberately unsupported
                // because the path segments become URL components, and supporting
                // it means supporting a second encoding of untrusted input into a
                // URL for no benefit to us.
                if rest.contains(':') {
                    return Err(DidError::Invalid(input.to_owned()));
                }
                if !rest
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                {
                    return Err(DidError::Invalid(input.to_owned()));
                }
            }
            other => return Err(DidError::UnsupportedMethod(other.to_owned())),
        }
        Ok(Self(input.to_owned()))
    }

    /// The full DID.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The DID method (`plc`, `web`).
    pub fn method(&self) -> &str {
        self.0.split(':').nth(1).unwrap_or_default()
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_methods() {
        assert_eq!(
            Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz")
                .unwrap()
                .method(),
            "plc"
        );
        assert_eq!(Did::parse("did:web:example.com").unwrap().method(), "web");
    }

    #[test]
    fn rejects_unsupported_and_malformed() {
        assert!(matches!(
            Did::parse("did:key:z6Mk"),
            Err(DidError::UnsupportedMethod(_))
        ));
        assert!(matches!(
            Did::parse("https://example.com"),
            Err(DidError::NotADid(_))
        ));
        assert!(matches!(
            Did::parse("did:plc:"),
            Err(DidError::NotADid(_)) | Err(DidError::Invalid(_))
        ));
        assert!(matches!(
            Did::parse("did:web:example.com:user:alice"),
            Err(DidError::Invalid(_))
        ));
        assert!(matches!(
            Did::parse("did:web:example.com/../x"),
            Err(DidError::Invalid(_))
        ));
        assert!(matches!(
            Did::parse("did:plc:UPPER"),
            Err(DidError::Invalid(_))
        ));
    }
}
