//! AT Protocol identity resolution.
//!
//! A DID document says where an account's data lives: the `#atproto_pds`
//! service endpoint is the PDS that serves it. This crate resolves a DID to
//! that endpoint, which is the first step in fetching any of its blobs.
//!
//! ```no_run
//! # async fn run() -> Result<(), atproto_identity::Error> {
//! let dir = atproto_identity::Directory::new();
//! let did = atproto_identity::Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz")?;
//! let identity = dir.lookup_did(&did).await?;
//! println!("{:?}", identity.pds_endpoint());
//! # Ok(()) }
//! ```
//!
//! Supports `did:plc` (through the PLC directory) and hostname-form `did:web`.
//! Resolution goes through [`egress`], so a DID document hosted on a private
//! address is refused, and so is a redirect that tries to reach one.

mod did;
mod directory;
mod document;

pub use did::{Did, DidError};
pub use directory::{Directory, DirectoryConfig, Error};
pub use document::{Identity, ServiceEndpoint};
