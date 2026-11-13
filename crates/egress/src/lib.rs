//! Outbound HTTP for services that fetch URLs they did not choose.
//!
//! When a service fetches a URL derived from user input — a DID's `did:web`
//! host, a handle's well-known endpoint, an avatar URL from a record — the
//! request becomes an SSRF primitive unless the address it actually connects to
//! is checked. Hostname validation is not enough: a name can resolve to
//! loopback, and a redirect can re-point the request at an internal address.
//!
//! This crate makes the safe configuration the default one:
//!
//! - [`AddressPolicy::DenyLocal`] is the default. DNS answers are checked at
//!   connect time and rejected in full if any address is blocked. The connector
//!   dials only addresses that were checked, preventing DNS rebinding between
//!   check and connect.
//! - Redirects are **not** followed unless you ask for them, and when you do the
//!   policy is re-applied to every hop because each hop resolves again.
//! - Response bodies are capped, so a hostile server cannot stream forever.
//!
//! ```
//! # async fn run() -> Result<(), egress::Error> {
//! let client = egress::Client::new(egress::ClientConfig::default())?;
//! let body = client.get_bytes("https://plc.directory/did:plc:abc".parse()?).await?;
//! # Ok(()) }
//! ```
//!
//! The blocked-address set mirrors the Go client we use elsewhere
//! (`gttp`'s `isBlockedIP`), because two services on the same edge should not
//! disagree about what counts as "local".

pub mod client;
pub mod policy;

pub use client::{Client, ClientConfig, Error};
pub use policy::{is_blocked, AddressPolicy};
