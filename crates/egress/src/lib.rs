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
//! - [`AddressPolicy::DenyLocal`] is the default. In the native backend, DNS
//!   answers are checked at connect time and rejected in full if any address is
//!   blocked. The connector dials only addresses that were checked, preventing
//!   DNS rebinding between check and connect.
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
//!
//! # Cloudflare Workers
//!
//! Ordinary `Client::new` fails closed on `wasm32`. The explicit
//! `Client::new_cloudflare` constructor is available there only for callers
//! running in Cloudflare Workers with `global_fetch_strictly_public` and
//! public-only outbound routing. Rust still enforces schemes and literal-IP
//! policy, but only Cloudflare can enforce policy on resolved addresses in that
//! environment. Hostname validation is not a substitute for that platform
//! guarantee; see the constructor's full documentation before opting in.

pub mod client;
pub mod policy;
#[cfg(any(test, target_arch = "wasm32"))]
mod worker;

pub use client::{Client, ClientConfig, Error, Response};
pub use policy::{is_blocked, AddressPolicy};
