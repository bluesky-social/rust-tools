# AGENTS.md

Rust workspace of two crates: `egress` (outbound HTTP with an address policy)
and `atproto-identity` (DID → PDS endpoint, built on `egress`).

Public repo. Nothing secrets-adjacent goes in here: no internal hostnames, no
service-specific configuration, no environment defaults pulled from our
infrastructure. If a change is only interesting to one internal service, it does
not belong here.

## Invariants

- `AddressPolicy::DenyLocal` stays the default. A change that lets a request
  reach a private address without an explicit opt-in is a bug, not a feature.
- Two checks, both required: the URL's literal host before the request is built,
  and the resolved addresses at connect time. Removing either re-opens an SSRF
  path (see the README).
- No redirects are followed unless the caller asks for them.
- Tests for the blocked-address table mirror the Go client's; keep them in step.

## Before pushing

```sh
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```
