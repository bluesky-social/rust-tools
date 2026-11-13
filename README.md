# rust-tools

Rust libraries we build on. Small, focused, and safe by default.

Everything here is public because it is generally useful, not Blusky-specific
in any way that matters:

| crate | what it is |
|---|---|
| [`egress`](crates/egress) | Outbound HTTP for services that fetch **untrusted URLs**: native connect-time address policy (SSRF), bounded bodies, plaintext refused by default. |
| [`atproto-identity`](crates/atproto-identity) | [AT Protocol](https://atproto.com) identity resolution: DID → DID document → **PDS endpoint**, for `did:plc` and hostname-form `did:web`, with a TTL cache on top of `egress`. |

The pairing is deliberate. Resolving an identity means fetching a URL whose host
came from user input, which is the classic SSRF shape; `atproto-identity` is
useful mostly because `egress` makes that fetch safe.

```rust
let dir = atproto_identity::Directory::new();
let identity = dir.lookup_did(&atproto_identity::Did::parse("did:plc:…")?).await?;
println!("{:?}", identity.pds_endpoint());
```

## Why the address policy is not just a DNS hook

A guard that only filters resolved addresses has a hole: when a URL's host is
already an IP literal, there is nothing to resolve, so the resolver hook never
runs and the connection goes straight to that address. `http://127.0.0.1/` and
`http://169.254.169.254/` are the two most attractive SSRF targets there are.

On native targets, `egress` therefore checks twice: the URL's literal host
before the request exists, and every resolved address at connect time. The
second check is what makes it rebinding-safe — the addresses returned by the
resolver are the addresses the connector dials, so a second DNS answer cannot
redirect the connection. A DNS answer is rejected in full if any address is
blocked, even when it also contains public addresses. Redirects are off by
default. When enabled, **every hop is checked with the same rule as the first
URL** — scheme and literal host — because a redirect is a second,
attacker-chosen URL, and a public host can redirect straight to
`https://169.254.169.254/`.

The blocked set is the one our Go client uses, so two services behind the same
edge cannot disagree about what "local" means: loopback, RFC 1918, link-local
(including cloud metadata), multicast, unspecified, `0.0.0.0/8`, limited
broadcast, RFC 6598 CGNAT, IPv6 unique-local, and both NAT64 prefixes.

Residual risk, stated plainly: address filtering cannot defend against a
malicious recursive resolver that returns a globally routable address fronting
an internal host. Services resolving fully untrusted identities should also
restrict egress at the network layer.

Implicit proxies are disabled for the same reason: with `HTTP_PROXY` set, the
connection goes to the proxy and the proxy resolves the destination, so a
resolver hook never sees the address that is eventually fetched. There is also
no accessor for the underlying `reqwest::Client` — handing one out would skip the
URL checks and reintroduce the literal-host hole.

## Cloudflare Workers

The WebAssembly backend is an **explicit platform-trust opt-in**: the caller
must use Cloudflare Workers with `global_fetch_strictly_public` and only public
outbound routing. Unlike the native backend, Worker `fetch` does not expose a
connect-time DNS resolver or pin the checked IP. The Worker backend relies on
the platform for the connected address; it does not independently guarantee
that its resolved-address policy is identical to the native blocked-IP table.
Do not use it in a runtime that can reach private networks. `wrangler dev` may
allow local network access even where production Workers do not, so it is not
proof of the production egress policy.

Under their default policy, both backends refuse unsafe literal addresses and
limit response sizes. The Worker backend does not follow redirects. In a Worker,
construct the explicit client and pass it to the identity directory:

```rust
let client = egress::Client::new_cloudflare(egress::ClientConfig::default())?;
let directory = atproto_identity::Directory::with_client(
    atproto_identity::DirectoryConfig::default(),
    client.clone(),
);
```

`Directory::new` and `Default` are native-only; `Directory::with_config` returns
an error on WebAssembly rather than selecting a less restrictive backend.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```
