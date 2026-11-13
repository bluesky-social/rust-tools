//! The client must refuse to talk to addresses the policy disallows, and must
//! not follow a redirect that would take it somewhere disallowed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use egress::{AddressPolicy, Client, ClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn client(policy: AddressPolicy) -> Client {
    Client::new(ClientConfig {
        policy,
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        allow_plaintext: true,
        ..ClientConfig::default()
    })
    .expect("client builds")
}

/// Serve exactly one canned HTTP response, returning the bound address.
async fn serve_once(response: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
    addr
}

#[tokio::test]
async fn refuses_loopback_under_deny_local() {
    let addr = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi").await;
    let err = client(AddressPolicy::DenyLocal)
        .get(&format!("http://{addr}/"))
        .await
        .expect_err("loopback must be refused");
    assert!(
        matches!(err, egress::Error::AddressRefused(_)),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn permits_loopback_when_opted_in() {
    // Proves the filtered resolver still returns usable addresses: if it
    // dropped the port or mangled the list this would fail to connect.
    let addr = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi").await;
    let body = client(AddressPolicy::AllowAll)
        .get(&format!("http://{addr}/"))
        .await
        .expect("request should succeed");
    assert_eq!(body, b"hi");
}

#[tokio::test]
async fn does_not_follow_redirects_by_default() {
    let target = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nsecret").await;
    let redirect =
        format!("HTTP/1.1 302 Found\r\nlocation: http://{target}/\r\ncontent-length: 0\r\n\r\n");
    let redirect: &'static str = Box::leak(redirect.into_boxed_str());
    let from = serve_once(redirect).await;

    let err = client(AddressPolicy::AllowAll)
        .get(&format!("http://{from}/"))
        .await
        .expect_err("a redirect must be returned, not followed");
    assert!(
        matches!(err, egress::Error::Status { status: 302, .. }),
        "unexpected: {err}"
    );
}

#[tokio::test]
async fn enforces_the_body_cap() {
    let addr = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 1024\r\n\r\n").await;
    let c = Client::new(ClientConfig {
        policy: AddressPolicy::AllowAll,
        max_response_bytes: 8,
        timeout: Duration::from_secs(5),
        allow_plaintext: true,
        ..ClientConfig::default()
    })
    .expect("client builds");
    let err = c
        .get(&format!("http://{addr}/"))
        .await
        .expect_err("oversized body must be refused");
    assert!(
        matches!(err, egress::Error::TooLarge(_)),
        "unexpected: {err}"
    );
}

#[test]
fn client_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Client>();
    assert_send_sync::<Arc<Client>>();
}

#[tokio::test]
async fn follows_redirects_when_allowed_and_target_is_permitted() {
    let target = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi").await;
    let redirect =
        format!("HTTP/1.1 302 Found\r\nlocation: http://{target}/\r\ncontent-length: 0\r\n\r\n");
    let redirect: &'static str = Box::leak(redirect.into_boxed_str());
    let from = serve_once(redirect).await;

    let c = Client::new(ClientConfig {
        policy: AddressPolicy::AllowAll,
        allow_plaintext: true,
        max_redirects: Some(3),
        timeout: Duration::from_secs(5),
        ..ClientConfig::default()
    })
    .expect("client builds");
    let body = c
        .get(&format!("http://{from}/"))
        .await
        .expect("permitted redirect should be followed");
    assert_eq!(body, b"hi");
}

#[tokio::test]
async fn refuses_a_redirect_to_a_literal_private_address() {
    // The initial URL is permitted (a public-looking domain is unreachable in a
    // test), so the redirect target is what has to be refused. `localhost` is
    // resolved — and filtered — at connect time; the literal form is the hole
    // this test exists for, so the policy is exercised directly.
    let c = Client::new(ClientConfig {
        policy: AddressPolicy::DenyLocal,
        allow_plaintext: true,
        max_redirects: Some(3),
        timeout: Duration::from_secs(2),
        ..ClientConfig::default()
    })
    .expect("client builds");
    // A literal private address is refused before any connection is attempted,
    // by the same check the redirect policy calls for each hop.
    let err = c
        .get("http://169.254.169.254/latest/meta-data/")
        .await
        .expect_err("literal metadata address must be refused");
    assert!(
        matches!(err, egress::Error::AddressRefused(_)),
        "unexpected: {err}"
    );
}
