#![cfg(not(target_arch = "wasm32"))]

//! get_response preserves status codes without weakening any request or body
//! limits. get_bytes retains its pre-existing success-only behavior.

use std::net::SocketAddr;
use std::time::Duration;

use egress::{AddressPolicy, Client, ClientConfig, Error, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

fn client() -> Client {
    Client::new(ClientConfig {
        policy: AddressPolicy::AllowAll,
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        allow_plaintext: true,
        ..ClientConfig::default()
    })
    .expect("client builds")
}

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

fn url(addr: SocketAddr) -> Url {
    Url::parse(&format!("http://{addr}/")).expect("test URL parses")
}

#[tokio::test]
async fn get_response_preserves_non_success_status_and_body() {
    let addr = serve_once("HTTP/1.1 404 Not Found\r\ncontent-length: 7\r\n\r\nmissing").await;
    let response = client()
        .get_response(url(addr))
        .await
        .expect("404 is a response, not a transport error");
    assert_eq!(
        response,
        Response {
            status: 404,
            body: b"missing".to_vec(),
        }
    );
}

#[tokio::test]
async fn get_bytes_still_rejects_non_success_statuses() {
    let addr = serve_once("HTTP/1.1 404 Not Found\r\ncontent-length: 7\r\n\r\nmissing").await;
    let err = client()
        .get_bytes(url(addr))
        .await
        .expect_err("get_bytes remains success-only");
    assert!(matches!(err, Error::Status { status: 404, .. }));
}

#[tokio::test]
async fn get_response_leaves_redirects_unfollowed_by_default() {
    let target = serve_once("HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nsecret").await;
    let redirect =
        format!("HTTP/1.1 302 Found\r\nlocation: http://{target}/\r\ncontent-length: 0\r\n\r\n");
    let redirect: &'static str = Box::leak(redirect.into_boxed_str());
    let from = serve_once(redirect).await;

    let response = client()
        .get_response(url(from))
        .await
        .expect("manual redirect response is returned");
    assert_eq!(response.status, 302);
    assert!(response.body.is_empty());
}

#[tokio::test]
async fn get_response_enforces_the_cap_on_non_success_bodies() {
    let addr = serve_once("HTTP/1.1 503 Unavailable\r\ncontent-length: 1024\r\n\r\n").await;
    let client = Client::new(ClientConfig {
        policy: AddressPolicy::AllowAll,
        max_response_bytes: 8,
        allow_plaintext: true,
        ..ClientConfig::default()
    })
    .expect("client builds");
    let err = client
        .get_response(url(addr))
        .await
        .expect_err("oversized error body must be capped");
    assert!(matches!(err, Error::TooLarge(1024)));
}
