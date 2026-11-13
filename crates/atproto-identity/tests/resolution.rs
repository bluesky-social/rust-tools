//! Resolution against a stand-in PLC directory.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use atproto_identity::{Did, Directory, DirectoryConfig};
use egress::AddressPolicy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const DOC: &str = r##"{"id":"did:plc:ewvi7nxzyoun6zhxrhs64oiz","alsoKnownAs":["at://alice.example.com"],"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example.com"}]}"##;

/// A PLC directory that answers any `did:plc:*` path with `DOC` and counts hits.
async fn plc(doc: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = socket.read(&mut buf).await;
                let body = doc;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (addr, hits)
}

fn directory(plc: SocketAddr) -> Directory {
    Directory::with_config(DirectoryConfig {
        plc_url: format!("http://{plc}/").parse().expect("url"),
        ttl: Duration::from_secs(60),
        capacity: 32,
        address_policy: AddressPolicy::AllowAll,
        timeout: Duration::from_secs(5),
        allow_plaintext: true,
    })
    .expect("directory builds")
}

#[tokio::test]
async fn resolves_pds_and_caches() {
    let (addr, hits) = plc(DOC).await;
    let dir = directory(addr);
    let did = Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").expect("did");

    assert_eq!(
        dir.lookup_pds(&did).await.expect("resolves"),
        "https://pds.example.com"
    );
    assert_eq!(
        dir.lookup_pds(&did).await.expect("resolves from cache"),
        "https://pds.example.com"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "second lookup must come from the cache"
    );
    assert_eq!(dir.len(), 1);
}

#[tokio::test]
async fn purge_forces_a_refetch() {
    let (addr, hits) = plc(DOC).await;
    let dir = directory(addr);
    let did = Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").expect("did");

    dir.lookup_did(&did).await.expect("first");
    dir.purge(&did);
    dir.lookup_did(&did).await.expect("second");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "purge must invalidate the entry"
    );
}

#[tokio::test]
async fn rejects_a_document_for_a_different_did() {
    let (addr, _) = plc(r##"{"id":"did:plc:someoneelse","service":[]}"##).await;
    let dir = directory(addr);
    let did = Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").expect("did");
    let err = dir.lookup_did(&did).await.expect_err("must reject");
    assert!(
        err.to_string().contains("does not match"),
        "unexpected: {err}"
    );
}

#[tokio::test]
async fn missing_pds_is_an_error() {
    let (addr, _) = plc(r##"{"id":"did:plc:ewvi7nxzyoun6zhxrhs64oiz","service":[]}"##).await;
    let dir = directory(addr);
    let did = Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").expect("did");
    let err = dir.lookup_pds(&did).await.expect_err("must reject");
    assert!(
        err.to_string().contains("no PDS endpoint"),
        "unexpected: {err}"
    );
}

#[tokio::test]
async fn denies_private_hosts_under_the_default_policy() {
    // The default policy must refuse a DID document served from loopback, which
    // is what a self-hosted resolver pointed at an internal address looks like.
    let (addr, _) = plc(DOC).await;
    let dir = Directory::with_config(DirectoryConfig {
        plc_url: format!("http://{addr}/").parse().expect("url"),
        address_policy: AddressPolicy::DenyLocal,
        allow_plaintext: true,
        ..DirectoryConfig::default()
    })
    .expect("directory builds");
    let did = Did::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz").expect("did");
    let err = dir.lookup_did(&did).await.expect_err("must refuse");
    let rendered = err.to_string();
    assert!(
        rendered.contains("refused") || rendered.contains("scheme"),
        "unexpected: {err}"
    );
}
