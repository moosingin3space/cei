use std::sync::Arc;

use anyhow::Result;
use cei::policy::SandboxPolicy;
use cei::proxy::ProxyListener;
use http_body_util::BodyExt;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
#[ntest::timeout(10_000)]
async fn test_proxy_connect_allow() -> Result<()> {
    // 1. Setup a dummy target server (echo server)
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;
    let target_port = target_addr.port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = target_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    stream.write_all(&buf[..n]).await.unwrap();
                }
            });
        }
    });

    // 2. Setup the proxy with the target host in allowlist
    let mut policy = SandboxPolicy::from_current_dir()?;
    policy = policy.with_allowed_host("127.0.0.1");
    let proxy_listener = ProxyListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;

    tokio::spawn(async move {
        proxy_listener.run(Arc::new(policy)).await.unwrap();
    });

    // 3. Client: Send CONNECT request to proxy
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let authority = format!("127.0.0.1:{}", target_port);
    let req = format!("CONNECT {0} HTTP/1.1\r\nHost: {0}\r\n\r\n", authority);
    stream.write_all(req.as_bytes()).await?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let resp_str = String::from_utf8_lossy(&buf[..n]);
    assert!(resp_str.contains("HTTP/1.1 200 OK"));

    // 4. Tunnel bytes
    let msg = b"hello proxy";
    stream.write_all(msg).await?;
    let mut buf = [0u8; 11];
    stream.read_exact(&mut buf).await?;
    assert_eq!(&buf, msg);

    Ok(())
}

#[tokio::test]
#[ntest::timeout(10_000)]
async fn test_proxy_connect_deny() -> Result<()> {
    // 1. Setup proxy with a different host in allowlist
    let mut policy = SandboxPolicy::from_current_dir()?;
    policy = policy.with_allowed_host("example.com");
    let proxy_listener = ProxyListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;

    tokio::spawn(async move {
        proxy_listener.run(Arc::new(policy)).await.unwrap();
    });

    // 2. Client: Send CONNECT request to proxy for a different host
    let stream = TcpStream::connect(proxy_addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let authority = "127.0.0.1:80";
    let req = Request::builder()
        .method("CONNECT")
        .uri(authority)
        .header("Host", authority)
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;

    let resp = sender.send_request(req).await?;
    assert_eq!(resp.status(), hyper::StatusCode::FORBIDDEN);

    Ok(())
}

#[tokio::test]
#[ntest::timeout(10_000)]
async fn test_proxy_plain_http_allow() -> Result<()> {
    // 1. Setup a dummy HTTP target server
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;
    let target_port = target_addr.port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = target_listener.accept().await {
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        hyper::service::service_fn(|_req| async {
                            Ok::<_, anyhow::Error>(hyper::Response::new(http_body_util::Full::new(
                                hyper::body::Bytes::from("hello from target"),
                            )))
                        }),
                    )
                    .await
                    .unwrap();
            });
        }
    });

    // 2. Setup the proxy with the target host in allowlist
    let mut policy = SandboxPolicy::from_current_dir()?;
    policy = policy.with_allowed_host("127.0.0.1");
    let proxy_listener = ProxyListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;

    tokio::spawn(async move {
        proxy_listener.run(Arc::new(policy)).await.unwrap();
    });

    // 3. Client: Send plain HTTP request via proxy
    let stream = TcpStream::connect(proxy_addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let authority = format!("127.0.0.1:{}", target_port);
    let req = Request::builder()
        .uri(format!("http://{}/", authority))
        .header("Host", &authority)
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;

    let resp = sender.send_request(req).await?;
    assert_eq!(resp.status(), hyper::StatusCode::OK);

    let body = resp.collect().await?.to_bytes();
    assert_eq!(body, "hello from target");

    Ok(())
}

#[tokio::test]
#[ntest::timeout(10_000)]
async fn test_proxy_https_allow() -> Result<()> {
    use std::sync::Arc;
    use tokio_rustls::rustls;

    // 1. Generate self-signed cert for target server
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der).into(),
        )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    // 2. Setup HTTPS target server
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;
    let target_port = target_addr.port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = target_listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let stream = acceptor.accept(stream).await.unwrap();
                let io = TokioIo::new(stream);
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        hyper::service::service_fn(|_req| async {
                            Ok::<_, anyhow::Error>(hyper::Response::new(http_body_util::Full::new(
                                hyper::body::Bytes::from("hello from https target"),
                            )))
                        }),
                    )
                    .await
                    .unwrap();
            });
        }
    });

    // 3. Setup proxy with target host in allowlist
    let mut policy = SandboxPolicy::from_current_dir()?;
    policy = policy.with_allowed_host("127.0.0.1");
    let proxy_listener = ProxyListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;

    tokio::spawn(async move {
        proxy_listener.run(Arc::new(policy)).await.unwrap();
    });

    // 4. Client: Connect to proxy and send CONNECT
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let authority = format!("127.0.0.1:{}", target_port);
    let connect_req = format!("CONNECT {0} HTTP/1.1\r\nHost: {0}\r\n\r\n", authority);
    stream.write_all(connect_req.as_bytes()).await?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    assert!(String::from_utf8_lossy(&buf[..n]).contains("HTTP/1.1 200 OK"));

    // 5. Upgrade and TLS handshake over the tunnel
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(rustls::pki_types::CertificateDer::from(cert_der))?;
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1")?.to_owned();
    let tls_stream = connector.connect(server_name, stream).await?;

    // 6. Send HTTPS request over TLS tunnel
    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let req = Request::builder()
        .uri(format!("https://{}/", authority))
        .header("Host", &authority)
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;

    let resp = sender.send_request(req).await?;
    assert_eq!(resp.status(), hyper::StatusCode::OK);

    let body = resp.collect().await?.to_bytes();
    assert_eq!(body, "hello from https target");

    Ok(())
}

#[tokio::test]
#[ntest::timeout(10_000)]
async fn test_proxy_reject_http2() -> Result<()> {
    // 1. Setup proxy
    let policy = SandboxPolicy::from_current_dir()?;
    let proxy_listener = ProxyListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;

    tokio::spawn(async move {
        proxy_listener.run(Arc::new(policy)).await.unwrap();
    });

    // 2. Client: Send HTTP/2 connection preface (RFC 7540)
    let mut stream = TcpStream::connect(proxy_addr).await?;
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    stream.write_all(preface).await?;

    // 3. Assert the proxy either returns an error or closes the connection.
    // An HTTP/1.1 parser receiving this will typically respond with a 400
    // or simply drop the connection due to the malformed request.
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;

    if n > 0 {
        let resp_str = String::from_utf8_lossy(&buf[..n]);
        // hyper's http1 parser usually returns 400 Bad Request for this.
        assert!(resp_str.contains("400 Bad Request"));
    } else {
        // Or it closed the connection immediately.
        assert_eq!(n, 0);
    }

    Ok(())
}
