use std::sync::Arc;

use anyhow::{Result, anyhow};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::policy::SandboxPolicy;

pub struct ProxyListener {
    listener: TcpListener,
}

impl ProxyListener {
    pub async fn bind(addr: &str) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener })
    }

    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.listener.local_addr().map_err(Into::into)
    }

    pub async fn run(self, policy: Arc<SandboxPolicy>) -> Result<()> {
        info!(addr = %self.local_addr()?, "proxy listener started");
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let policy = policy.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, policy).await {
                    error!(peer = %peer, "proxy connection error: {e:#}");
                }
            });
        }
    }
}

async fn handle_connection(stream: TcpStream, policy: Arc<SandboxPolicy>) -> Result<()> {
    let io = TokioIo::new(stream);
    let mut builder = http1::Builder::new();
    builder.preserve_header_case(true);
    builder.title_case_headers(true);
    // Try to find with_upgrades. If it's not there, it might be a version issue.
    // In hyper 1.0, it should be on the builder.
    builder
        .serve_connection(
            io,
            service_fn(move |req| {
                let policy = policy.clone();
                async move { dispatch(req, policy).await }
            }),
        )
        .with_upgrades()
        .await
        .map_err(Into::into)
}

async fn dispatch(
    req: Request<Incoming>,
    policy: Arc<SandboxPolicy>,
) -> Result<Response<BoxBody<Bytes, anyhow::Error>>> {
    if req.method() == Method::CONNECT {
        handle_connect(req, policy).await
    } else {
        handle_plain_http(req, policy).await
    }
}

async fn handle_connect(
    req: Request<Incoming>,
    policy: Arc<SandboxPolicy>,
) -> Result<Response<BoxBody<Bytes, anyhow::Error>>> {
    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| anyhow!("CONNECT missing authority"))?
        .clone();

    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    if !policy.network_allows_connect(&host, port) {
        warn!(host, port, "deny CONNECT");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(empty_body())
            .unwrap());
    }

    info!(host, port, "allow CONNECT");

    let origin = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| anyhow!("upstream connect failed: {e}"))?;

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                let mut origin_io = origin;
                if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut origin_io).await
                {
                    error!(host, port, "tunnel error: {e}");
                }
            }
            Err(e) => error!(host, port, "upgrade error: {e}"),
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .unwrap())
}

async fn handle_plain_http(
    mut req: Request<Incoming>,
    policy: Arc<SandboxPolicy>,
) -> Result<Response<BoxBody<Bytes, anyhow::Error>>> {
    let host = req
        .uri()
        .host()
        .ok_or_else(|| anyhow!("plain HTTP request missing host"))?
        .to_string();
    let port = req.uri().port_u16().unwrap_or(80);

    if !policy.network_allows_connect(&host, port) {
        warn!(host, port, "deny HTTP");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(empty_body())
            .unwrap());
    }

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    *req.uri_mut() = path.parse()?;

    for header in &[
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ] {
        req.headers_mut().remove(*header);
    }

    let origin = TcpStream::connect((host.as_str(), port)).await?;
    let io = TokioIo::new(origin);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let resp = sender.send_request(req).await?;
    Ok(resp.map(|b| b.map_err(anyhow::Error::from).boxed()))
}

fn empty_body() -> BoxBody<Bytes, anyhow::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
