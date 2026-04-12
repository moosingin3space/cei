# HTTP Proxy Implementation Spec

## Scope

This document specifies the first-pass network interception layer for `cei`: an
HTTP/CONNECT proxy running inside the supervisor process, reachable by sandboxed
processes via injected `http_proxy`/`https_proxy` environment variables.

This layer covers well-behaved processes only. It is designed to be implemented
and useful on its own, and to compose cleanly with the TUN layer when that is
added later.

---

## New Source Files

| File | Purpose |
|---|---|
| `src/proxy.rs` | Proxy listener task: accept loop, CONNECT handler, plain HTTP handler |
| `src/proxy_policy.rs` | `ProxyPolicy` trait + default `SandboxPolicy` impl |

`SandboxPolicy` in `src/policy.rs` gains a `network_allows` method. No other
existing files change structurally, though `src/main.rs` and `src/supervisor.rs`
gain wiring.

---

## Dependencies

Add to `Cargo.toml`:

```toml
tokio        = { version = "1",   features = ["full"] }
hyper        = { version = "1",   features = ["http1", "server"] }
hyper-util   = { version = "0.1", features = ["tokio"] }
http-body-util = "0.1"
```

No TLS dependency is required: the proxy tunnels HTTPS opaquely and never
terminates TLS itself.

---

## Lifecycle and Wiring

### Port allocation

The proxy binds to `127.0.0.1:0` (OS-assigned port) before the child is
forked. The assigned port is retrieved with `local_addr()` immediately after
`bind` and held in the supervisor until the child exits.

Using port 0 avoids hardcoded port conflicts and is safe because the proxy
address is communicated to the child through environment variables, not through
any fixed convention.

### Startup sequence

```
main
 │
 ├─ ProxyListener::bind("127.0.0.1:0")   ← before fork, port now known
 │
 ├─ fork()
 │    │
 │    ├─ [child]  inject_proxy_env(port) into envp, execvp target command
 │    │
 │    └─ [parent] tokio::spawn(proxy_listener.run(policy.clone()))
 │                supervisor.run_until_exit(child_pid)
 │
 └─ on child exit: supervisor shuts down; proxy task is dropped
```

The proxy task and the seccomp supervisor loop run concurrently in the same
tokio runtime. No shared mutable state is needed between them: both hold an
`Arc<SandboxPolicy>` and operate independently.

### Environment injection

In `child_main`, construct a new `envp` vec from the current environment,
replacing any existing proxy vars, then call `execvpe` instead of `execvp`:

```rust
fn build_proxy_env(port: u16) -> Vec<CString> {
    let proxy_url = format!("http://127.0.0.1:{port}");
    let no_proxy  = "no_proxy=localhost,127.0.0.1".to_string();

    // Collect current env, stripping any pre-existing proxy vars.
    let mut env: Vec<CString> = std::env::vars_os()
        .filter(|(k, _)| {
            !matches!(
                k.to_str().unwrap_or(""),
                "http_proxy" | "https_proxy" | "HTTP_PROXY" | "HTTPS_PROXY" | "no_proxy"
            )
        })
        .map(|(k, v)| {
            CString::new(format!("{}={}", k.to_string_lossy(), v.to_string_lossy()))
                .expect("env var contains NUL")
        })
        .collect();

    // Inject both cases; different tools check different conventions.
    for var in &["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
        env.push(CString::new(format!("{var}={proxy_url}")).unwrap());
    }
    env.push(CString::new(no_proxy).unwrap());
    env
}
```

`execvpe` is `nix::unistd::execvpe`, available in the `nix` crate with no new
feature flags beyond those already in use.

---

## Proxy Listener

### Accept loop

```rust
pub struct ProxyListener {
    listener: TcpListener,
}

impl ProxyListener {
    pub async fn bind(addr: &str) -> Result<Self> { ... }
    pub fn local_port(&self) -> u16 { ... }

    pub async fn run(self, policy: Arc<SandboxPolicy>) -> Result<()> {
        loop {
            let (stream, _peer) = self.listener.accept().await?;
            let policy = policy.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, policy).await {
                    eprintln!("[proxy] connection error: {e:#}");
                }
            });
        }
    }
}
```

Each connection is handled in its own task. The proxy never buffers request
bodies; it either tunnels or forwards them as streams.

### Connection handler

```rust
async fn handle_connection(stream: TcpStream, policy: Arc<SandboxPolicy>) -> Result<()> {
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .with_upgrades()          // required for CONNECT to work
        .serve_connection(io, service_fn(move |req| {
            let policy = policy.clone();
            async move { dispatch(req, policy).await }
        }))
        .await
        .map_err(Into::into)
}
```

`.with_upgrades()` is mandatory. Without it, `hyper::upgrade::on` returns an
error even for valid CONNECT requests.

### Dispatch

```rust
async fn dispatch(
    req: Request<Incoming>,
    policy: Arc<SandboxPolicy>,
) -> Result<Response<BoxBody>> {
    if req.method() == Method::CONNECT {
        handle_connect(req, policy).await
    } else {
        handle_plain_http(req, policy).await
    }
}
```

---

## CONNECT Handler

### Overview

```
client ──CONNECT host:port──► proxy
                               │ policy check
                               │ deny  ──► 403
                               │ allow ──► TCP connect to host:port
                               │           200 Connection Established
                               │           copy_bidirectional(client, origin)
```

### Implementation

```rust
async fn handle_connect(
    req: Request<Incoming>,
    policy: Arc<SandboxPolicy>,
) -> Result<Response<BoxBody>> {
    // Extract host:port from the request-target.
    let authority = req.uri().authority()
        .ok_or_else(|| anyhow!("CONNECT missing authority"))?
        .clone();

    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    // Policy check before attempting any outbound connection.
    if !policy.network_allows_connect(&host, port) {
        eprintln!("[proxy] deny CONNECT {host}:{port}");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(empty_body())
            .unwrap());
    }

    eprintln!("[proxy] allow CONNECT {host}:{port}");

    // Resolve and connect to the origin *before* sending 200,
    // so a connection failure returns a proper error to the client.
    let origin = TcpStream::connect((host.as_str(), port)).await
        .map_err(|e| anyhow!("upstream connect failed: {e}"))?;

    // Spawn the tunnel. hyper::upgrade::on will not resolve until
    // after we return the 200 response below.
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                let mut origin_io = origin;
                if let Err(e) = tokio::io::copy_bidirectional(
                    &mut client_io,
                    &mut origin_io,
                ).await {
                    eprintln!("[proxy] tunnel error {host}:{port}: {e}");
                }
            }
            Err(e) => eprintln!("[proxy] upgrade error: {e}"),
        }
    });

    // The 200 must be returned here to unblock the upgrade future above.
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .unwrap())
}
```

### Why connect before responding 200

Connecting to the origin before sending `200` means a refused or unreachable
upstream produces a `502 Bad Gateway` (or a logged error) rather than an
established tunnel that immediately closes. This gives the client a meaningful
error and avoids spawning unnecessary tasks.

### SNI inspection hook (future)

After the upgrade resolves, the first bytes from the client will be a TLS
`ClientHello` if the destination port is 443. To extract SNI, buffer the first
read before handing off to `copy_bidirectional`:

```rust
// Read the first chunk from the client side.
let mut buf = [0u8; 512];
let n = client_io.read(&mut buf).await?;
if let Some(sni) = parse_tls_sni(&buf[..n]) {
    // second policy check or audit log with actual SNI
}
// Write the buffered bytes to origin before entering the copy loop.
origin_io.write_all(&buf[..n]).await?;
tokio::io::copy_bidirectional(&mut client_io, &mut origin_io).await?;
```

This hook is not implemented in the first pass but the structure above is where
it slots in with minimal restructuring.

---

## Plain HTTP Handler

Plain HTTP requests (`http://` URLs) arrive with an absolute-form request URI.
The proxy must strip the URI back to origin-form before forwarding.

```rust
async fn handle_plain_http(
    mut req: Request<Incoming>,
    policy: Arc<SandboxPolicy>,
) -> Result<Response<BoxBody>> {
    let host = req.uri().host()
        .ok_or_else(|| anyhow!("plain HTTP request missing host"))?
        .to_string();
    let port = req.uri().port_u16().unwrap_or(80);

    if !policy.network_allows_connect(&host, port) {
        eprintln!("[proxy] deny HTTP {host}:{port}");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(empty_body())
            .unwrap());
    }

    // Rewrite to origin-form URI (strip scheme + authority).
    let path = req.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    *req.uri_mut() = path.parse()?;

    // Remove hop-by-hop headers.
    for header in &["proxy-connection", "proxy-authenticate",
                    "proxy-authorization", "te", "trailers",
                    "transfer-encoding", "upgrade"] {
        req.headers_mut().remove(*header);
    }

    let origin = TcpStream::connect((host.as_str(), port)).await?;
    let io = TokioIo::new(origin);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let resp = sender.send_request(req).await?;
    Ok(resp.map(|b| b.boxed()))
}
```

Plain HTTP is uncommon in practice (most tools use HTTPS for any non-local
destination) but is needed for `pip` over plain mirrors, `apt`, and some
internal tooling.

---

## Policy Interface

`SandboxPolicy` gains one new method, used by both the CONNECT and plain HTTP
handlers:

```rust
impl SandboxPolicy {
    /// Return true if the supervised process may open a connection to host:port.
    ///
    /// Called for both CONNECT (HTTPS) and plain HTTP requests.
    /// In the first pass, the default is to allow everything and log.
    pub fn network_allows_connect(&self, host: &str, port: u16) -> bool {
        eprintln!("[policy] network connect allowed: {host}:{port}");
        true
    }
}
```

The method signature is `bool` for the first pass. It will become
`NetworkVerdict` (as specified in `network_interception_design.md`) when deny
and rewrite cases are wired in. Keeping it `bool` now avoids committing to the
richer enum before the call sites are known.

---

## Error Handling

| Failure | Behaviour |
|---|---|
| Policy denies connection | `403 Forbidden`, connection closed |
| Origin TCP connect fails | `502 Bad Gateway`, connection closed |
| Tunnel I/O error after 200 | Logged, both sides closed; no response possible |
| Malformed CONNECT target | `400 Bad Request` |
| Plain HTTP parse error | `400 Bad Request` |

Tunnel errors after the `200` is sent cannot be reported to the client as HTTP
responses; logging is the only option.

---

## What This Does Not Cover

This spec intentionally excludes the following, all of which belong to later
passes:

- **TUN / smoltcp layer** for ill-behaved processes (specified in
  `network_interception_design.md`).
- **DNS interception**. Sandboxed processes resolve names through whatever
  resolver the host provides; no filtering is applied.
- **TLS SNI inspection**. The ClientHello hook is noted above but not
  implemented.
- **`no_proxy` enforcement on the proxy side**. The env var tells clients not
  to proxy loopback traffic; the proxy itself does not need to enforce this
  since loopback connections from the sandbox go directly to 127.0.0.1 and
  never reach the proxy.
- **Proxy authentication**. The listener is on loopback and only reachable from
  the sandbox; no auth is needed.
- **HTTP/2**. The hyper server is configured HTTP/1 only. HTTP/2 proxying via
  `CONNECT` uses a different framing (extended CONNECT, RFC 8441) and is out of
  scope.
- **Connection pooling** to upstream origins. Each proxied request opens a new
  TCP connection. This is adequate for CLI tool use.

---

## Testing Approach

The proxy can be tested without the full sandbox stack:

1. **Unit**: bind proxy on localhost, send a `CONNECT` request using a raw
   `TcpStream`, assert `200` response, write bytes through the tunnel, assert
   they arrive at a local echo server.
2. **Policy deny**: configure policy to deny a host, assert `403`.
3. **Integration**: run `curl -x http://127.0.0.1:{port} https://example.com`
   against the proxy with no sandbox; assert the request succeeds and is logged.
4. **Env injection**: verify that `build_proxy_env` strips pre-existing proxy
   vars and injects all four variants.
