# TUN/smoltcp Network Interception Layer

## Motivation

The current `slirp4netns` integration provides network namespace bridging but
offers no enforcement: the sandbox can reach arbitrary internet destinations by
bypassing the `http_proxy` environment variable.  Any process that opens a raw
TCP socket, uses UDP, or simply ignores the proxy env will transact directly with
the internet.

This spec replaces `slirp4netns` with a supervisor-owned TUN device backed by
the `smoltcp` userspace TCP/IP stack.  Because all sandbox traffic must traverse
the TUN fd, the supervisor sees every packet before it leaves the namespace and
can enforce policy at L3/L4 — rejecting non-proxy destinations with a TCP RST
rather than silently forwarding them.

---

## Goals

- **Hard enforcement**: connections not destined for the supervisor's proxy are
  rejected with RST before any data leaves the host.
- **No external process**: eliminate the `slirp4netns` subprocess and its
  associated lifecycle management.
- **No address conflicts**: gateway uses an IPv4 link-local address
  (`169.254.0.1`) that cannot clash with any project's own network topology.
  `http_proxy`/`https_proxy` env vars and the proxy port are unchanged.
- **Splice fast-path**: data relayed between the real upstream socket and the
  proxy handler is moved in-kernel via `splice(2)`, avoiding a userspace copy on
  the hot path.

---

## Out of Scope

- DNS interception (block all UDP for now; DNS via DoH through the HTTP proxy is
  sufficient for well-behaved tools)
- TLS SNI inspection (handled at the existing proxy layer)
- IPv6 routing (the TUN uses IPv4 link-local; full IPv6 forwarding is a later concern)
- UDP policy (all UDP is dropped at the smoltcp layer for this pass)
- Any change to `proxy.rs` — it remains unmodified

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  sandbox network namespace (bwrap)                   │
│                                                      │
│  ┌─────────────────┐                                 │
│  │  sandboxed proc │                                 │
│  └────────┬────────┘                                 │
│           │  TCP connect 169.254.0.1:PROXY_PORT       │
│  ┌────────▼────────┐                                 │
│  │  kernel TCP/IP  │                                 │
│  └────────┬────────┘                                 │
│           │  IP packets                              │
│  ┌────────▼────────┐                                 │
│  │     tun0        │  (L3 TUN device, IFF_NO_PI)     │
│  └────────┬────────┘                                 │
└───────────│──────────────────────────────────────────┘
            │  fd: raw IP packets
┌───────────▼──────────────────────────────────────────┐
│  supervisor process (host namespace)                 │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │  smoltcp interface (Medium::Ip, 169.254.0.1/30)   │
│  │                                              │    │
│  │  Policy:                                     │    │
│  │   dst == 169.254.0.1:PROXY_PORT → accept     │    │
│  │   all other TCP                  → RST        │    │
│  │   all UDP/ICMP                   → drop       │    │
│  └──────────────────────────────────────────────┘    │
│            │                                         │
│            │  smoltcp TcpSocket (recv/send buffers)  │
│            │                                         │
│  ┌─────────▼──────────┐  socketpair                  │
│  │  TUN relay task    ├────────────►  socketpair[0]  │
│  └────────────────────┘  (AF_UNIX,                   │
│                           SOCK_STREAM)                │
│                                         │             │
│                           ┌────────────▼───────────┐ │
│                           │    proxy.rs handler    │ │
│                           │  (unmodified: CONNECT, │ │
│                           │   plain HTTP, policy)  │ │
│                           └────────────┬───────────┘ │
│                                        │             │
│                    splice(2) fast-path │             │
│                                        │             │
│                           ┌────────────▼───────────┐ │
│                           │   upstream TCP socket  │ │
│                           └────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

---

## Network Topology

IPv4 link-local addresses (RFC 3927, `169.254.0.0/16`) are used for the TUN
point-to-point link.  Link-local addresses are reserved and will never appear in
any project's real network topology, eliminating the address-conflict risk that
exists with RFC 1918 ranges like `10.0.2.x` (used by QEMU/KVM by default).

A `/30` subnet is used — the minimal allocation for a two-endpoint link.

| Address | Role |
|---|---|
| `169.254.0.1/30` | gateway; smoltcp interface address on the supervisor side |
| `169.254.0.2/30` | sandbox's `tun0` address |
| `169.254.0.1:PROXY_PORT` | the HTTP/CONNECT proxy endpoint |

The sandbox's routing table after TUN setup:
```
169.254.0.0/30  dev tun0  scope link
default         via 169.254.0.1  dev tun0
```

All outbound traffic — whether destined for `169.254.0.1` or any other address —
takes the default route through `tun0` and lands in smoltcp.

### Address constants

```rust
// src/tun.rs
pub const TUN_GATEWAY_IP:   [u8; 4] = [169, 254, 0, 1];
pub const TUN_SANDBOX_IP:   [u8; 4] = [169, 254, 0, 2];
pub const TUN_PREFIX_LEN:   u8      = 30;
```

These replace the former `SLIRP_HOST_IP = "10.0.2.2"` constant in `launch.rs`.

---

## TUN Device Creation

The TUN device must exist inside the sandbox's network namespace but its fd must
be held by the supervisor in the host namespace.  This is possible because a TUN
fd remains valid after `setns` restores the calling thread to its original
namespace.

### Sequence (in `setup_tun`)

```rust
/// Create a TUN device inside the sandbox network namespace and configure it.
/// Returns the TUN fd, which must be held open for the lifetime of the sandbox.
fn setup_tun(sandbox_pid: u32) -> Result<OwnedFd> {
    // 1. Save current network namespace.
    let orig_netns = File::open("/proc/self/ns/net")
        .context("opening host netns")?;

    // 2. Enter the sandbox's network namespace.
    let sandbox_netns_path = format!("/proc/{sandbox_pid}/ns/net");
    let sandbox_netns = File::open(&sandbox_netns_path)
        .context("opening sandbox netns")?;
    nix::sched::setns(sandbox_netns.as_fd(), nix::sched::CloneFlags::CLONE_NEWNET)
        .context("setns into sandbox netns")?;

    // 3. Open the TUN device inside that namespace.
    let tun_fd = setup_tun_device("tun0")?;   // see below

    // 4. Configure IP address and routing via rtnetlink.
    configure_tun_interface("tun0")?;         // see below

    // 5. Return to the host namespace.
    nix::sched::setns(orig_netns.as_fd(), nix::sched::CloneFlags::CLONE_NEWNET)
        .context("restoring host netns")?;

    Ok(tun_fd)
}
```

> **Thread safety**: `setns` is per-thread.  `setup_tun` must be called on the
> main thread **before** the tokio runtime's `block_on` loop begins (the same
> timing constraint that applied to `setup_slirp`).  This is already satisfied
> by the current control flow in `launch.rs`.

### `setup_tun_device`

```rust
fn setup_tun_device(name: &str) -> Result<OwnedFd> {
    use std::os::unix::io::FromRawFd;
    use nix::ioctl_write_ptr;

    // TUNSETIFF = _IOW('T', 202, struct ifreq)  (0x400454ca)
    ioctl_write_ptr!(tunsetiff, b'T', 202, libc::ifreq);

    let fd = unsafe {
        libc::open(b"/dev/net/tun\0".as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC)
    };
    if fd < 0 {
        bail!("open /dev/net/tun: {}", std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = name.as_bytes();
    ifr.ifr_name[..name_bytes.len()]
        .copy_from_slice(unsafe { &*(name_bytes as *const [u8] as *const [i8]) });
    // IFF_TUN:   L3 mode (raw IP packets, no Ethernet headers)
    // IFF_NO_PI: suppress the 4-byte packet-info prefix prepended by the kernel
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;

    unsafe { tunsetiff(owned.as_raw_fd(), &ifr) }.context("TUNSETIFF")?;
    Ok(owned)
}
```

### `configure_tun_interface`

Uses the `rtnetlink` crate (already in the ecosystem) to:

1. Set link state UP for `tun0`
2. Add address `169.254.0.2/30` to `tun0`
3. Add default route `0.0.0.0/0 via 169.254.0.1 dev tun0`

This replaces the `--configure` flag that slirp4netns previously handled.

```toml
# Cargo.toml additions
rtnetlink = "0.14"
futures    = "0.3"   # for rtnetlink's async API; already transitive likely
```

The rtnetlink calls must be awaited.  Because they must occur before the tokio
runtime enters its `block_on` loop, use a temporary one-shot runtime just for
this step, or restructure `setup_tun` to be async and called from within the
runtime.

> **Preferred**: make `setup_tun` async and call it from a `block_on` wrapper
> immediately after reading the sandbox PID, before spawning the smoltcp task.

---

## smoltcp Integration

### Crate

```toml
smoltcp = { version = "0.11", default-features = false, features = [
    "medium-ip",    # L3/TUN mode (no Ethernet)
    "proto-ipv4",
    "proto-tcp",
    "proto-icmpv4", # for ICMP host-unreachable on denied connections
    "socket-tcp",
] }
```

### Device abstraction

smoltcp's `phy` layer needs a type implementing `Device`.  Wrap the TUN fd
(which reads/writes raw IP packets when opened with `IFF_TUN | IFF_NO_PI`):

```rust
struct TunDevice {
    fd: std::os::unix::io::RawFd,
    rx_buf: Vec<u8>,
    tx_buf: Vec<u8>,
}

impl smoltcp::phy::Device for TunDevice {
    // receive: read() from fd into rx_buf, return slice
    // transmit: return tx_buf slice; on flush, write() to fd
}
```

`rx_buf` and `tx_buf` are fixed-size (MTU = 1500 bytes is sufficient; the
sandbox kernel's MTU on `tun0` is set to 1500 during `configure_tun_interface`).

### Interface setup

```rust
let config = smoltcp::iface::Config::new(
    smoltcp::wire::HardwareAddress::Ip,  // no MAC; pure L3
);
let mut iface = smoltcp::iface::Interface::new(config, &mut device, Instant::now());
iface.update_ip_addrs(|addrs| {
    // smoltcp answers as the gateway (169.254.0.1/30)
    addrs.push(smoltcp::wire::IpCidr::new(
        smoltcp::wire::IpAddress::from(TUN_GATEWAY_IP),
        TUN_PREFIX_LEN,
    )).unwrap();
});
```

smoltcp presents itself as `169.254.0.1`.  All packets the sandbox sends to the
gateway are received and processed by smoltcp.  Packets the sandbox sends to
arbitrary internet IPs arrive via the default route and are also received by
smoltcp (because the TUN is the only interface and the default route points at
it).

---

## Policy Enforcement in the smoltcp Loop

The smoltcp task runs in a dedicated `tokio::task::spawn_blocking` thread (since
smoltcp's `poll` is synchronous and CPU-bound) or as a tight loop in a regular
tokio task with careful `yield` points.

```rust
loop {
    let timestamp = smoltcp_timestamp();
    iface.poll(timestamp, &mut device, &mut sockets);

    // Drain newly accepted connections.
    for handle in sockets.iter() {
        let socket = sockets.get_mut::<TcpSocket>(handle);

        if socket.is_open() && socket.may_recv() {
            let remote = socket.remote_endpoint().unwrap();

            if is_proxy_endpoint(remote) {
                // dst == 169.254.0.1:PROXY_PORT — hand off to proxy relay.
                relay_to_proxy(socket, proxy_port, tx.clone()).await;
            } else {
                // Hard deny: close with RST.
                socket.abort();
                tracing::debug!(
                    remote = %remote,
                    "smoltcp: rejected non-proxy connection with RST"
                );
            }
        }
    }

    // Pre-allocate a listening socket for the next incoming SYN.
    ensure_listener_socket(&mut sockets, proxy_port);

    tokio::task::yield_now().await;
}
```

`is_proxy_endpoint` checks that `remote.addr == TUN_GATEWAY_IP` (`169.254.0.1`)
and `remote.port == proxy_port`.

> **Important**: smoltcp requires at least one `TcpSocket` in `LISTEN` state to
> accept incoming connections.  `ensure_listener_socket` adds a fresh socket in
> `listen` mode whenever the set drops below a minimum (e.g. 4 pre-allocated
> listener sockets to avoid dropping SYNs during bursts).

---

## Proxy Integration via `socketpair`

Passing a smoltcp socket's data directly into `proxy.rs` requires a bridge
between smoltcp's in-memory buffers and a real kernel fd that the proxy's accept
loop can read from.

### The socketpair bridge

When a connection is accepted and identified as a proxy connection:

1. Create `socketpair(AF_UNIX, SOCK_STREAM, 0)` → `[tun_side, proxy_side]`
2. Spawn a **relay task** that copies data between the smoltcp socket and
   `tun_side` (detailed below).
3. Pass `proxy_side` directly to the proxy handler as if it were an accepted
   `TcpStream` — no changes to `proxy.rs` needed.

```rust
async fn relay_to_proxy(
    socket: &mut TcpSocket<'_>,
    proxy_handler: Arc<ProxyHandler>,
    policy: Arc<SandboxPolicy>,
) -> Result<()> {
    let (tun_side, proxy_side) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?;

    // Hand off the proxy_side fd to the existing proxy handler.
    let proxy_stream = unsafe { tokio::net::UnixStream::from_raw_fd(proxy_side.into_raw_fd()) }?;
    tokio::spawn(async move {
        if let Err(e) = proxy_handler.handle_unix_stream(proxy_stream, policy).await {
            tracing::debug!(error = %e, "proxy handler error");
        }
    });

    // Run the bidirectional relay between smoltcp socket and tun_side.
    smoltcp_relay_loop(socket, tun_side).await
}
```

`proxy_handler.handle_unix_stream` is a thin wrapper in `proxy.rs` that accepts
an `AsyncRead + AsyncWrite` instead of a `TcpStream` — the existing
`handle_connection` logic is unchanged, only the type parameter is generalized.

### `smoltcp_relay_loop`

```rust
async fn smoltcp_relay_loop(socket: &mut TcpSocket<'_>, fd: OwnedFd) -> Result<()> {
    let async_fd = tokio::io::unix::AsyncFd::new(fd)?;
    let mut buf = vec![0u8; 8192];

    loop {
        // Sandbox → proxy direction: read from smoltcp, write to fd.
        if socket.may_recv() {
            let n = socket.recv_slice(&mut buf).unwrap_or(0);
            if n > 0 {
                async_fd.get_ref().write_all(&buf[..n]).await?;
            }
        }

        // Proxy → sandbox direction: read from fd, write to smoltcp.
        if socket.may_send() {
            let n = async_fd.get_ref().read(&mut buf).await.unwrap_or(0);
            if n == 0 { break; }   // proxy closed
            socket.send_slice(&buf[..n]).unwrap_or(0);
        }

        if socket.state() == TcpState::CloseWait || socket.state() == TcpState::Closed {
            break;
        }
    }
    socket.close();
    Ok(())
}
```

---

## Splice Fast-Path for the CONNECT Upstream Relay

Once the proxy handler has accepted the socketpair connection and parsed the HTTP
`CONNECT` request, it establishes a TCP connection to the upstream origin.  At
that point we have two real kernel fds:

- `proxy_side` (Unix stream socket)
- `upstream_socket` (TCP socket)

This matches pasta's local-connection scenario exactly: both endpoints are kernel
file descriptors, and `splice(2)` can move data between them without a userspace
copy.

Replace `tokio::io::copy_bidirectional` in the CONNECT handler with a
splice-based relay:

```rust
async fn splice_relay(a: OwnedFd, b: OwnedFd) -> Result<()> {
    // Two pipes, one for each direction.
    let (pipe_a_r, pipe_a_w) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)?;
    let (pipe_b_r, pipe_b_w) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)?;

    let async_a = tokio::io::unix::AsyncFd::new(a)?;
    let async_b = tokio::io::unix::AsyncFd::new(b)?;

    loop {
        tokio::select! {
            // a → pipe_a → b
            _ = async_a.readable() => {
                splice_nonblock(async_a.get_ref().as_raw_fd(), pipe_a_w.as_raw_fd())?;
                splice_nonblock(pipe_a_r.as_raw_fd(), async_b.get_ref().as_raw_fd())?;
            }
            // b → pipe_b → a
            _ = async_b.readable() => {
                splice_nonblock(async_b.get_ref().as_raw_fd(), pipe_b_w.as_raw_fd())?;
                splice_nonblock(pipe_b_r.as_raw_fd(), async_a.get_ref().as_raw_fd())?;
            }
        }
    }
}

fn splice_nonblock(from: RawFd, to: RawFd) -> Result<usize> {
    let n = unsafe {
        libc::splice(from, ptr::null_mut(), to, ptr::null_mut(),
                     65536, libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE)
    };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::WouldBlock { return Ok(0); }
        bail!("splice: {e}");
    }
    Ok(n as usize)
}
```

> **Why splice here but not in the smoltcp relay**: smoltcp's socket is not a
> kernel fd — its receive/send buffers live in userspace.  The smoltcp↔tun_side
> relay necessarily goes through userspace.  The `proxy_side`↔`upstream` path is
> purely between kernel sockets and is the hot path for all bulk data transfer,
> so splice gives the most benefit there.

> **splice limitation**: `splice` requires that at least one fd refers to a pipe.
> The implementation above routes through intermediate pipes.  On Linux ≥ 5.12,
> `SPLICE_F_MOVE` is a no-op hint; the kernel may or may not avoid the copy
> depending on the socket type.  For Unix sockets and TCP sockets this is still
> faster than userspace `read`+`write` because it avoids the user↔kernel
> boundary twice.

---

## Startup Sequence

`setup_slirp` in `launch.rs` is replaced by `setup_tun`.  The call site and
surrounding structure are unchanged:

```rust
// In the parent fork arm, after read_bwrap_child_pid:
let tun_fd: Option<OwnedFd> = match info_read {
    Some(r) => {
        let sandbox_pid = read_bwrap_child_pid(r)?;
        info!(sandbox_pid, "creating TUN device in sandbox netns");
        Some(setup_tun(sandbox_pid).await?)
    }
    None => None,
};
```

The `tun_fd` is then moved into the tokio runtime and passed to the smoltcp task:

```rust
let exit_code = rt.block_on(async move {
    if let Some(fd) = tun_fd {
        let policy = policy.clone();
        tokio::spawn(async move {
            if let Err(e) = run_smoltcp(fd, proxy_port, proxy_listener_tx, policy).await {
                error!(message = "smoltcp task failed", error = %e);
            }
        });
    }

    tokio::spawn(async move {
        proxy_listener.run(policy).await
    });

    // ... pidfd await and waitpid unchanged ...
});
```

`proxy_listener_tx` is a channel through which the smoltcp task pushes accepted
socketpair fds into the proxy's accept loop.

### Removal of `slirp_bin` resolution

The early `find_slirp4netns()` call and its error hint are removed.  The
`SLIRP_HOST_IP` constant (`"10.0.2.2"`) is replaced by `TUN_GATEWAY_IP`
(`[169, 254, 0, 1]`) defined in `src/tun.rs`.  All downstream consumers (env
var injection, proxy host selection) are updated to stringify this constant.

---

## Dropped and Blocked Traffic

| Traffic type | smoltcp action | Rationale |
|---|---|---|
| TCP to `169.254.0.1:PROXY_PORT` | Accept, relay to proxy | Permitted |
| TCP to any other destination | `socket.abort()` (RST) | Hard deny |
| UDP (any) | Not delivered (no smoltcp UDP socket) | Drop silently; DNS must go through DoH |
| ICMP echo request | Optional: reply with smoltcp's ICMP handler | Diagnostic; doesn't bypass policy |
| ICMP to non-gateway | Ignore | No route exists |

---

## New Source Files

| File | Purpose |
|---|---|
| `src/tun.rs` | `setup_tun_device`, `configure_tun_interface`, `TunDevice` smoltcp phy impl |
| `src/smoltcp_task.rs` | `run_smoltcp` event loop, listener socket management, connection dispatch |
| `src/splice.rs` | `splice_relay`, `splice_nonblock` helpers |

Modified files:

| File | Change |
|---|---|
| `src/launch.rs` | Replace `setup_slirp` + `find_slirp4netns` with `setup_tun`; rename `SLIRP_HOST_IP` → `TUN_GATEWAY_IP` |
| `src/proxy.rs` | Generalize `handle_connection` to accept `impl AsyncRead + AsyncWrite + Unpin` instead of `TcpStream`; wire `splice_relay` in CONNECT handler |
| `Cargo.toml` | Add `smoltcp`, `rtnetlink`; remove `slirp4netns` dependency if it was explicit |

---

## New Dependencies

```toml
smoltcp  = { version = "0.11", default-features = false, features = [
    "medium-ip", "proto-ipv4", "proto-tcp", "proto-icmpv4", "socket-tcp",
] }
rtnetlink = "0.14"
```

`libc` is already a dependency; `splice` and TUN ioctls use it directly.

---

## Error Handling

| Failure | Behaviour |
|---|---|
| `/dev/net/tun` not available | Fatal error at startup with hint to check `CONFIG_TUN` |
| `setns` fails (kernel <4.9 or permission) | Fatal; clear error message |
| rtnetlink address/route config fails | Fatal; sandbox netns is unusable |
| smoltcp `poll` error | Log and continue; individual connections fail gracefully |
| Relay loop fd closed unexpectedly | Close corresponding smoltcp socket; log |
| `splice` returns `EINVAL` (kernel doesn't support for fd type) | Fall back to `copy_bidirectional` on first failure; log once |

---

## Testing Approach

### Unit: policy enforcement

Construct the smoltcp loop against a fake TUN (in-memory `Vec<u8>` device), send
a synthetic TCP SYN to a non-proxy destination, and assert the smoltcp loop
emits a RST segment.

### Unit: splice relay

Open a `socketpair`, write known bytes into one side, run `splice_relay` for
one iteration, assert the bytes appear on the other side without going through
userspace buffers (verify by running under `strace` and checking no `read`/`write`
syscalls appear for the bulk data path).

### Integration: proxy-only access

Launch a full `cei launch` sandbox, attempt `curl http://example.com` (goes
through proxy) and `nc 8.8.8.8 80` (direct TCP, should be RST'd).  Assert:

- `curl` succeeds (or is policy-denied with 403, depending on allow-list)
- `nc` exits with connection refused / reset immediately

### Integration: no external subprocess

After `cei launch` starts, assert `pgrep slirp4netns` returns nothing.

### Regression: existing proxy tests

All existing proxy integration tests (`--allow-http-host`, CONNECT tunnelling,
plain HTTP forwarding) must pass without modification, since `proxy.rs` is
unchanged in logic.
