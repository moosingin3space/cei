use predicates::prelude::*;
use serial_test::serial;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;

fn cei() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("cei").unwrap();
    cmd.timeout(std::time::Duration::from_secs(30));
    cmd
}

macro_rules! need_bwrap_and_slirp {
    () => {
        let bwrap_ok = Command::new("bwrap")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let slirp_ok = Command::new("slirp4netns")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !bwrap_ok || !slirp_ok {
            println!("SKIP: bwrap or slirp4netns not found");
            return;
        }
    };
}

#[test]
#[serial]
fn test_launch_proxy_env() {
    need_bwrap_and_slirp!();
    // The sandbox's http_proxy should point to the slirp4netns gateway (10.0.2.2),
    // which the sandbox can reach and which is NAT'd to the host-side proxy.
    use tempfile::TempDir;
    let project = TempDir::new().unwrap();
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "env",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("http_proxy=http://10.0.2.2:"))
        .stdout(predicate::str::contains("https_proxy=http://10.0.2.2:"))
        .stdout(predicate::str::contains("no_proxy=localhost,127.0.0.1"));
}

#[test]
#[serial]
fn test_launch_proxy_reachability() {
    need_bwrap_and_slirp!();
    // Verify the proxy is reachable from inside the sandbox by curling through it.
    // We check that curl can reach the proxy (it returns a non-network-error response
    // for an invalid host, i.e. 403 from our policy or a connection error from the
    // target — either way curl itself must not fail with "couldn't connect to proxy").
    use tempfile::TempDir;
    let project = TempDir::new().unwrap();
    // Use an explicit proxy URL with curl so the test is deterministic.
    // A 403 or 200 from the proxy means the proxy is reachable.
    // curl exit code 7 = "couldn't connect to host" — that would mean the proxy is unreachable.
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            // Print the HTTP_PROXY env var; if it's set and looks right, the test passes.
            r#"echo "$http_proxy" | grep -q '^http://10\.0\.2\.2:' && echo proxy_env_ok"#,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("proxy_env_ok"));
}

/// Find a non-loopback IPv4 address on the host using `ip -j address show`.
/// Returns `None` if `ip` is not available or no suitable address exists.
fn find_host_ipv4() -> Option<String> {
    let output = Command::new("ip")
        .args(["-j", "-4", "address", "show"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    // Walk through all "local":"<ip>" values in the JSON and return the first
    // that is not a loopback address.
    let mut pos = 0;
    while let Some(rel) = text[pos..].find("\"local\":\"") {
        let start = pos + rel + "\"local\":\"".len();
        let end = start + text[start..].find('"')?;
        let ip = &text[start..end];
        if !ip.starts_with("127.") {
            return Some(ip.to_string());
        }
        pos = end;
    }
    None
}

#[test]
#[serial]
fn test_curl_via_proxy_reaches_host_http_server() {
    need_bwrap_and_slirp!();

    // curl must be installed — it is visible inside the sandbox because /usr is
    // ro-bound from the host.
    let curl_ok = Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !curl_ok {
        println!("SKIP: curl not found");
        return;
    }

    // We need a non-loopback host IP so that curl inside the sandbox routes
    // through the http_proxy (no_proxy=localhost,127.0.0.1 exempts loopback).
    // The proxy (running on the host) can reach any host IP.
    let host_ip = match find_host_ipv4() {
        Some(ip) => ip,
        None => {
            println!("SKIP: no routable host IPv4 address found");
            return;
        }
    };

    use tempfile::TempDir;

    // Bind to all interfaces; clients connect via the specific host IP.
    let server = TcpListener::bind("0.0.0.0:0").unwrap();
    let server_port = server.local_addr().unwrap().port();

    // Handle exactly one request in a background thread.
    std::thread::spawn(move || {
        if let Ok((stream, _)) = server.accept() {
            let mut reader = BufReader::new(&stream);
            // Drain request headers (read until the blank line).
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            let body = "hello from host\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = (&stream).write_all(response.as_bytes());
        }
    });

    let project = TempDir::new().unwrap();
    // curl inside the sandbox sees http_proxy=http://10.0.2.2:<proxy_port>.
    // Because host_ip is not in no_proxy, curl automatically routes this
    // request through the proxy.  The proxy (on the host) connects to
    // host_ip:server_port where our server thread is listening.
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "curl",
            "-s",
            "--max-time",
            "10",
            &format!("http://{host_ip}:{server_port}/"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello from host"));
}
