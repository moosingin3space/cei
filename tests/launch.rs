use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn cei() -> Command {
    Command::cargo_bin("cei").unwrap()
}

/// Skip the calling test if `bwrap` is not available on this host.
macro_rules! need_bwrap {
    () => {
        let ok = std::process::Command::new("bwrap")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("SKIP: bwrap not found");
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// Basic execution
// ---------------------------------------------------------------------------

#[test]
fn exits_zero_on_success() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "true",
        ])
        .assert()
        .success();
}

#[test]
fn exits_nonzero_on_failure() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "false",
        ])
        .assert()
        .failure();
}

#[test]
fn propagates_exit_code() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "exit 7",
        ])
        .assert()
        .code(7);
}

// ---------------------------------------------------------------------------
// Environment and working directory
// ---------------------------------------------------------------------------

#[test]
fn cwd_is_workspace() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "pwd",
        ])
        .assert()
        .success()
        .stdout("/workspace\n");
}

#[test]
fn home_is_workspace() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            r#"printf '%s\n' "$HOME""#,
        ])
        .assert()
        .success()
        .stdout("/workspace\n");
}

// ---------------------------------------------------------------------------
// Filesystem isolation
// ---------------------------------------------------------------------------

#[test]
fn etc_is_readonly() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "touch /etc/cei-write-test",
        ])
        .assert()
        .failure();
}

#[test]
fn workspace_is_writable_and_visible_on_host() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "echo sandbox-output > /workspace/result.txt",
        ])
        .assert()
        .success();

    let content = fs::read_to_string(project.path().join("result.txt")).unwrap();
    assert_eq!(content, "sandbox-output\n");
}

#[test]
fn tmp_is_writable_scratch() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    // Writing to /tmp must succeed, and must NOT appear on the host.
    let host_tmp_marker = std::env::temp_dir().join("cei-tmp-leak-test");
    let _ = fs::remove_file(&host_tmp_marker); // clean up any leftover

    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &format!("echo leak > {}", host_tmp_marker.display()),
        ])
        .assert()
        .success();

    assert!(
        !host_tmp_marker.exists(),
        "/tmp inside sandbox leaked a file to the host"
    );
}

// ---------------------------------------------------------------------------
// Network isolation
// ---------------------------------------------------------------------------

#[test]
fn network_namespace_contains_only_loopback() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    // /proc/net/dev is available inside the sandbox (we mount /proc).
    // In an unshared network namespace only "lo" is present.
    // awk skips the two header lines and counts non-loopback interfaces.
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            r"awk 'NR>2 && !/lo:/ {c++} END {print c+0}' /proc/net/dev",
        ])
        .assert()
        .success()
        .stdout("0\n");
}

// ---------------------------------------------------------------------------
// `cei` binary self-protection
// ---------------------------------------------------------------------------

#[test]
fn cei_binary_is_visible_at_run_cei() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    // The binary must be readable (we only deny exec, not read).
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "test -f /run/cei && echo found",
        ])
        .assert()
        .success()
        .stdout("found\n");
}

#[test]
fn cei_binary_exec_is_denied() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    // Attempting to exec /run/cei returns EPERM; the shell exits with code 126.
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "/run/cei intercept -- true",
        ])
        .assert()
        .code(126)
        .stderr(predicate::str::contains("deny: /run/cei"));
}

// ---------------------------------------------------------------------------
// Exec redirect forwarded to intercept
// ---------------------------------------------------------------------------

#[test]
fn redirect_is_applied_inside_sandbox() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--redirect",
            "/usr/bin/false=/usr/bin/true",
            "--",
            "/usr/bin/false",
        ])
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// Extra bind mounts
// ---------------------------------------------------------------------------

#[test]
fn extra_ro_bind_is_readable() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    let host_file = project.path().join("hostfile.txt");
    fs::write(&host_file, "host-content\n").unwrap();

    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--ro-bind",
            &format!("{}=/tmp/imported", host_file.display()),
            "--",
            "sh",
            "-c",
            "cat /tmp/imported",
        ])
        .assert()
        .success()
        .stdout("host-content\n");
}

#[test]
fn extra_ro_bind_is_not_writable() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    let host_file = project.path().join("hostfile.txt");
    fs::write(&host_file, "original\n").unwrap();

    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--ro-bind",
            &format!("{}=/tmp/imported", host_file.display()),
            "--",
            "sh",
            "-c",
            "echo overwrite > /tmp/imported",
        ])
        .assert()
        .failure();

    // Content on host must be unchanged.
    assert_eq!(fs::read_to_string(&host_file).unwrap(), "original\n");
}

#[test]
fn extra_bind_is_writable_and_reflected_on_host() {
    need_bwrap!();
    let project = TempDir::new().unwrap();
    let host_dir = TempDir::new().unwrap();

    cei()
        .args([
            "launch",
            "--project",
            project.path().to_str().unwrap(),
            "--bind",
            &format!("{}=/mnt/shared", host_dir.path().display()),
            "--",
            "sh",
            "-c",
            "echo shared-write > /mnt/shared/out.txt",
        ])
        .assert()
        .success();

    let content = fs::read_to_string(host_dir.path().join("out.txt")).unwrap();
    assert_eq!(content, "shared-write\n");
}
