use assert_cmd::Command;
use predicates::prelude::*;

fn cei() -> Command {
    Command::cargo_bin("cei").unwrap()
}

// ---------------------------------------------------------------------------
// Exit code propagation
// ---------------------------------------------------------------------------

#[test]
fn exits_zero_on_success() {
    cei().args(["intercept", "--", "true"]).assert().success();
}

#[test]
fn exits_one_on_failure() {
    cei().args(["intercept", "--", "false"]).assert().code(1);
}

#[test]
fn propagates_arbitrary_exit_code() {
    cei()
        .args(["intercept", "--", "sh", "-c", "exit 42"])
        .assert()
        .code(42);
}

// ---------------------------------------------------------------------------
// I/O passthrough
// ---------------------------------------------------------------------------

#[test]
fn stdout_passthrough() {
    cei()
        .args(["intercept", "--", "echo", "hello from intercept"])
        .assert()
        .success()
        .stdout("hello from intercept\n");
}

#[test]
fn stderr_passthrough() {
    cei()
        .args(["intercept", "--", "sh", "-c", "echo oops >&2"])
        .assert()
        .success()
        // The supervisor also writes to stderr; check the child's line is present.
        .stderr(predicate::str::contains("oops"));
}

#[test]
fn stdin_forwarded_to_child() {
    cei()
        .args(["intercept", "--", "sh", "-c", "read line; echo got:$line"])
        .write_stdin("payload\n")
        .assert()
        .success()
        .stdout("got:payload\n");
}

// ---------------------------------------------------------------------------
// Exec redirect
// ---------------------------------------------------------------------------

#[test]
fn redirect_replaces_exec_target() {
    // Exec of /usr/bin/false is silently replaced by /usr/bin/true.
    cei()
        .args([
            "intercept",
            "--redirect", "/usr/bin/false=/usr/bin/true",
            "--",
            "/usr/bin/false",
        ])
        .assert()
        .success();
}

#[test]
fn redirect_can_invert_exit_code() {
    // Exec of /usr/bin/true is replaced by /usr/bin/false.
    cei()
        .args([
            "intercept",
            "--redirect", "/usr/bin/true=/usr/bin/false",
            "--",
            "/usr/bin/true",
        ])
        .assert()
        .code(1);
}

#[test]
fn redirect_only_applies_to_named_path() {
    // A redirect on /usr/bin/false must not affect /usr/bin/true.
    cei()
        .args([
            "intercept",
            "--redirect", "/usr/bin/false=/usr/bin/false",
            "--",
            "/usr/bin/true",
        ])
        .assert()
        .success();
}

#[test]
fn multiple_redirects_are_independent() {
    // Both redirects apply; /usr/bin/false is what actually runs.
    cei()
        .args([
            "intercept",
            "--redirect", "/usr/bin/true=/usr/bin/false",
            "--redirect", "/usr/bin/false=/usr/bin/true",
            "--",
            "/usr/bin/true",
        ])
        .assert()
        .code(1);
}

// ---------------------------------------------------------------------------
// Child spawns further execs (grandchildren are also intercepted)
// ---------------------------------------------------------------------------

#[test]
fn grandchild_execs_are_intercepted() {
    // sh execs echo — both execs go through the supervisor.
    cei()
        .args([
            "intercept",
            "--redirect", "/usr/bin/echo=/usr/bin/true",
            "--",
            "sh", "-c", "/usr/bin/echo should-be-silenced",
        ])
        .assert()
        .success()
        // /usr/bin/true produces no output, so stdout should be empty.
        .stdout("");
}
