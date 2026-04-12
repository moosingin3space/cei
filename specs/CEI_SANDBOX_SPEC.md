# `cei` + Bubblewrap Integration Specification

## Overview

This document specifies a new subcommand, `cei launch` ("cei launcher"), that owns the
outer sandboxing layer. It constructs and enters a Bubblewrap container, then
executes `cei intercept` inside it as PID 2. The existing `cei` codebase is unchanged.

```
cei launch [options] -- <command> [args...]
    │
    │  (host namespace, before exec)
    ├── open cei binary fd
    ├── construct bwrap argv
    └── execvp(bwrap, ...)
            │
            │  bwrap forks, sets up namespaces, becomes PID 1
            └── /proc/self/fd/<CEI_FD> intercept [--redirect ...] <command> [args]
                    │
                    │  (inside sandbox, PID 2)
                    ├── fork() → child installs seccomp USER_NOTIF, execs <command>
                    └── supervisor loop (seccomp notification handling)
```

---

## Subcommand: `cei launch`

### CLI

```
cei launch [OPTIONS] -- <COMMAND> [ARGS...]

Options:
  --project <PATH>          Host path to mount read-write at /workspace.
                            Defaults to current working directory.
  --ro-bind <HOST=GUEST>    Additional read-only bind mounts. Repeatable.
  --bind <HOST=GUEST>       Additional read-write bind mounts. Repeatable.
  --redirect <FROM=TO>      Forwarded verbatim to `cei run --redirect`. Repeatable.
  --bwrap <PATH>            Path to the `bwrap` binary. Defaults to $BWRAP or
                            which(bwrap).
  --share-net               Do not unshare the network namespace (default: unshared).
  --unshare-user            Enter a user namespace (required on systems without
                            unprivileged mount namespaces, see Privilege section).
```

---

## Filesystem Mount Topology

Mounts are applied in this order; later entries override earlier ones.

### Mandatory mounts

| bwrap flag | Host path | Guest path | Notes |
|---|---|---|---|
| `--ro-bind` | `/` | `/` | Read-only rootfs baseline |
| `--dev` | — | `/dev` | Fresh devtmpfs |
| `--proc` | — | `/proc` | Required by `cei` (`process_vm_readv`, `/proc/self/fd/N`) |
| `--tmpfs` | — | `/tmp` | Writable scratch |
| `--tmpfs` | — | `/run` | Prevent host runtime socket leakage |
| `--bind` | `$project` | `/workspace` | Read-write project directory |

### Why `/proc` must be present

`cei`'s redirect mechanism writes `/proc/self/fd/<N>` as the replacement exec
path. Inside the sandbox, that procfs path must resolve. Without `--proc /proc`,
the injected path string points at nothing and exec fails with `ENOENT`.

Additionally, `process_vm_readv` and `process_vm_writev` do not use procfs paths
directly but do require a live `/proc` for the kernel's pid-to-task resolution
under some configurations.

### Optional mounts

User-supplied `--ro-bind HOST=GUEST` and `--bind HOST=GUEST` entries are appended
after the mandatory set. This allows read-only access to credentials, config
files, or toolchain roots without granting write access.

### What is intentionally absent

- `/home` — not bind-mounted; the rootfs copy (from `--ro-bind /`) is read-only
- `/etc/passwd`, `/etc/shadow` — readable (from ro rootfs) but not writable
- Host's `/tmp`, `/run`, `/var/run` — shadowed by fresh tmpfs entries

---

## PID Namespace and Init

`--unshare-pid` is always passed. bwrap is invoked without `--as-pid1`; bwrap's
default behaviour under `--unshare-pid` is to fork a minimal init process that:

- reaps orphaned children (calls `waitpid(-1)` in a loop),
- forwards `SIGTERM`/`SIGINT` to its child process group.

This makes bwrap PID 1 and `cei run` PID 2. `cei`'s supervisor loop has no init
responsibilities and receives signals normally.

**Do not** pass `--as-pid1` unless you have added a signal handler and reaping
loop to `cei` itself.

---

## The `cei` Binary: Pre-Opening and fd Passing

### Motivation

`cei launch` opens the `cei` binary in the host namespace before exec'ing bwrap. The
opened fd is passed into the sandbox via `--pass-fd`. Inside the sandbox, `cei`
is invoked as `/proc/self/fd/<N>` — it does not need to exist at any path inside
the read-only rootfs.

This is intentional: `cei` is a supervisor tool, not a sandboxed application.
Keeping it absent from the sandbox filesystem prevents the sandboxed process from
inspecting, replacing, or exec'ing it directly.

### Implementation

```rust
// In cei's main, before constructing bwrap argv:
let cei_file = File::open("/proc/self/exe")
    .with_context(|| format!("opening cei binary: {}", cei_path.display()))?;
let cei_fd = cei_file.into_raw_fd();          // kept open across execvp
let cei_fd_path = format!("/proc/self/fd/{cei_fd}");
```

The fd must **not** have `O_CLOEXEC` set — `into_raw_fd()` on a `File` gives a
raw fd without CLOEXEC, which is correct. Verify this: if you use `OpenOptions`
or `OwnedFd`, clear CLOEXEC explicitly with `fcntl(F_SETFD, 0)`.

bwrap argv then includes:

```
--pass-fd <cei_fd>
-- /proc/self/fd/<cei_fd> run [--redirect FROM=TO ...] <command> [args...]
```

### Kernel exec permission check

The kernel checks execute permission on the inode that the fd refers to, not on
the `/proc/self/fd/N` path itself. The `cei` binary must be executable (`+x`) on
the host. No special permission is required inside the sandbox.

---

## Full bwrap argv Construction

```rust
fn build_bwrap_argv(config: &Config, cei_fd: RawFd) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec!["bwrap".into()];

    // Mandatory namespace flags
    argv.extend(["--unshare-pid".into()]);
    if !config.share_net {
        argv.extend(["--unshare-net".into()]);
    }

    // Mandatory mounts (order matters)
    argv.extend(["--ro-bind".into(), "/".into(), "/".into()]);
    argv.extend(["--dev".into(),   "/dev".into()]);
    argv.extend(["--proc".into(),  "/proc".into()]);
    argv.extend(["--tmpfs".into(), "/tmp".into()]);
    argv.extend(["--tmpfs".into(), "/run".into()]);

    // Project directory
    let project = config.project.as_os_str();
    argv.extend(["--bind".into(), project.into(), "/workspace".into()]);

    // User-supplied mounts
    for (host, guest) in &config.extra_ro_binds {
        argv.extend(["--ro-bind".into(), host.into(), guest.into()]);
    }
    for (host, guest) in &config.extra_binds {
        argv.extend(["--bind".into(), host.into(), guest.into()]);
    }

    // Pass the cei fd through
    argv.extend(["--pass-fd".into(), cei_fd.to_string().into()]);

    // Separator, then the inner command
    argv.push("--".into());
    argv.push(format!("/proc/self/fd/{cei_fd}").into()); // cei binary
    argv.push("run".into());

    for r in &config.redirects {
        argv.extend(["--redirect".into(), r.into()]);
    }

    argv.push("--".into());
    argv.push(config.command.clone().into());
    for arg in &config.command_args {
        argv.push(arg.into());
    }

    argv
}
```

Then `execvp("bwrap", &argv)` — this replaces the `ceil` process entirely; no
child process management needed in `ceil` itself.

---

## Privilege Requirements

### Preferred: unprivileged user namespaces

On kernels with `kernel.unprivileged_userns_clone=1` (Debian, Ubuntu, most
distros):

```
--unshare-user --unshare-pid --unshare-net
```

No capabilities required. The mount namespace is created inside the user
namespace and is fully unprivileged.

### Without unprivileged user namespaces

Some hardened distributions (RHEL 8 without adjustment, some Arch configs)
disable unprivileged user namespaces. In this case bwrap needs either:

- `CAP_SYS_ADMIN` in the ambient capability set, or
- the bwrap binary itself to be setuid root (the upstream default install)

`cei launch` should detect this at startup by attempting a dry-run `--unshare-user`
bwrap invocation and falling back to setuid mode with a warning, or failing with
a clear error message directing the user to install setuid bwrap.

### `ptrace_scope` interaction

`cei` uses ptrace as the direct parent of the supervised process. Inside a user
namespace (default path), the `ptrace_scope=1` restriction (Yama) does not
block parent-child ptrace. `ptrace_scope=2` or `3` will block it regardless;
`cei launch` should check `/proc/sys/kernel/yama/ptrace_scope` at startup and emit a
warning if the value is ≥ 2.

---

## Environment Variable Handling

By default bwrap propagates the full environment from `cei launch`'s process into the
sandbox. This is usually desirable (preserves `HOME`, `PATH`, `LANG`, etc.) but
leaks host-specific variables.

`cei launch` should filter the environment before exec'ing bwrap:

### Variables to strip

- `LD_PRELOAD`, `LD_LIBRARY_PATH` — prevent host library injection
- `DBUS_SESSION_BUS_ADDRESS`, `DISPLAY`, `WAYLAND_DISPLAY` — prevent host
  display/session socket access (sandboxed processes should not reach these
  unless explicitly re-exposed via `--ro-bind`)
- Any `BWRAP_*` or `CEI_*` internal variables that should not leak inward

### Variables to inject

- `HOME=/workspace` — prevents tools writing dotfiles to host home
- `TMPDIR=/tmp`
- Working directory: set via `--chdir /workspace` bwrap flag

Pass `--chdir /workspace` so the sandboxed process starts in the project
directory, matching user expectation.

---

## Interaction Between `cei launch` and `cei intercept`

### What `cei intercept` does not know

`cei intercept` has no awareness of bwrap. It installs its seccomp filter, handles
exec notifications, and applies its own policy exactly as it does today. The
only difference is that it runs as PID 2 inside a mount+pid+net namespace.

### What `cei launch` does not know

`cei launch` does not parse or validate `--redirect` arguments — it passes them
verbatim to `cei intercept`. Policy for exec redirection remains entirely in `cei`.

### Workspace path convention

`cei`'s `SandboxPolicy::from_current_dir()` captures the current working
directory as `host_workspace`. Inside the sandbox, the cwd is `/workspace`
(via `--chdir /workspace`), so `host_workspace` will be `/workspace`. This is
correct: write-allow checks compare child paths against `/workspace`, which is
exactly the writable bind mount.

The mapping is:

```
host: /home/user/myproject  →  guest: /workspace
```

`cei`'s write policy (`host_allows_write`) will allow writes under `/workspace`,
which map back to the project directory on the host. No changes to `cei` needed.

---

## Sequence Diagram

```
cei launch (host)
  │
  ├── resolve bwrap path
  ├── resolve cei path
  ├── open(cei_path) → cei_fd        # host namespace, no CLOEXEC
  ├── build bwrap argv
  └── execvp(bwrap, argv)            # cei launch is replaced
        │
        bwrap (PID 1 in new namespaces)
          ├── unshare pid, net, mount
          ├── set up mount topology (ro-bind /, dev, proc, tmpfs, bind /workspace)
          ├── pass-fd: keep cei_fd open
          ├── chdir /workspace
          └── fork → exec /proc/self/fd/<cei_fd> intercept ...
                        │
                        cei intercept (PID 2)
                          ├── socketpair(AF_UNIX, SEQPACKET)
                          └── fork()
                                ├── child (PID 3):
                                │     set_no_new_privs()
                                │     install seccomp USER_NOTIF filter
                                │     send listener_fd → parent via SCM_RIGHTS
                                │     execvp(<command>)   ← intercepted by own filter
                                │
                                └── parent/supervisor (PID 2 continues):
                                      recv listener_fd
                                      loop:
                                        notif = listener.recv()
                                        handle: allow / deny / redirect
                                      waitpid(child)
                                      exit(child_code)
```

---

## Error Handling and Diagnostics

| Failure | Detection point | Behaviour |
|---|---|---|
| bwrap not found | `cei launch` startup | Fatal error with install hint |
| cei_fd not executable | kernel, at inner exec | bwrap reports exec failure; `cei launch` propagates exit code |
| CLOEXEC set on cei_fd | kernel, at inner exec | `/proc/self/fd/N` → `ENOENT` inside sandbox; add startup assertion |
| `ptrace_scope` ≥ 2 | `ceil` startup check | Warning; cei will fail at ptrace attach |
| `/proc` not mounted | inside sandbox | `cei` redirect fails with `ENOENT` on procfd path; always include `--proc` |
| unprivileged userns disabled | bwrap exec failure | Detect and advise setuid bwrap or `sysctl` change |

---

## What Is Explicitly Out of Scope for This Spec

- Network namespace policy (TUN device, proxy injection) — covered in `network_interception_design.md`
- Landlock integration inside `cei intercept` — separate hardening pass
- Seccomp filter coverage beyond `execve`/`execveat` — separate hardening pass
- Multi-project or nested sandboxes
- macOS / non-Linux platforms
