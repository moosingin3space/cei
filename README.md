# cei

`execve` interception sandbox supervisor for Linux.

Design spec: `specs/linux_sandbox_design.md`.

## How it works

`cei` forks a child, intercepts every `execve`/`execveat` the child (and any of its descendants) makes, and can allow, deny, or silently redirect them to a different binary — all without modifying the child program.

The mechanism:

1. **Setup** — Parent creates an `AF_UNIX SOCK_SEQPACKET` socket pair and forks.
2. **Child** — Installs a seccomp `USER_NOTIF` filter that routes all `execve`/`execveat` syscalls to the supervisor, sends the resulting listener fd to the parent via `SCM_RIGHTS`, then execs the target command (which the supervisor immediately allows).
3. **Supervisor loop** — For each notification the kernel delivers, the supervisor consults the policy and either:
   - **Allows** — sends `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
   - **Denies** — sends `EPERM`.
   - **Redirects** — opens the replacement binary, injects its fd into the child process as a fixed fd number via `SECCOMP_IOCTL_NOTIF_ADDFD`, writes the path `/proc/self/fd/<N>` onto the child's stack below the x86-64 red zone via `process_vm_writev`, rewrites the exec path pointer register (`rdi` for `execve`, `rsi` for `execveat`) via ptrace, then sends `CONTINUE`. The kernel executes the replacement binary.

Using the child's stack for the injected path string is TOCTOU-safe and works regardless of where the original pathname lived (`.rodata`, heap, another stack frame).

## Source layout

| File                    | Purpose                                                                |
| ----------------------- | ---------------------------------------------------------------------- |
| `src/main.rs`           | CLI (`run` subcommand), fork/exec orchestration, SCM_RIGHTS fd passing |
| `src/policy.rs`         | `SandboxPolicy`: workspace write policy and exec redirect table        |
| `src/seccomp_notify.rs` | Seccomp `USER_NOTIF` listener installation and ioctl wrappers          |
| `src/ptrace_rewrite.rs` | ptrace register rewrite helper (x86-64)                                |
| `src/supervisor.rs`     | Supervisor notification-handling loop                                  |

## Usage

```
cei run [--redirect FROM=TO]... <command> [args...]
```

Run `<command>` under execve interception. Each `--redirect` entry redirects
an exact exec path: when the supervised process tries to exec `FROM`, it runs
`TO` instead. Both paths must be absolute.

**Example** — transparently swap one Python interpreter for another:

```bash
cei run --redirect /usr/bin/python3=/opt/python/bin/python3.12 my-script.py arg1
```

**Example** — multiple redirects:

```bash
cei run \
  --redirect /usr/bin/node=/opt/node20/bin/node \
  --redirect /usr/bin/npm=/opt/node20/bin/npm \
  bash
```

## Platform requirements

- Linux kernel ≥ 5.9 (seccomp `USER_NOTIF` with `SECCOMP_IOCTL_NOTIF_ADDFD`)
- x86-64 only (the ptrace register rewrite is architecture-specific)
- Works under the default Yama `ptrace_scope=1` without special capabilities, since the supervisor is the direct parent of the traced process. `ptrace_scope=2` requires `CAP_SYS_PTRACE`; `ptrace_scope=3` blocks ptrace entirely.
