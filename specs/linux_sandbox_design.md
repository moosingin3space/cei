# Linux Sandbox Design

## Goal

Provide a process sandbox that can run untrusted CLI commands while:

- allowing writes only under the current project directory (mapped to `/workspace` in the sandbox),
- intercepting `execve`/`execveat` from supervisor space,
- supporting binaries that do not rely on `LD_PRELOAD` (including static/Go binaries).

## Layered Architecture

The design uses multiple layers because no single mechanism covers all requirements.

1. Styrolite layer
- Creates mount, PID, network, IPC, and UTS namespaces.
- Uses read-only rootfs plus explicit writable mounts (`/workspace`, `/tmp`).
- Provides primary write confinement through mount layout.

2. seccomp USER_NOTIF layer
- Intercepts `execve` and `execveat` at syscall entry.
- Blocks calling thread and notifies a supervisor through a listener fd.
- Lets supervisor continue or deny execution and inject fds (`SECCOMP_IOCTL_NOTIF_ADDFD`).

3. ptrace (narrow use)
- Used only for register rewrite during intercepted exec calls.
- Swaps path argument register pointer (`rdi` for `execve`, `rsi` for `execveat` on x86_64)
  to a supervisor-controlled buffer.
- Avoids writing into the child's original path string, so read-only `.rodata` strings
  are supported.

4. memfd scratch page
- Shared mapping used for TOCTOU-safe path strings.
- Supervisor writes `/proc/self/fd/<N>` into fixed slots.
- Child uses read-only mapping address as rewritten exec path pointer.

## Write-Confinement Policy

Host policy baseline:

- Allowed writable host path: current working directory at launch time.
- In sandbox mount namespace:
  - rootfs mounted read-only,
  - host project bind-mounted read-write at `/workspace`,
  - `/tmp` mounted as tmpfs.

This gives practical "deny writes outside current directory" behavior through filesystem topology rather than per-syscall path filtering.

## Intercept-and-Redirect Flow (Per exec)

1. Child reaches `execve`/`execveat`.
2. seccomp sends USER_NOTIF event and blocks the task.
3. Supervisor validates notification id (`ID_VALID`).
4. Supervisor reads child path argument (`process_vm_readv`).
5. Supervisor resolves allow/deny/substitute policy.
6. On allow/substitute:
- supervisor opens target binary in host namespace,
- injects opened fd into child with `NOTIF_ADDFD`,
- writes `/proc/self/fd/<injected_fd>` into memfd scratch slot,
- swaps child exec path pointer register to scratch slot address with ptrace,
- revalidates notification id,
- sends `NOTIF_SEND` with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
7. Child resumes and kernel resolves the rewritten procfd path to injected inode.

## Security Properties

- Limits writes outside project directory via mount configuration.
- Keeps binary selection under supervisor control at exec boundary.
- Reduces path TOCTOU risk by avoiding direct child-memory path reuse.

## Known Limitations

- Current scaffold primarily enforces write controls via mount namespace; Landlock-specific controls are not yet wired in this crate version.
- `mmap(PROT_EXEC)` restrictions are not part of current baseline flow.
- UDP/raw socket policy is not fully represented by this scaffold.
- Shared-kernel isolation limitations still apply.

## Implementation Status in This Repo

Implemented in scaffold modules:

- `src/styrolite_launcher.rs`: namespace + mount request generation.
- `src/seccomp_notify.rs`: USER_NOTIF filter/listener/ioctl wrappers.
- `src/memfd_scratch.rs`: sealed memfd slot allocator.
- `src/ptrace_rewrite.rs`: x86_64 exec path pointer swap helper (`rdi`/`rsi`).
- `src/supervisor.rs`: notification processing loop skeleton.

Still to complete for production wiring:

- child bootstrap handshake for listener fd + scratch mapping address exchange,
- end-to-end supervisor process lifecycle integration from `main`,
- hardened policy engine for allow/deny/substitution decisions,
- broader test coverage (race, failure, and namespace edge cases).
