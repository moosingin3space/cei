# cei

CLI execution interception skeleton for Linux sandboxes.

Design spec: `specs/linux_sandbox_design.md`.

This scaffold wires:

- Styrolite namespace/mount setup with a read-only rootfs.
- Writable bind mount of the current host directory into `/workspace`.
- seccomp `USER_NOTIF` interception for `execve` and `execveat`.
- Supervisor-side fd injection (`SECCOMP_IOCTL_NOTIF_ADDFD`).
- memfd scratch slots for TOCTOU-safe `/proc/self/fd/N` path injection.
- ptrace register rewrite for `rdi` on x86_64 exec interceptions.

## Layout

- `src/main.rs`: CLI (`plan`, `run`) and high-level flow.
- `src/policy.rs`: current-directory write policy model.
- `src/styrolite_launcher.rs`: Styrolite request builder and launcher.
- `src/seccomp_notify.rs`: seccomp listener install + USER_NOTIF ioctl wrappers.
- `src/memfd_scratch.rs`: sealed memfd scratch-page slot allocator.
- `src/ptrace_rewrite.rs`: minimal ptrace register rewrite helper.
- `src/supervisor.rs`: notification handling loop skeleton.

## Usage

Print the Styrolite config generated from the current working directory policy:

```bash
cargo run -- plan --rootfs <rootfs> --command <command> [--arg <arg> ...]
```

Launch with Styrolite (skeleton mode):

```bash
cargo run -- run --styrolite-bin <path-to-styrolite-bin> --rootfs <rootfs> --command <command> [--arg <arg> ...]
```

## Important skeleton boundaries

- The supervisor runtime is implemented as modules but not fully connected to a child bootstrap handshake in `main` yet.
- Landlock-specific hooks are not exposed by `styrolite = 0.3.1`; this scaffold enforces write confinement primarily via mount layout (`rootfs_readonly + writable /workspace bind`).
- You still need to wire child pre-exec setup for scratch-page mapping and listener-fd transport to complete the full design.
