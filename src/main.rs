#![deny(unsafe_code)]

mod launch;
mod policy;
mod ptrace_rewrite;
mod seccomp_notify;
mod supervisor;

use std::ffi::CString;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, Subcommand};
use nix::cmsg_space;
use nix::errno::Errno;
use nix::mount::{MntFlags, umount2};
use nix::sys::prctl::set_no_new_privs;
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg,
    sendmsg, socketpair,
};
use nix::unistd::{ForkResult, execvp, fork};
use tracing::error;

#[derive(Debug, Parser)]
#[command(name = "cei")]
#[command(about = "execve sandboxing supervisor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run a command inside a bubblewrap sandbox with execve interception.
    ///
    /// Opens a bubblewrap container (read-only rootfs, fresh /dev, /proc, /tmp,
    /// /run; read-write /workspace bound to --project), then executes
    /// `cei intercept` as PID 2 inside it.
    Launch {
        /// Host path to mount read-write at /workspace.
        /// Defaults to the current working directory.
        #[arg(long, value_name = "PATH")]
        project: Option<PathBuf>,

        /// Additional read-only bind mount (repeatable). Format: HOST=GUEST.
        #[arg(long = "ro-bind", value_name = "HOST=GUEST", action = ArgAction::Append)]
        ro_binds: Vec<String>,

        /// Additional read-write bind mount (repeatable). Format: HOST=GUEST.
        #[arg(long = "bind", value_name = "HOST=GUEST", action = ArgAction::Append)]
        binds: Vec<String>,

        /// Redirect execve of FROM to TO inside the sandbox (repeatable).
        /// Forwarded verbatim to `cei intercept`.
        #[arg(long = "redirect", value_name = "FROM=TO", action = ArgAction::Append)]
        redirects: Vec<String>,

        /// Path to the bwrap binary. Defaults to $BWRAP or which(bwrap).
        #[arg(long, value_name = "PATH")]
        bwrap: Option<PathBuf>,

        /// Do not unshare the network namespace (default: network is unshared).
        #[arg(long)]
        share_net: bool,

        /// Enter a user namespace. Required on systems that disable unprivileged
        /// mount namespaces (RHEL-like) unless bwrap is setuid root.
        #[arg(long)]
        unshare_user: bool,

        /// Executable to run inside the sandbox.
        command: String,

        /// Arguments forwarded to COMMAND.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run a command under execve interception (used internally by `cei launch`).
    Intercept {
        /// Redirect execve of FROM to TO.  Repeatable.  Both paths must be absolute.
        /// Example: --redirect /usr/bin/python3=/opt/python/bin/python3.12
        #[arg(
            long = "redirect",
            value_name = "FROM=TO",
            action = ArgAction::Append,
        )]
        redirects: Vec<String>,

        /// Internal: guest path to lazy-unmount after fork, then drop caps.
        /// Set by `cei launch` when using --bind-fd to pass the cei binary.
        #[arg(long = "detach-mount", value_name = "PATH", hide = true)]
        detach_mount: Option<PathBuf>,

        /// Executable to run.
        command: String,
        /// Arguments forwarded to COMMAND.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Launch {
            project,
            ro_binds,
            binds,
            redirects,
            bwrap,
            share_net,
            unshare_user,
            command,
            args,
        } => {
            let project = match project {
                Some(p) => p,
                None => std::env::current_dir().context("getting current working directory")?,
            };
            let extra_ro_binds = ro_binds
                .iter()
                .map(|s| launch::parse_bind_pair(s))
                .collect::<Result<Vec<_>>>()?;
            let extra_binds = binds
                .iter()
                .map(|s| launch::parse_bind_pair(s))
                .collect::<Result<Vec<_>>>()?;
            launch::run_launch(launch::LaunchConfig {
                project,
                extra_ro_binds,
                extra_binds,
                redirects,
                bwrap_path: bwrap,
                share_net,
                unshare_user,
                command: command.into(),
                command_args: args.into_iter().map(Into::into).collect(),
            })
        }
        Commands::Intercept {
            redirects,
            detach_mount,
            command,
            args,
        } => run_sandboxed(&command, &args, &redirects, detach_mount.as_deref()),
    }
}

fn run_sandboxed(
    command: &str,
    args: &[String],
    raw_redirects: &[String],
    detach_mount: Option<&Path>,
) -> Result<()> {
    // Socketpair used to pass the seccomp listener fd from child to parent.
    let (parent_sock, child_sock) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .context("socketpair")?;

    // Parse and validate redirects before forking so errors surface immediately.
    let mut policy = policy::SandboxPolicy::from_current_dir()?;
    for entry in raw_redirects {
        let (from, to) = entry
            .split_once('=')
            .with_context(|| format!("--redirect '{entry}' must be in FROM=TO form"))?;
        policy = policy.with_redirect(from, to);
    }
    // When the cei binary was bind-mounted at a guest path, deny exec of that
    // path so the sandboxed process cannot re-execute the supervisor binary.
    if let Some(p) = detach_mount {
        policy = policy.with_denied_exec(p.to_string_lossy().as_ref());
    }

    // SAFETY: we are single-threaded here and do not use any Rust
    // synchronisation primitives between this point and the exec/exit in
    // both branches, satisfying fork(2)'s async-signal-safety contract.
    #[expect(unsafe_code)]
    match unsafe { fork() }.context("fork")? {
        ForkResult::Child => {
            drop(parent_sock);
            // child_main never returns on success (exec replaces us).
            let e = child_main(child_sock.as_raw_fd(), command, args).unwrap_err();
            error!(message = "cei: child setup failed", error = %e);
            std::process::exit(1);
        }
        ForkResult::Parent { child: child_pid } => {
            drop(child_sock);
            if let Some(path) = detach_mount {
                detach_and_harden(path)?;
            }
            parent_main(parent_sock, child_pid.as_raw(), policy)
        }
    }
}

/// Child: install seccomp USER_NOTIF on execve, hand listener fd to the
/// parent supervisor, then exec the target program.
fn child_main(sock: RawFd, command: &str, args: &[String]) -> Result<()> {
    // Required before seccomp installation.
    set_no_new_privs().context("prctl PR_SET_NO_NEW_PRIVS")?;

    let listener = seccomp_notify::SeccompListener::install_exec_listener()
        .context("installing seccomp exec listener")?;

    send_fd(sock, listener.as_raw_fd()).context("sending listener fd to supervisor")?;
    drop(listener); // Close our copy; the filter itself stays active. sock is CLOEXEC.

    let c_cmd = CString::new(command).context("command contains NUL")?;
    let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
    c_args.push(c_cmd.clone());
    for a in args {
        c_args.push(CString::new(a.as_str()).context("argument contains NUL")?);
    }

    // This exec is itself intercepted; the supervisor will allow it.
    execvp(&c_cmd, &c_args).context("execvp")?;
    unreachable!()
}

/// Parent: receive listener fd from child, run supervisor event loop.
fn parent_main(sock: OwnedFd, child_pid: i32, policy: policy::SandboxPolicy) -> Result<()> {
    let fd = recv_fd(sock.as_raw_fd()).context("receiving listener fd from child")?;
    let listener = seccomp_notify::SeccompListener::from_owned_fd(fd);
    let sup = supervisor::Supervisor::new(policy, listener);
    let code = sup.run_until_exit(child_pid)?;
    std::process::exit(code);
}

// --- post-fork hardening ---

/// Called in the supervisor (parent) immediately after `fork()` when
/// `cei launch` used `--bind-fd` to mount the binary at a guest path.
///
/// 1. Lazy-detaches the bind mount — the path disappears from the namespace
///    before the sandboxed child ever execs its command.
/// 2. Drops all capability sets inherited from a user namespace.
/// 3. Calls `set_no_new_privs` on the supervisor itself.
fn detach_and_harden(path: &Path) -> Result<()> {
    // 1. Detach the bind mount.
    umount2(path, MntFlags::MNT_DETACH)
        .or_else(|e| {
            // EPERM: bwrap clears all caps (including bounding set) before
            // exec, so umount2 is not available inside the sandbox — not fatal.
            if e == Errno::EPERM { Ok(()) } else { Err(e) }
        })
        .with_context(|| format!("umount2 {}", path.display()))?;

    // 2. Drop effective + permitted + inheritable capability sets.
    //    When --unshare-user is in effect the process holds a full cap set
    //    inside the user namespace; zero it out.  Outside a user namespace
    //    the sets are already empty and set_capabilities is a no-op.
    if let Ok(mut caps) = rustix::thread::capabilities(None) {
        caps.effective = rustix::thread::CapabilityFlags::empty();
        caps.permitted = rustix::thread::CapabilityFlags::empty();
        caps.inheritable = rustix::thread::CapabilityFlags::empty();
        rustix::thread::set_capabilities(None, caps).ok();
    }

    // 3. Clear ambient capability set.
    rustix::thread::clear_ambient_capability_set().ok();

    // 4. Prevent future privilege re-acquisition via exec.
    set_no_new_privs().context("set_no_new_privs in supervisor")?;

    Ok(())
}

// --- SCM_RIGHTS fd-passing helpers ---

fn send_fd(sock: RawFd, fd: RawFd) -> Result<()> {
    let dummy = [0u8; 1];
    let iov = [IoSlice::new(&dummy)];
    let fds = [fd];
    let cmsgs = [ControlMessage::ScmRights(&fds)];
    sendmsg::<()>(sock, &iov, &cmsgs, MsgFlags::empty(), None).context("sendmsg SCM_RIGHTS")?;
    Ok(())
}

fn recv_fd(sock: RawFd) -> Result<OwnedFd> {
    let mut dummy = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut dummy)];
    let mut cmsg_buf = cmsg_space!(RawFd);
    let msg =
        recvmsg::<()>(sock, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty()).context("recvmsg")?;

    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(&fd) = fds.first()
        {
            // SAFETY: fd was received from the kernel via SCM_RIGHTS and is
            // a freshly allocated fd owned exclusively by this process.
            #[expect(unsafe_code)]
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
    bail!("recvmsg: no fd received in SCM_RIGHTS message")
}
