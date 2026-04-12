#![deny(unsafe_code)]

mod policy;
mod ptrace_rewrite;
mod seccomp_notify;
mod supervisor;

use std::ffi::CString;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, Subcommand};
use nix::cmsg_space;
use nix::sys::prctl::set_no_new_privs;
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, recvmsg,
    sendmsg, socketpair,
};
use nix::unistd::{ForkResult, execvp, fork};

#[derive(Debug, Parser)]
#[command(name = "cei")]
#[command(about = "execve sandboxing supervisor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run a command under execve interception.
    Intercept {
        /// Redirect execve of FROM to TO.  Repeatable.  Both paths must be absolute.
        /// Example: --redirect /usr/bin/python3=/opt/python/bin/python3.12
        #[arg(
            long = "redirect",
            value_name = "FROM=TO",
            action = ArgAction::Append,
        )]
        redirects: Vec<String>,

        /// Executable to run.
        command: String,
        /// Arguments forwarded to COMMAND.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Intercept {
            redirects,
            command,
            args,
        } => run_sandboxed(&command, &args, &redirects),
    }
}

fn run_sandboxed(command: &str, args: &[String], raw_redirects: &[String]) -> Result<()> {
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

    // SAFETY: we are single-threaded here and do not use any Rust
    // synchronisation primitives between this point and the exec/exit in
    // both branches, satisfying fork(2)'s async-signal-safety contract.
    #[expect(unsafe_code)]
    match unsafe { fork() }.context("fork")? {
        ForkResult::Child => {
            drop(parent_sock);
            // child_main never returns on success (exec replaces us).
            let e = child_main(child_sock.as_raw_fd(), command, args).unwrap_err();
            eprintln!("cei: child setup failed: {e:#}");
            std::process::exit(1);
        }
        ForkResult::Parent { child: child_pid } => {
            drop(child_sock);
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
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                // SAFETY: fd was received from the kernel via SCM_RIGHTS and is
                // a freshly allocated fd owned exclusively by this process.
                #[expect(unsafe_code)]
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    bail!("recvmsg: no fd received in SCM_RIGHTS message")
}
