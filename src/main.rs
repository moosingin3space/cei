mod policy;
mod ptrace_rewrite;
mod seccomp_notify;
mod supervisor;

use std::ffi::CString;
use std::mem::size_of;
use std::os::fd::{FromRawFd, OwnedFd};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, Subcommand};

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
    Run {
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
        Commands::Run {
            redirects,
            command,
            args,
        } => run_sandboxed(&command, &args, &redirects),
    }
}

fn run_sandboxed(command: &str, args: &[String], raw_redirects: &[String]) -> Result<()> {
    // Socketpair used to pass the seccomp listener fd from child to parent.
    let mut socks = [0i32; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            socks.as_mut_ptr(),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("socketpair");
    }
    // Parse and validate redirects before forking so errors surface immediately.
    let mut policy = policy::SandboxPolicy::from_current_dir()?;
    for entry in raw_redirects {
        let (from, to) = entry
            .split_once('=')
            .with_context(|| format!("--redirect '{entry}' must be in FROM=TO form"))?;
        policy = policy.with_redirect(from, to);
    }

    let [parent_sock, child_sock] = socks;

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(std::io::Error::last_os_error()).context("fork"),
        0 => {
            unsafe { libc::close(parent_sock) };
            // child_main never returns on success (exec replaces us).
            let e = child_main(child_sock, command, args).unwrap_err();
            eprintln!("cei: child setup failed: {e:#}");
            unsafe { libc::_exit(1) };
        }
        child_pid => {
            unsafe { libc::close(child_sock) };
            let result = parent_main(parent_sock, child_pid, policy);
            unsafe { libc::close(parent_sock) };
            result
        }
    }
}

/// Child: install seccomp USER_NOTIF on execve, hand listener fd to the
/// parent supervisor, then exec the target program.
fn child_main(sock: i32, command: &str, args: &[String]) -> Result<()> {
    // Required before seccomp installation.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1usize, 0usize, 0usize, 0usize) } < 0 {
        return Err(std::io::Error::last_os_error()).context("prctl PR_SET_NO_NEW_PRIVS");
    }

    let listener = seccomp_notify::SeccompListener::install_exec_listener()
        .context("installing seccomp exec listener")?;

    send_fd(sock, listener.as_raw_fd()).context("sending listener fd to supervisor")?;
    unsafe { libc::close(sock) };
    drop(listener); // Close our copy; the filter itself stays active.

    let c_cmd = CString::new(command).context("command contains NUL")?;
    let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
    c_args.push(c_cmd.clone());
    for a in args {
        c_args.push(CString::new(a.as_str()).context("argument contains NUL")?);
    }
    let c_argv: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // This exec is itself intercepted; the supervisor will allow it.
    unsafe { libc::execvp(c_cmd.as_ptr(), c_argv.as_ptr()) };
    Err(std::io::Error::last_os_error()).context("execvp")
}

/// Parent: receive listener fd from child, run supervisor event loop.
fn parent_main(sock: i32, child_pid: libc::pid_t, policy: policy::SandboxPolicy) -> Result<()> {
    let fd = recv_fd(sock).context("receiving listener fd from child")?;
    let listener = seccomp_notify::SeccompListener::from_owned_fd(fd);
    let sup = supervisor::Supervisor::new(policy, listener);
    let code = sup.run_until_exit(child_pid)?;
    std::process::exit(code);
}

// --- SCM_RIGHTS fd-passing helpers ---

// cmsghdr requires pointer alignment; a plain [u8] buffer is only byte-aligned.
#[repr(C, align(8))]
struct CmsgBuf([u8; 32]);

fn send_fd(sock: i32, fd: i32) -> Result<()> {
    let mut cmsg_buf = CmsgBuf([0u8; 32]);
    let dummy = 0u8;
    let mut iov = libc::iovec {
        iov_base: &dummy as *const u8 as *mut libc::c_void,
        iov_len: 1,
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.0.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            bail!("CMSG_FIRSTHDR returned null");
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as _;
        std::ptr::write(libc::CMSG_DATA(cmsg) as *mut i32, fd);
        msg.msg_controllen = (*cmsg).cmsg_len as _;
    }

    if unsafe { libc::sendmsg(sock, &msg, 0) } < 0 {
        return Err(std::io::Error::last_os_error()).context("sendmsg SCM_RIGHTS");
    }
    Ok(())
}

fn recv_fd(sock: i32) -> Result<OwnedFd> {
    let mut cmsg_buf = CmsgBuf([0u8; 32]);
    let mut dummy = 0u8;
    let mut iov = libc::iovec {
        iov_base: &mut dummy as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.0.len();

    if unsafe { libc::recvmsg(sock, &mut msg, 0) } < 0 {
        return Err(std::io::Error::last_os_error()).context("recvmsg");
    }

    let received_fd = unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            bail!("recvmsg: no control message");
        }
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            bail!("recvmsg: unexpected cmsg type");
        }
        std::ptr::read(libc::CMSG_DATA(cmsg) as *const i32)
    };

    Ok(unsafe { OwnedFd::from_raw_fd(received_fd) })
}
