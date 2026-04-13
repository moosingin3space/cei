use std::env;
use std::ffi::{CString, OsString};
use std::fs;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, execvp, fork, pipe2};
use tracing::{error, info, warn};

use crate::policy::SandboxPolicy;
use crate::proxy::ProxyListener;

/// Default slirp4netns gateway — the sandbox can reach the host's loopback via this IP.
const SLIRP_HOST_IP: &str = "10.0.2.2";

/// Variables to strip from the environment before entering the sandbox.
const VARS_TO_STRIP: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "WAYLAND_DISPLAY",
];

/// How the `cei` binary is passed into the sandbox.
enum CeiArg<'a> {
    /// Primary path: open fd bound at `/run/cei` via `--bind-fd`.
    /// `intercept` will detach the mount after forking.
    Fd(i32),
    /// Fallback: the binary's host path, visible because the system directories
    /// are ro-bound into the sandbox.
    Path(&'a Path),
}

pub struct LaunchConfig {
    pub project: PathBuf,
    pub extra_ro_binds: Vec<(OsString, OsString)>,
    pub extra_binds: Vec<(OsString, OsString)>,
    pub redirects: Vec<String>,
    pub allow_http_hosts: Vec<String>,
    pub bwrap_path: Option<PathBuf>,
    pub share_net: bool,
    pub unshare_user: bool,
    pub command: OsString,
    pub command_args: Vec<OsString>,
}

pub fn run_launch(config: LaunchConfig) -> Result<()> {
    let bwrap = resolve_bwrap(config.bwrap_path.as_deref())?;
    check_ptrace_scope();

    // When network is isolated, slirp4netns bridges the sandbox's netns to the host.
    // We check for it early so we can give a clear error before any forks.
    let slirp_bin: Option<PathBuf> = if !config.share_net {
        Some(find_slirp4netns().context(
            "slirp4netns not found in PATH; install it (e.g. `dnf install slirp4netns`) \
             or pass --share-net to skip network isolation",
        )?)
    } else {
        None
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    let proxy_listener = rt.block_on(async { ProxyListener::bind("127.0.0.1:0").await })?;
    let proxy_port = proxy_listener.local_addr()?.port();

    // Inside the sandbox the proxy is reached via the slirp4netns gateway (NAT'd to our loopback),
    // not through 127.0.0.1 which belongs to the sandbox's own loopback in an unshared netns.
    let proxy_host: &str = if config.share_net {
        "127.0.0.1"
    } else {
        SLIRP_HOST_IP
    };

    // A pipe for bwrap --info-fd: bwrap writes {"child-pid": N} before exec'ing the init
    // process, giving us the PID we need to attach slirp4netns to the right network namespace.
    let (info_read, info_write) = if !config.share_net {
        let (r, w) = pipe2(OFlag::O_CLOEXEC).context("creating bwrap info pipe")?;
        (Some(r), Some(w))
    } else {
        (None, None)
    };
    // Capture the raw fd before the fork so both arms can see it without ownership issues.
    let info_write_raw: Option<i32> = info_write.as_ref().map(|w| w.as_raw_fd());

    // Primary: open /proc/self/exe and clear O_CLOEXEC so the fd survives
    // execvp into bwrap. bwrap will bind-mount the fd at /run/cei, and
    // `cei intercept` will unmount it after forking.
    let (cei_arg, _fallback_path) = match open_cei_fd() {
        Ok(fd) => (CeiArg::Fd(fd), None),
        Err(e) => {
            warn!(message = "cei: warning: could not open /proc/self/exe, falling back to host path", error = %e);
            let path = fs::read_link("/proc/self/exe")
                .context("resolving cei binary path via /proc/self/exe")?;
            (CeiArg::Path(Path::new("")), Some(path))
        }
    };
    // Reborrow so the fallback path lifetime works out.
    let cei_arg = match &_fallback_path {
        Some(p) => CeiArg::Path(p.as_path()),
        None => cei_arg,
    };

    filter_env();

    // SAFETY: fork is called before any threads are spawned (we use single-threaded runtime).
    #[expect(unsafe_code)]
    match unsafe { fork() }.context("fork")? {
        ForkResult::Child => {
            // The read end is only used in the parent.
            drop(info_read);
            // Clear O_CLOEXEC on the write end so bwrap inherits it across execvp.
            if let Some(fd) = info_write_raw {
                // SAFETY: fd is valid and we are the sole owner (write end of the info pipe).
                #[expect(unsafe_code)]
                let bfd = unsafe { BorrowedFd::borrow_raw(fd) };
                fcntl(bfd, FcntlArg::F_SETFD(FdFlag::empty()))
                    .context("clearing O_CLOEXEC on bwrap info pipe")?;
            }

            let argv = build_bwrap_argv(&config, &cei_arg, proxy_port, proxy_host, info_write_raw);

            let bwrap_c = CString::new(bwrap.as_os_str().as_bytes())
                .context("bwrap path contains NUL byte")?;
            let c_argv: Vec<CString> = argv
                .iter()
                .map(|a| CString::new(a.as_bytes()).context("bwrap argument contains NUL byte"))
                .collect::<Result<_>>()?;

            execvp(&bwrap_c, &c_argv).context("execvp bwrap")?;
            unreachable!()
        }
        ForkResult::Parent { child: child_pid } => {
            // Close the write end so reads on info_read return EOF when bwrap exits.
            drop(info_write);

            // Open a pidfd for the bwrap child.  A pidfd becomes readable (in
            // epoll terms) the moment the process exits, so we can await it
            // inside the tokio executor without blocking the event loop.
            //
            // SAFETY: child_pid was just returned by fork(); it is a valid live
            // process in our process group.
            #[expect(unsafe_code)]
            let bwrap_pidfd: OwnedFd = {
                let raw = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_open,
                        child_pid.as_raw() as libc::c_long,
                        0_i32,
                    )
                } as i32;
                if raw < 0 {
                    bail!("pidfd_open: {}", std::io::Error::last_os_error());
                }
                // SAFETY: raw is a freshly allocated fd we own.
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                fcntl(&owned, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
                    .context("O_NONBLOCK on bwrap pidfd")?;
                owned
            };

            // Read the sandbox PID from bwrap, then launch slirp4netns to wire up networking.
            let _slirp_child: Option<Child> = match (slirp_bin, info_read) {
                (Some(ref slirp), Some(r)) => {
                    let sandbox_pid = read_bwrap_child_pid(r)?;
                    info!(
                        sandbox_pid,
                        "attaching slirp4netns to sandbox network namespace"
                    );
                    Some(setup_slirp(slirp, sandbox_pid)?)
                }
                _ => None,
            };

            let mut policy = SandboxPolicy::from_current_dir()?;
            for host in config.allow_http_hosts {
                policy = policy.with_allowed_host(host);
            }
            let policy = Arc::new(policy);

            let exit_code = rt.block_on(async move {
                tokio::spawn(async move {
                    if let Err(e) = proxy_listener.run(policy).await {
                        error!(message = "proxy listener failed", error = %e);
                    }
                });

                // AsyncFd registers the pidfd with the tokio reactor (epoll).
                // When the child exits the fd becomes readable and the future
                // resolves, yielding the executor to handle proxy connections
                // the whole time the sandbox is alive.
                let async_pidfd = tokio::io::unix::AsyncFd::new(bwrap_pidfd)
                    .context("AsyncFd for bwrap pidfd")?;
                async_pidfd
                    .readable()
                    .await
                    .context("awaiting bwrap pidfd")?
                    .retain_ready();

                let status = waitpid(Some(child_pid), None).context("waitpid bwrap")?;
                info!(?status, "bwrap exited");
                Ok::<_, anyhow::Error>(match status {
                    WaitStatus::Exited(_, code) => code,
                    WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
                    _ => 1,
                })
            })?;
            std::process::exit(exit_code);
        }
    }
}

/// Open `/proc/self/exe`, clear `O_CLOEXEC`, and return the raw fd.
fn open_cei_fd() -> Result<i32> {
    let file = fs::File::open("/proc/self/exe").context("open /proc/self/exe")?;
    // Clear O_CLOEXEC while we still hold the File so we can use AsFd safely.
    fcntl(file.as_fd(), FcntlArg::F_SETFD(FdFlag::empty()))
        .context("clearing O_CLOEXEC on cei fd")?;
    Ok(file.into_raw_fd())
}

/// Parse a `HOST=GUEST` bind-mount argument.
pub fn parse_bind_pair(s: &str) -> Result<(OsString, OsString)> {
    let (host, guest) = s
        .split_once('=')
        .with_context(|| format!("bind '{s}' must be in HOST=GUEST form"))?;
    Ok((host.into(), guest.into()))
}

// ---------------------------------------------------------------------------
// bwrap argv
// ---------------------------------------------------------------------------

/// Guest path where the `cei` binary is bind-mounted when using the fd path.
const CEI_GUEST_PATH: &str = "/run/cei";

fn build_bwrap_argv(
    config: &LaunchConfig,
    cei: &CeiArg<'_>,
    proxy_port: u16,
    proxy_host: &str,
    info_fd: Option<i32>,
) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec!["bwrap".into()];

    // Namespace flags
    argv.push("--unshare-pid".into());
    // A user namespace is required for slirp4netns to configure the tap device
    // without root privileges.  When network isolation is active we implicitly
    // enable it even if the caller did not ask for it explicitly.
    if config.unshare_user || !config.share_net {
        argv.push("--unshare-user".into());
    }
    if !config.share_net {
        argv.push("--unshare-net".into());
    }

    // Ask bwrap to write {"child-pid": N} to the info pipe once the sandbox
    // is set up.  The parent uses this PID to attach slirp4netns.
    if let Some(fd) = info_fd {
        argv.extend(["--info-fd".into(), fd.to_string().into()]);
    }

    // Root is bwrap's internal tmpfs. Bind only what is needed so that new
    // mount points (like /workspace) can be created without fighting a
    // read-only rootfs.
    argv.extend(["--ro-bind".into(), "/usr".into(), "/usr".into()]);
    argv.extend(["--ro-bind".into(), "/etc".into(), "/etc".into()]);
    argv.extend(["--ro-bind".into(), "/var".into(), "/var".into()]);

    // On merged-usr systems /bin, /sbin, /lib, /lib64 are symlinks into /usr.
    // Recreate them in the sandbox; on older layouts they are real dirs to bind.
    for (guest, usr_target) in &[
        ("/bin", "usr/bin"),
        ("/sbin", "usr/sbin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
    ] {
        let host = Path::new(guest);
        if host.is_symlink() {
            argv.extend(["--symlink".into(), (*usr_target).into(), (*guest).into()]);
        } else if host.is_dir() {
            argv.extend(["--ro-bind".into(), (*guest).into(), (*guest).into()]);
        }
    }

    argv.extend(["--dev".into(), "/dev".into()]);
    argv.extend(["--proc".into(), "/proc".into()]);
    argv.extend(["--tmpfs".into(), "/tmp".into()]);
    argv.extend(["--tmpfs".into(), "/run".into()]);

    // Project directory — bwrap creates the mount point automatically.
    argv.extend([
        "--bind".into(),
        config.project.as_os_str().to_owned(),
        "/workspace".into(),
    ]);

    // User-supplied additional mounts
    for (host, guest) in &config.extra_ro_binds {
        argv.extend(["--ro-bind".into(), host.clone(), guest.clone()]);
    }
    for (host, guest) in &config.extra_binds {
        argv.extend(["--bind".into(), host.clone(), guest.clone()]);
    }

    // Primary path: bind the pre-opened fd at /run/cei (inside the fresh /run
    // tmpfs) so the binary has no host-filesystem path inside the sandbox.
    if let CeiArg::Fd(fd) = cei {
        argv.extend([
            "--bind-fd".into(),
            fd.to_string().into(),
            CEI_GUEST_PATH.into(),
        ]);
    }

    argv.extend(["--chdir".into(), "/workspace".into()]);

    // bwrap separator, then the inner cei invocation
    argv.push("--".into());

    match cei {
        CeiArg::Fd(_) => {
            argv.push(CEI_GUEST_PATH.into());
            argv.push("intercept".into());
            // Tell intercept to unmount itself after forking.
            argv.extend(["--detach-mount".into(), CEI_GUEST_PATH.into()]);
        }
        CeiArg::Path(p) => {
            argv.push(p.as_os_str().to_owned());
            argv.push("intercept".into());
        }
    }

    for r in &config.redirects {
        argv.push("--redirect".into());
        argv.push(r.into());
    }

    // Tell intercept the proxy address so it can inject http_proxy / https_proxy.
    // The host part differs: in an unshared netns the sandbox reaches the host's
    // loopback via the slirp4netns gateway; in a shared netns it's just 127.0.0.1.
    argv.push("--proxy-host".into());
    argv.push(proxy_host.into());
    argv.push("--proxy-port".into());
    argv.push(proxy_port.to_string().into());

    argv.push("--".into());
    argv.push(config.command.clone());
    for arg in &config.command_args {
        argv.push(arg.clone());
    }

    argv
}

// ---------------------------------------------------------------------------
// Network namespace bridging — slirp4netns
// ---------------------------------------------------------------------------

/// Find the `slirp4netns` binary in `$PATH`.
fn find_slirp4netns() -> Option<PathBuf> {
    if let Ok(path_var) = env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = Path::new(dir).join("slirp4netns");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Poll `fd` for readability with a millisecond timeout.
/// Returns `true` if data is available, `false` if the timeout expired.
fn poll_readable(fd: BorrowedFd<'_>, timeout_ms: i32) -> Result<bool> {
    let mut pollfds = [PollFd::new(fd, PollFlags::POLLIN)];
    let timeout = PollTimeout::try_from(timeout_ms).unwrap_or(PollTimeout::MAX);
    let n = poll(&mut pollfds, timeout).context("poll")?;
    Ok(n > 0)
}

/// Read the sandbox child PID from bwrap's `--info-fd` output.
///
/// bwrap writes `{"child-pid": N}\n` to the fd after namespace setup and
/// before exec'ing the init process.  The PID is in the host's PID namespace.
fn read_bwrap_child_pid(r: OwnedFd) -> Result<u32> {
    // Wait up to 10 s for bwrap to write the info JSON.  An infinite block here
    // almost always means bwrap failed to set up the user/network namespace.
    if !poll_readable(r.as_fd(), 10_000)? {
        bail!(
            "timed out after 10s waiting for bwrap --info-fd; \
             bwrap may have failed to set up the user/network namespace \
             (check if kernel.unprivileged_userns_clone is enabled)"
        );
    }
    // SAFETY: we own this fd; wrapping it in File transfers ownership cleanly.
    #[expect(unsafe_code)]
    let mut file = unsafe { fs::File::from_raw_fd(r.into_raw_fd()) };
    let mut buf = [0u8; 512];
    let n = file.read(&mut buf).context("reading bwrap info-fd")?;
    if n == 0 {
        bail!("bwrap closed info-fd without writing child-pid (did bwrap exit early?)");
    }
    let s = std::str::from_utf8(&buf[..n]).context("bwrap info-fd output is not UTF-8")?;
    parse_child_pid_json(s)
}

fn parse_child_pid_json(s: &str) -> Result<u32> {
    let idx = s
        .find("child-pid")
        .context("\"child-pid\" not found in bwrap info JSON")?;
    let rest = &s[idx + "child-pid".len()..];
    let start = rest
        .find(|c: char| c.is_ascii_digit())
        .context("no digit after \"child-pid\" in bwrap info JSON")?;
    let num: String = rest[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num.parse::<u32>().context("parsing child-pid as u32")
}

/// Attach `slirp4netns` to the network namespace of `sandbox_pid`.
///
/// Uses `--configure` so slirp4netns sets up the tap device, IP address
/// (10.0.2.100/24), default route (via 10.0.2.2), and lo.  The `--ready-fd`
/// pipe is used to wait until the network is fully configured before
/// returning.
///
/// slirp4netns stays alive as a background process and exits automatically
/// when the network namespace is destroyed (i.e., when all sandbox processes
/// exit).
fn setup_slirp(slirp_bin: &Path, sandbox_pid: u32) -> Result<Child> {
    let (ready_read, ready_write) =
        pipe2(OFlag::O_CLOEXEC).context("creating slirp4netns ready pipe")?;

    // Clear O_CLOEXEC so slirp4netns inherits the write end across exec.
    let ready_write_fd = ready_write.as_raw_fd();
    fcntl(&ready_write, FcntlArg::F_SETFD(FdFlag::empty()))
        .context("clearing O_CLOEXEC on slirp ready-fd")?;

    let child = Command::new(slirp_bin)
        .args([
            "--configure",
            "--mtu=65520",
            &format!("--ready-fd={ready_write_fd}"),
            &sandbox_pid.to_string(),
            "tap0",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning slirp4netns")?;

    // Close the write end in this process so we detect EOF if slirp exits early.
    drop(ready_write);

    // Wait up to 10 s for slirp4netns to signal readiness.
    if !poll_readable(ready_read.as_fd(), 10_000)? {
        bail!(
            "timed out after 10s waiting for slirp4netns readiness; \
             slirp4netns may have failed to configure the tap device in the sandbox netns"
        );
    }

    // Block until slirp4netns signals readiness (writes 1 byte) or exits (EOF).
    // SAFETY: we own this fd.
    #[expect(unsafe_code)]
    let mut ready_file = unsafe { fs::File::from_raw_fd(ready_read.into_raw_fd()) };
    let mut buf = [0u8; 1];
    let n = ready_file
        .read(&mut buf)
        .context("waiting for slirp4netns ready signal")?;
    if n == 0 {
        bail!("slirp4netns exited before signalling readiness; check stderr for details");
    }

    info!(sandbox_pid, proxy_host = SLIRP_HOST_IP, "slirp4netns ready");
    Ok(child)
}

// ---------------------------------------------------------------------------
// bwrap path resolution
// ---------------------------------------------------------------------------

fn resolve_bwrap(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }

    if let Ok(p) = env::var("BWRAP") {
        let p = PathBuf::from(&p);
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "BWRAP={p:?} is set but does not point to a regular file; \
             install bubblewrap or set --bwrap"
        );
    }

    if let Ok(path_var) = env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = Path::new(dir).join("bwrap");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    bail!(
        "bwrap not found in PATH. \
         Install bubblewrap (e.g. `dnf install bubblewrap` / `apt install bubblewrap`) \
         or pass --bwrap <path>."
    )
}

// ---------------------------------------------------------------------------
// Environment filtering
// ---------------------------------------------------------------------------

fn filter_env() {
    // SAFETY: called just before execvp; we are single-threaded at this point
    // (no other threads exist after fork, and we have not spawned any), so
    // mutating the environment has no data-race risk.
    #[expect(unsafe_code)]
    unsafe {
        for &var in VARS_TO_STRIP {
            env::remove_var(var);
        }

        // Strip any BWRAP_* and CEI_* internals that must not leak inward.
        let to_remove: Vec<String> = env::vars()
            .map(|(k, _)| k)
            .filter(|k| k.starts_with("BWRAP_") || k.starts_with("CEI_"))
            .collect();
        for k in to_remove {
            env::remove_var(k);
        }

        // Inject workspace-centric defaults.
        env::set_var("HOME", "/workspace");
        env::set_var("TMPDIR", "/tmp");
    }
}

// ---------------------------------------------------------------------------
// ptrace_scope check
// ---------------------------------------------------------------------------

fn check_ptrace_scope() {
    let Ok(s) = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") else {
        return;
    };
    let val: i32 = s.trim().parse().unwrap_or(0);
    if val >= 2 {
        warn!(
            message = "cei: warning: ptrace is blocked system-wide",
            ptrace_scope = val,
            advice = "Set to 0 or 1 to use cei"
        );
    }
}
