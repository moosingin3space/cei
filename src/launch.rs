use std::env;
use std::ffi::{CString, OsString};
use std::fs;
use std::os::fd::{AsFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::unistd::execvp;

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
    pub bwrap_path: Option<PathBuf>,
    pub share_net: bool,
    pub unshare_user: bool,
    pub command: OsString,
    pub command_args: Vec<OsString>,
}

pub fn run_launch(config: LaunchConfig) -> Result<()> {
    let bwrap = resolve_bwrap(config.bwrap_path.as_deref())?;
    check_ptrace_scope();

    // Primary: open /proc/self/exe and clear O_CLOEXEC so the fd survives
    // execvp into bwrap. bwrap will bind-mount the fd at /run/cei, and
    // `cei intercept` will unmount it after forking.
    let (cei_arg, _fallback_path) = match open_cei_fd() {
        Ok(fd) => (CeiArg::Fd(fd), None),
        Err(e) => {
            eprintln!("cei: warning: could not open /proc/self/exe ({e:#}); \
                       falling back to host path");
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

    let argv = build_bwrap_argv(&config, &cei_arg);

    let bwrap_c = CString::new(bwrap.as_os_str().as_bytes())
        .context("bwrap path contains NUL byte")?;
    let c_argv: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_bytes()).context("bwrap argument contains NUL byte"))
        .collect::<Result<_>>()?;

    execvp(&bwrap_c, &c_argv).context("execvp bwrap")?;
    unreachable!()
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

fn build_bwrap_argv(config: &LaunchConfig, cei: &CeiArg<'_>) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec!["bwrap".into()];

    // Namespace flags
    argv.push("--unshare-pid".into());
    if config.unshare_user {
        argv.push("--unshare-user".into());
    }
    if !config.share_net {
        argv.push("--unshare-net".into());
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

    argv.push("--".into());
    argv.push(config.command.clone());
    for arg in &config.command_args {
        argv.push(arg.clone());
    }

    argv
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
        eprintln!(
            "cei: warning: /proc/sys/kernel/yama/ptrace_scope={val} — \
             ptrace is blocked system-wide regardless of parent-child relationship. \
             cei intercept will fail to attach. Set to 0 or 1 to use cei."
        );
    }
}
