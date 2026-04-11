use std::ffi::CString;

use anyhow::{Context, Result, bail};

use crate::policy::SandboxPolicy;
use crate::ptrace_rewrite::write_path_and_swap_pointer;
use crate::seccomp_notify::{ExecNotification, SeccompListener};

/// fd number injected into the supervised process for exec redirection.
/// Must be high enough that it is unlikely to already be open in the child.
const INJECTED_FD: u32 = 1000;

pub struct Supervisor {
    policy: SandboxPolicy,
    listener: SeccompListener,
}

impl Supervisor {
    pub fn new(policy: SandboxPolicy, listener: SeccompListener) -> Self {
        Self { policy, listener }
    }

    /// Drive the notification loop until no more supervised processes exist,
    /// then reap `child_pid` and return its exit code.
    pub fn run_until_exit(&self, child_pid: libc::pid_t) -> Result<i32> {
        loop {
            match self.listener.recv() {
                Ok(notif) => self.handle_notification(notif)?,
                Err(_) => break,
            }
        }

        let mut status = 0i32;
        unsafe { libc::waitpid(child_pid, &mut status, 0) };

        Ok(if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        })
    }

    fn handle_notification(&self, notif: ExecNotification) -> Result<()> {
        if !self.listener.notif_id_valid(notif.id)? {
            return Ok(());
        }

        let path_addr = path_arg_addr(notif).context("unsupported syscall for exec path")?;
        let path = read_child_cstring(notif.pid as i32, path_addr)
            .unwrap_or_else(|_| "<unknown>".to_string());

        if let Some(replacement) = self.policy.exec_redirect(&path) {
            eprintln!(
                "[supervisor] pid={} redirect: {path} -> {replacement}",
                notif.pid
            );
            let replacement = replacement.to_owned();
            self.redirect_exec(notif, &replacement)?;
        } else if self.policy.exec_allowed(&path) {
            eprintln!("[supervisor] pid={} allow: {path}", notif.pid);
            self.listener.send_continue(notif.id)?;
        } else {
            eprintln!("[supervisor] pid={} deny: {path}", notif.pid);
            self.listener.send_errno(notif.id, libc::EPERM)?;
        }

        Ok(())
    }

    /// Rewrite an execve in-flight to run `replacement` instead.
    ///
    /// Mechanism:
    ///  1. Open `replacement` on the supervisor side.
    ///  2. Inject the fd into the supervised process as `INJECTED_FD` (no
    ///     O_CLOEXEC so the fd survives the exec).
    ///  3. Write "/proc/self/fd/<INJECTED_FD>" onto the child's stack below the
    ///     red zone via process_vm_writev (stack is always writable and present
    ///     after any exec, unlike a pre-mapped scratch page).
    ///  4. Swap the exec path pointer register (rdi for execve, rsi for
    ///     execveat) to point at that stack location.
    ///  5. Send CONTINUE — the kernel executes the replacement binary.
    fn redirect_exec(&self, notif: ExecNotification, replacement: &str) -> Result<()> {
        // Open the replacement binary in the supervisor.
        let c_replacement = CString::new(replacement).context("replacement path contains NUL")?;
        let host_fd =
            unsafe { libc::open(c_replacement.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if host_fd < 0 {
            let e = std::io::Error::last_os_error();
            let _ = self
                .listener
                .send_errno(notif.id, e.raw_os_error().unwrap_or(libc::ENOENT));
            return Err(e).with_context(|| format!("opening replacement binary: {replacement}"));
        }

        // Inject the fd into the supervised process.  newfd_flags = 0: no
        // O_CLOEXEC, so the fd is visible as /proc/self/fd/INJECTED_FD during exec.
        let inject_result = self.listener.add_fd(notif.id, host_fd, INJECTED_FD, 0);
        unsafe { libc::close(host_fd) };
        inject_result.context("injecting replacement binary fd into supervised process")?;

        // Write "/proc/self/fd/INJECTED_FD\0" to the child's stack and rewrite
        // the path pointer register in one ptrace pass.
        let path = format!("/proc/self/fd/{INJECTED_FD}\0");
        write_path_and_swap_pointer(notif.pid as i32, notif.syscall_nr, path.as_bytes())
            .context("rewriting exec path pointer register")?;

        if !self.listener.notif_id_valid(notif.id)? {
            return Ok(());
        }

        self.listener.send_continue(notif.id)
    }
}

fn path_arg_addr(notif: ExecNotification) -> Result<u64> {
    if notif.syscall_nr == libc::SYS_execve as i32 {
        Ok(notif.arg0)
    } else if notif.syscall_nr == libc::SYS_execveat as i32 {
        Ok(notif.arg1)
    } else {
        bail!("unsupported syscall {}", notif.syscall_nr)
    }
}

// --- child memory helpers ---

fn read_child_cstring(pid: i32, child_addr: u64) -> Result<String> {
    let mut buf = vec![0u8; 4096];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: child_addr as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let n = unsafe { libc::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("process_vm_readv");
    }

    let nul = buf[..n as usize]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(n as usize);
    Ok(String::from_utf8_lossy(&buf[..nul]).into_owned())
}
