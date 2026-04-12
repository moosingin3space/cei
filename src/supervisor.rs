use std::fs::File;
use std::io::IoSliceMut;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result, bail};
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;

use crate::policy::SandboxPolicy;
use crate::ptrace_rewrite::write_path_and_swap_pointer;
use crate::seccomp_notify::{ExecNotification, SeccompListener};

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
    pub fn run_until_exit(&self, child_pid: i32) -> Result<i32> {
        while let Ok(notif) = self.listener.recv() {
            self.handle_notification(notif)?;
        }

        let status = waitpid(Some(Pid::from_raw(child_pid)), None)?;
        Ok(match status {
            WaitStatus::Exited(_, code) => code,
            WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
            _ => 0,
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
    ///  2. Inject the fd into the supervised process, letting the kernel choose
    ///     an unused target fd (no O_CLOEXEC so the fd survives the exec).
    ///  3. Write "/proc/self/fd/<allocated-fd>" onto the child's stack below
    ///     the red zone via process_vm_writev (stack is always writable and
    ///     present after any exec, unlike a pre-mapped scratch page).
    ///  4. Swap the exec path pointer register (rdi for execve, rsi for
    ///     execveat) to point at that stack location.
    ///  5. Send CONTINUE — the kernel executes the replacement binary.
    fn redirect_exec(&self, notif: ExecNotification, replacement: &str) -> Result<()> {
        // Open the replacement binary in the supervisor (read-only; std sets CLOEXEC).
        let host_file = File::open(replacement)
            .inspect_err(|e| {
                let errno = e.raw_os_error().unwrap_or(libc::ENOENT);
                let _ = self.listener.send_errno(notif.id, errno);
            })
            .with_context(|| format!("opening replacement binary: {replacement}"))?;

        // Inject the fd into the supervised process. newfd_flags = 0: no
        // O_CLOEXEC, so the fd is visible as /proc/self/fd/<n> during exec.
        let inject_result = self
            .listener
            .add_fd(notif.id, host_file.as_raw_fd(), None, 0);
        drop(host_file); // supervisor's copy no longer needed
        let injected_fd =
            inject_result.context("injecting replacement binary fd into supervised process")?;

        // Write "/proc/self/fd/<allocated-fd>\0" to the child's stack and
        // rewrite the path pointer register in one ptrace pass.
        let path = format!("/proc/self/fd/{injected_fd}\0");
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
    let remote_iov = [RemoteIoVec {
        base: child_addr as usize,
        len: buf.len(),
    }];
    let mut local_iov = [IoSliceMut::new(&mut buf)];
    let n = process_vm_readv(Pid::from_raw(pid), &mut local_iov, &remote_iov)
        .context("process_vm_readv")?;

    let nul = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Ok(String::from_utf8_lossy(&buf[..nul]).into_owned())
}
