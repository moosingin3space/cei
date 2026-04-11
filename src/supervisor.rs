use std::ffi::CString;

use anyhow::{Context, Result};

use crate::memfd_scratch::ScratchPage;
use crate::policy::SandboxPolicy;
use crate::ptrace_rewrite::rewrite_execve_path_arg;
use crate::seccomp_notify::{ExecNotification, SeccompListener};

#[derive(Debug)]
pub struct Supervisor {
    policy: SandboxPolicy,
    listener: SeccompListener,
    scratch: ScratchPage,
    child_scratch_base: u64,
    injected_fd: u32,
}

impl Supervisor {
    pub fn new(
        policy: SandboxPolicy,
        listener: SeccompListener,
        scratch: ScratchPage,
        child_scratch_base: u64,
        injected_fd: u32,
    ) -> Self {
        Self {
            policy,
            listener,
            scratch,
            child_scratch_base,
            injected_fd,
        }
    }

    pub fn run_once(&self) -> Result<()> {
        let notif = self.listener.recv()?;
        self.handle_exec_notification(notif)
    }

    pub fn run_forever(&self) -> Result<()> {
        loop {
            self.run_once()?;
        }
    }

    fn handle_exec_notification(&self, notif: ExecNotification) -> Result<()> {
        if notif.syscall_nr != libc::SYS_execve as i32 && notif.syscall_nr != libc::SYS_execveat as i32 {
            self.listener.send_continue(notif.id)?;
            return Ok(());
        }

        if !self.listener.notif_id_valid(notif.id)? {
            return Ok(());
        }

        let path = read_child_cstring(notif.pid as i32, notif.arg0)
            .context("reading exec path from sandboxed task")?;

        let open_path = CString::new(path.clone()).context("exec path contains NUL")?;
        let host_fd = unsafe { libc::open(open_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if host_fd < 0 {
            let _ = self.listener.send_errno(notif.id, libc::EPERM);
            return Ok(());
        }

        if !self.policy.host_allows_write(std::path::Path::new(&path)) {
            // Write confinement is primarily mount-namespace based. This policy hook
            // is where host-side deny/redirect logic can be layered in.
        }

        let _remote_fd = self
            .listener
            .add_fd(notif.id, host_fd, self.injected_fd)
            .context("injecting opened binary fd into sandbox task")?;
        unsafe {
            libc::close(host_fd);
        }

        let slot = self.scratch.reserve_slot();
        self.scratch
            .write_procfd_path(slot, self.injected_fd as i32)
            .context("writing /proc/self/fd/N into scratch page")?;

        let child_addr = self.child_scratch_base + slot.offset as u64;
        rewrite_execve_path_arg(notif.pid as i32, child_addr)
            .context("ptrace register rewrite for execve path")?;

        if !self.listener.notif_id_valid(notif.id)? {
            return Ok(());
        }

        self.listener.send_continue(notif.id)?;
        Ok(())
    }
}

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

    let read = unsafe {
        libc::process_vm_readv(
            pid,
            &local_iov,
            1,
            &remote_iov,
            1,
            0,
        )
    };

    if read < 0 {
        return Err(std::io::Error::last_os_error()).context("process_vm_readv failed");
    }

    let valid = &buf[..read as usize];
    let nul_pos = valid.iter().position(|b| *b == 0).unwrap_or(valid.len());
    Ok(String::from_utf8_lossy(&valid[..nul_pos]).to_string())
}
