use std::io::IoSlice;

use anyhow::{Context, Result, bail};
use nix::sys::ptrace;
use nix::sys::uio::{RemoteIoVec, process_vm_writev};
use nix::sys::wait::waitpid;
use nix::unistd::Pid;

/// Write `path` into the child's stack (below the red zone) and rewrite the
/// in-flight exec pathname pointer register to that location.
///
/// Writing to the stack rather than the original pathname buffer means this
/// works regardless of where the original string lives (.rodata, heap, another
/// stack frame, etc.) and regardless of whether the scratch page from a
/// previous process image is still mapped.
pub fn write_path_and_swap_pointer(pid_raw: i32, syscall_nr: i32, path: &[u8]) -> Result<()> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (pid_raw, syscall_nr, path);
        bail!("skeleton currently supports x86_64 register layout only");
    }

    #[cfg(target_arch = "x86_64")]
    {
        let pid = Pid::from_raw(pid_raw);
        ptrace::attach(pid)?;
        let _status = waitpid(pid, None)?;
        let mut regs = ptrace::getregs(pid)?;

        // Place the path below the 128-byte x86-64 red zone, aligned to 8.
        let target = (regs.rsp - 128 - path.len() as u64) & !7u64;

        // Write the path bytes into the child's stack via process_vm_writev.
        // The stack is always writable and present after any exec.
        let local_iov = [IoSlice::new(path)];
        let remote_iov = [RemoteIoVec {
            base: target as usize,
            len: path.len(),
        }];
        let written = match process_vm_writev(pid, &local_iov, &remote_iov) {
            Ok(n) => n,
            Err(e) => {
                ptrace::detach(pid, None)?;
                return Err(e).context("process_vm_writev to child stack");
            }
        };
        if written != path.len() {
            ptrace::detach(pid, None)?;
            bail!(
                "process_vm_writev wrote {} of {} bytes",
                written,
                path.len()
            );
        }

        if syscall_nr == libc::SYS_execve as i32 {
            regs.rdi = target;
        } else if syscall_nr == libc::SYS_execveat as i32 {
            regs.rsi = target;
        } else {
            ptrace::detach(pid, None)?;
            bail!("unexpected syscall in exec rewriter: {syscall_nr}");
        }

        ptrace::setregs(pid, regs)?;
        ptrace::detach(pid, None)?;
        Ok(())
    }
}
