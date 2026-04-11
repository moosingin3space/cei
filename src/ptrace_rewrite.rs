use anyhow::Result;
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;

pub fn rewrite_execve_path_arg(pid_raw: i32, child_addr: u64) -> Result<()> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (pid_raw, child_addr);
        bail!("skeleton currently supports x86_64 register layout only");
    }

    #[cfg(target_arch = "x86_64")]
    {
        let pid = Pid::from_raw(pid_raw);
        ptrace::attach(pid)?;
        let _status = waitpid(pid, None)?;
        let mut regs = ptrace::getregs(pid)?;
        regs.rdi = child_addr;
        ptrace::setregs(pid, regs)?;
        ptrace::detach(pid, None)?;
        Ok(())
    }
}
