#![expect(unsafe_code)]

use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result, bail};
use libc::sock_filter;

#[derive(Debug)]
pub struct SeccompListener {
    fd: OwnedFd,
}

#[derive(Debug, Clone, Copy)]
pub struct ExecNotification {
    pub id: u64,
    pub pid: u32,
    pub syscall_nr: i32,
    pub arg0: u64,
    pub arg1: u64,
}

impl SeccompListener {
    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn install_exec_listener() -> Result<Self> {
        let filter = build_exec_only_user_notif_filter()?;
        let fd = install_filter_with_listener(&filter)?;
        Ok(Self { fd })
    }

    pub fn as_fd(&self) -> &OwnedFd {
        &self.fd
    }

    pub fn recv(&self) -> Result<ExecNotification> {
        // SAFETY: seccomp_notif is a C struct with no invalid bit patterns;
        // zero-initialising it satisfies the kernel's requirement that reserved
        // fields are cleared before the ioctl.
        let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: fd is a valid seccomp listener; notif is a correctly-sized
        // output buffer for SECCOMP_IOCTL_NOTIF_RECV.
        let rc = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                seccomp_ioctl_notif_recv() as libc::c_ulong,
                &mut notif,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("SECCOMP_IOCTL_NOTIF_RECV");
        }

        Ok(ExecNotification {
            id: notif.id,
            pid: notif.pid,
            syscall_nr: notif.data.nr,
            arg0: notif.data.args[0],
            arg1: notif.data.args[1],
        })
    }

    pub fn notif_id_valid(&self, id: u64) -> Result<bool> {
        let mut id_copy = id;
        // SAFETY: fd is a valid seccomp listener; id_copy is the correct type
        // for SECCOMP_IOCTL_NOTIF_ID_VALID.
        let rc = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                seccomp_ioctl_notif_id_valid() as libc::c_ulong,
                &mut id_copy,
            )
        };
        if rc == 0 {
            return Ok(true);
        }

        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }

        Err(err).context("SECCOMP_IOCTL_NOTIF_ID_VALID")
    }

    /// Inject `srcfd` (supervisor-side) into the supervised process.
    ///
    /// When `child_fd` is `Some`, request that exact descriptor number in the
    /// target. When it is `None`, let the kernel allocate a free descriptor and
    /// return its number.
    ///
    /// `newfd_flags` is applied to the fd in the target process. Pass `0` when
    /// the fd must survive exec (e.g. for `/proc/self/fd/N` path rewriting);
    /// pass `O_CLOEXEC` for fds that should be cleaned up automatically.
    pub fn add_fd(
        &self,
        notif_id: u64,
        srcfd: i32,
        child_fd: Option<u32>,
        newfd_flags: u32,
    ) -> Result<i32> {
        let (flags, newfd) = match child_fd {
            Some(fd) => (libc::SECCOMP_ADDFD_FLAG_SETFD as libc::c_uint, fd),
            None => (0, 0),
        };
        let mut addfd = libc::seccomp_notif_addfd {
            id: notif_id,
            flags,
            srcfd: srcfd as u32,
            newfd,
            newfd_flags,
        };

        // SAFETY: fd is a valid seccomp listener; addfd is correctly initialised
        // for SECCOMP_IOCTL_NOTIF_ADDFD.
        let rc = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                seccomp_ioctl_notif_addfd() as libc::c_ulong,
                &mut addfd,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("SECCOMP_IOCTL_NOTIF_ADDFD");
        }
        Ok(rc)
    }

    pub fn send_continue(&self, notif_id: u64) -> Result<()> {
        let mut resp = libc::seccomp_notif_resp {
            id: notif_id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        };

        // SAFETY: fd is a valid seccomp listener; resp is correctly initialised
        // for SECCOMP_IOCTL_NOTIF_SEND.
        let rc = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                seccomp_ioctl_notif_send() as libc::c_ulong,
                &mut resp,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error())
                .context("SECCOMP_IOCTL_NOTIF_SEND (continue)");
        }

        Ok(())
    }

    pub fn send_errno(&self, notif_id: u64, errno: i32) -> Result<()> {
        let mut resp = libc::seccomp_notif_resp {
            id: notif_id,
            val: 0,
            error: -errno,
            flags: 0,
        };

        // SAFETY: fd is a valid seccomp listener; resp is correctly initialised
        // for SECCOMP_IOCTL_NOTIF_SEND.
        let rc = unsafe {
            libc::ioctl(
                self.fd.as_raw_fd(),
                seccomp_ioctl_notif_send() as libc::c_ulong,
                &mut resp,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error())
                .context("SECCOMP_IOCTL_NOTIF_SEND (errno)");
        }

        Ok(())
    }
}

fn build_exec_only_user_notif_filter() -> Result<Vec<sock_filter>> {
    let nr_offset = 0u32;
    let execve_nr = libc::SYS_execve as u32;
    let execveat_nr = libc::SYS_execveat as u32;

    let load_nr = bpf_stmt(
        (libc::BPF_LD + libc::BPF_W + libc::BPF_ABS) as u16,
        nr_offset,
    );
    let if_execve = bpf_jump(
        (libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K) as u16,
        execve_nr,
        0,
        1,
    );
    let ret_user_notif = bpf_stmt(
        (libc::BPF_RET + libc::BPF_K) as u16,
        libc::SECCOMP_RET_USER_NOTIF,
    );
    let if_execveat = bpf_jump(
        (libc::BPF_JMP + libc::BPF_JEQ + libc::BPF_K) as u16,
        execveat_nr,
        0,
        1,
    );
    let ret_allow = bpf_stmt(
        (libc::BPF_RET + libc::BPF_K) as u16,
        libc::SECCOMP_RET_ALLOW,
    );

    Ok(vec![
        load_nr,
        if_execve,
        ret_user_notif,
        if_execveat,
        ret_user_notif,
        ret_allow,
    ])
}

fn install_filter_with_listener(filter: &[sock_filter]) -> Result<OwnedFd> {
    if filter.is_empty() {
        bail!("seccomp filter unexpectedly empty");
    }

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    // NEW_LISTENER and TSYNC are mutually exclusive; NEW_LISTENER alone is sufficient
    // for single-threaded children that exec immediately.
    let flags = libc::SECCOMP_FILTER_FLAG_NEW_LISTENER;
    // SAFETY: prog points to a valid sock_fprog whose filter slice lives for
    // the duration of this call.  No safe wrapper exists for the seccomp(2)
    // syscall with SECCOMP_SET_MODE_FILTER | SECCOMP_FILTER_FLAG_NEW_LISTENER.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            flags,
            &prog as *const libc::sock_fprog,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("installing seccomp listener");
    }

    // SAFETY: the kernel returned a new, valid file descriptor that this
    // process now owns exclusively.
    let fd = unsafe { OwnedFd::from_raw_fd(ret as i32) };
    Ok(fd)
}

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioc(dir: u32, type_: u32, nr: u32, size: u32) -> u64 {
    ((dir << IOC_DIRSHIFT)
        | (type_ << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT)) as u64
}

const fn iow(type_: u32, nr: u32, size: u32) -> u64 {
    ioc(IOC_WRITE, type_, nr, size)
}

const fn iowr(type_: u32, nr: u32, size: u32) -> u64 {
    ioc(IOC_READ | IOC_WRITE, type_, nr, size)
}

const SECCOMP_IOC_MAGIC: u32 = b'!' as u32;

const fn seccomp_ioctl_notif_recv() -> u64 {
    iowr(
        SECCOMP_IOC_MAGIC,
        0,
        size_of::<libc::seccomp_notif>() as u32,
    )
}

const fn seccomp_ioctl_notif_send() -> u64 {
    iowr(
        SECCOMP_IOC_MAGIC,
        1,
        size_of::<libc::seccomp_notif_resp>() as u32,
    )
}

const fn seccomp_ioctl_notif_id_valid() -> u64 {
    iow(SECCOMP_IOC_MAGIC, 2, size_of::<u64>() as u32)
}

const fn seccomp_ioctl_notif_addfd() -> u64 {
    iow(
        SECCOMP_IOC_MAGIC,
        3,
        size_of::<libc::seccomp_notif_addfd>() as u32,
    )
}

fn bpf_stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}
