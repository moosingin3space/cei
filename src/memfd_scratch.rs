use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, bail};
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, ftruncate, memfd_create};
use rustix::io::pwrite;

#[derive(Debug)]
pub struct ScratchPage {
    fd: OwnedFd,
    slot_size: usize,
    slot_count: usize,
    next_slot: AtomicUsize,
}

#[derive(Debug, Clone, Copy)]
pub struct ScratchSlot {
    pub index: usize,
    pub offset: usize,
}

impl ScratchPage {
    pub fn new(slot_size: usize, slot_count: usize) -> Result<Self> {
        if slot_size < 64 {
            bail!("slot_size must be >= 64");
        }
        if slot_count == 0 {
            bail!("slot_count must be > 0");
        }

        let fd = memfd_create(
            "cei-scratch",
            MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
        )?;

        let total_size = slot_size
            .checked_mul(slot_count)
            .ok_or_else(|| anyhow::anyhow!("slot configuration overflows"))?;
        ftruncate(&fd, total_size as u64)?;

        // Keep layout fixed; slots are reused in a ring.
        fcntl_add_seals(&fd, SealFlags::GROW | SealFlags::SHRINK)?;

        Ok(Self {
            fd,
            slot_size,
            slot_count,
            next_slot: AtomicUsize::new(0),
        })
    }

    pub fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    pub fn reserve_slot(&self) -> ScratchSlot {
        let index = self.next_slot.fetch_add(1, Ordering::Relaxed) % self.slot_count;
        ScratchSlot {
            index,
            offset: index * self.slot_size,
        }
    }

    pub fn write_procfd_path(&self, slot: ScratchSlot, child_fd: i32) -> Result<()> {
        let path = format!("/proc/self/fd/{child_fd}\0");
        if path.len() > self.slot_size {
            bail!("slot too small for procfd path");
        }
        let written = pwrite(&self.fd, path.as_bytes(), slot.offset as u64)?;
        if written != path.len() {
            bail!("short write to memfd scratch page");
        }
        Ok(())
    }
}
