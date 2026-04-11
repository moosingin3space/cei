use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    host_workspace: PathBuf,
    guest_workspace: PathBuf,
}

impl SandboxPolicy {
    pub fn from_current_dir() -> Result<Self> {
        let host_workspace = std::env::current_dir().context("reading cwd")?;
        Ok(Self {
            host_workspace,
            guest_workspace: PathBuf::from("/workspace"),
        })
    }

    pub fn host_workspace(&self) -> &Path {
        &self.host_workspace
    }

    pub fn guest_workspace(&self) -> &Path {
        &self.guest_workspace
    }

    pub fn host_allows_write(&self, host_path: &Path) -> bool {
        host_path.starts_with(&self.host_workspace)
    }
}
