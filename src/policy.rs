use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    host_workspace: PathBuf,
    guest_workspace: PathBuf,
    /// Exact-path exec redirects: when the supervised process execs `key`,
    /// run `value` instead.
    exec_redirects: HashMap<String, String>,
}

impl SandboxPolicy {
    pub fn from_current_dir() -> Result<Self> {
        let host_workspace = std::env::current_dir().context("reading cwd")?;
        Ok(Self {
            host_workspace,
            guest_workspace: PathBuf::from("/workspace"),
            exec_redirects: HashMap::new(),
        })
    }

    pub fn with_redirect(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.exec_redirects.insert(from.into(), to.into());
        self
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

    /// Return the replacement path for `path`, if a redirect is configured.
    pub fn exec_redirect<'a>(&'a self, path: &str) -> Option<&'a str> {
        self.exec_redirects.get(path).map(|s| s.as_str())
    }

    /// Whether to permit this execve path (applies only when no redirect matches).
    pub fn exec_allowed(&self, _path: &str) -> bool {
        true
    }
}
