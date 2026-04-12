use std::collections::HashMap;

use anyhow::Result;

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Exact-path exec redirects: when the supervised process execs `key`,
    /// run `value` instead.
    exec_redirects: HashMap<String, String>,
}

impl SandboxPolicy {
    pub fn from_current_dir() -> Result<Self> {
        Ok(Self {
            exec_redirects: HashMap::new(),
        })
    }

    pub fn with_redirect(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.exec_redirects.insert(from.into(), to.into());
        self
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
