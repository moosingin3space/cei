use std::collections::HashMap;
use std::collections::HashSet;

use anyhow::Result;

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Exact-path exec redirects: when the supervised process execs `key`,
    /// run `value` instead.
    exec_redirects: HashMap<String, String>,
    /// Exact paths that are unconditionally denied (EPERM).
    exec_denied: HashSet<String>,
}

impl SandboxPolicy {
    pub fn from_current_dir() -> Result<Self> {
        Ok(Self {
            exec_redirects: HashMap::new(),
            exec_denied: HashSet::new(),
        })
    }

    pub fn with_redirect(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.exec_redirects.insert(from.into(), to.into());
        self
    }

    /// Deny execve of `path` with EPERM.  Takes precedence over redirects.
    pub fn with_denied_exec(mut self, path: impl Into<String>) -> Self {
        self.exec_denied.insert(path.into());
        self
    }

    /// Return the replacement path for `path`, if a redirect is configured.
    pub fn exec_redirect<'a>(&'a self, path: &str) -> Option<&'a str> {
        self.exec_redirects.get(path).map(|s| s.as_str())
    }

    /// Whether to permit this execve path (applies only when no redirect matches).
    pub fn exec_allowed(&self, path: &str) -> bool {
        !self.exec_denied.contains(path)
    }
}
