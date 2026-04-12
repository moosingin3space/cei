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
    /// Allowed hosts for network connections. If empty, all hosts are allowed (for now, as per spec first pass).
    /// Wait, the user said "It should feature allowlists for HTTP hosts that should be allowed."
    /// So if it's NOT empty, we should check it.
    allowed_hosts: HashSet<String>,
}

impl SandboxPolicy {
    pub fn from_current_dir() -> Result<Self> {
        Ok(Self {
            exec_redirects: HashMap::new(),
            exec_denied: HashSet::new(),
            allowed_hosts: HashSet::new(),
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

    pub fn with_allowed_host(mut self, host: impl Into<String>) -> Self {
        self.allowed_hosts.insert(host.into());
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

    /// Return true if the supervised process may open a connection to host:port.
    ///
    /// Called for both CONNECT (HTTPS) and plain HTTP requests.
    /// If `allowed_hosts` is non-empty, only hosts in the set are allowed.
    /// If `allowed_hosts` is empty, all hosts are allowed (first pass behavior).
    pub fn network_allows_connect(&self, host: &str, port: u16) -> bool {
        if self.allowed_hosts.is_empty() {
            tracing::info!(host, port, "network connect allowed (allowlist empty)");
            return true;
        }

        if self.allowed_hosts.contains(host) {
            tracing::info!(host, port, "network connect allowed (in allowlist)");
            true
        } else {
            tracing::warn!(host, port, "network connect denied (not in allowlist)");
            false
        }
    }
}
