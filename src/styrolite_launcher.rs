use std::path::Path;

use anyhow::Result;
use styrolite::config::{CreateRequest, MountSpec};
use styrolite::namespace::Namespace;
use styrolite::runner::{CreateRequestBuilder, Runner};

use crate::policy::SandboxPolicy;

pub fn build_create_request(
    policy: &SandboxPolicy,
    rootfs: &Path,
    command: &str,
    args: &[String],
) -> Result<CreateRequest> {
    let mut builder = CreateRequestBuilder::new()
        .set_rootfs(
            rootfs
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("rootfs path is not valid UTF-8"))?,
        )
        .set_rootfs_readonly(true)
        .set_executable(command)
        .set_no_new_privs(true)
        .set_working_directory(
            policy
                .guest_workspace()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("guest workspace path is not valid UTF-8"))?,
        )
        .push_namespace(Namespace::Mount)
        .push_namespace(Namespace::Pid)
        .push_namespace(Namespace::Net)
        .push_namespace(Namespace::Ipc)
        .push_namespace(Namespace::Uts)
        .push_environment("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    builder = builder.set_arguments(arg_refs);

    let workspace_source = policy
        .host_workspace()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("host workspace path is not valid UTF-8"))?
        .to_string();
    let workspace_target = policy
        .guest_workspace()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("guest workspace path is not valid UTF-8"))?
        .to_string();

    // Rootfs is read-only, and only /workspace is mounted writable.
    let workspace_bind = MountSpec {
        source: Some(workspace_source),
        target: workspace_target,
        fstype: None,
        bind: true,
        recurse: true,
        unshare: false,
        safe: true,
        create_mountpoint: true,
        read_only: false,
        data: None,
    };

    let tmpfs_mount = MountSpec {
        source: Some("tmpfs".to_string()),
        target: "/tmp".to_string(),
        fstype: Some("tmpfs".to_string()),
        bind: false,
        recurse: false,
        unshare: false,
        safe: true,
        create_mountpoint: true,
        read_only: false,
        data: Some("mode=1777,size=64m".to_string()),
    };

    Ok(builder.push_mount(workspace_bind).push_mount(tmpfs_mount).to_request())
}

pub fn run_in_styrolite(styrolite_bin: &Path, req: CreateRequest) -> Result<i32> {
    let runner = Runner::new(
        styrolite_bin
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("styrolite path is not valid UTF-8"))?,
    );
    runner.run(req)
}
