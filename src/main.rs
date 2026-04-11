#![expect(dead_code, reason = "skeleton modules are intentionally staged before full wiring")]

mod memfd_scratch;
mod policy;
mod ptrace_rewrite;
mod seccomp_notify;
mod styrolite_launcher;
mod supervisor;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use policy::SandboxPolicy;

#[derive(Debug, Parser)]
#[command(name = "cei")]
#[command(about = "CLI execution interception sandbox skeleton")]
#[command(
    long_about = "Build and run a Linux command interception sandbox scaffold.\n\n\
This CLI models a layered sandbox architecture using:\n\
- Styrolite for namespace and mount setup\n\
- seccomp USER_NOTIF interception for execve/execveat\n\
- supervisor-side fd injection and ptrace argument rewrite skeletons"
)]
struct Cli {
    /// Action to perform.
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(
        about = "Render the generated Styrolite create request as JSON",
        long_about = "Generate and print the Styrolite Config::Create payload for the current policy.\n\n\
Policy baseline:\n\
- Current host working directory is mapped to /workspace\n\
- Root filesystem is read-only\n\
- Intended writable area is /workspace (plus tmpfs /tmp)\n\n\
This mode does not execute the sandbox; it prints the launch configuration."
    )]
    Plan {
        #[arg(
            long,
            value_name = "ROOTFS",
            help = "Path to the root filesystem directory used by Styrolite",
            long_help = "Host path to the root filesystem directory passed to Styrolite as the container rootfs."
        )]
        rootfs: PathBuf,
        #[arg(
            long,
            value_name = "COMMAND",
            help = "Executable path to run inside the sandbox",
            long_help = "Executable path resolved inside the sandbox mount namespace (for example /bin/sh)."
        )]
        command: String,
        #[arg(
            long = "arg",
            value_name = "ARG",
            action = clap::ArgAction::Append,
            help = "Arguments forwarded to COMMAND",
            long_help = "Repeatable command argument forwarded to COMMAND unchanged. Example: --arg -c --arg 'echo hi'."
        )]
        args: Vec<String>,
    },
    #[command(
        about = "Launch through the Styrolite binary using the generated request",
        long_about = "Run the sandbox target by invoking a Styrolite runner binary with the generated create request.\n\n\
This is skeleton mode: namespace/mount setup is real, while supervisor wiring for seccomp\n\
listener handoff and child bootstrap remains staged in modules."
    )]
    Run {
        #[arg(
            long = "styrolite-bin",
            value_name = "STYROLITE_BIN",
            help = "Path to the Styrolite executable",
            long_help = "Filesystem path to the Styrolite runner binary used to launch the sandbox."
        )]
        styrolite_bin: PathBuf,
        #[arg(
            long,
            value_name = "ROOTFS",
            help = "Path to the root filesystem directory used by Styrolite",
            long_help = "Host path to the root filesystem directory passed to Styrolite as the container rootfs."
        )]
        rootfs: PathBuf,
        #[arg(
            long,
            value_name = "COMMAND",
            help = "Executable path to run inside the sandbox",
            long_help = "Executable path resolved inside the sandbox mount namespace (for example /bin/sh)."
        )]
        command: String,
        #[arg(
            long = "arg",
            value_name = "ARG",
            action = clap::ArgAction::Append,
            help = "Arguments forwarded to COMMAND",
            long_help = "Repeatable command argument forwarded to COMMAND unchanged. Example: --arg -c --arg 'echo hi'."
        )]
        args: Vec<String>,
    },
}

fn parse_policy() -> Result<SandboxPolicy> {
    SandboxPolicy::from_current_dir()
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Plan {
            rootfs,
            command,
            args,
        } => {
            let policy = parse_policy()?;
            let req = styrolite_launcher::build_create_request(&policy, &rootfs, &command, &args)
                .context("building Styrolite create request")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&styrolite::config::Config::Create(req))
                    .context("serializing Styrolite config")?
            );
        }
        Commands::Run {
            styrolite_bin,
            rootfs,
            command,
            args,
        } => {
            let policy = parse_policy()?;
            let req = styrolite_launcher::build_create_request(&policy, &rootfs, &command, &args)
                .context("building Styrolite create request")?;

            eprintln!("starting Styrolite sandbox (skeleton mode)");
            let child_exit = styrolite_launcher::run_in_styrolite(&styrolite_bin, req)?;
            eprintln!("sandbox process exited with code {child_exit}");

            eprintln!("supervisor wiring is scaffolded in src/supervisor.rs");
        }
    }

    Ok(())
}
