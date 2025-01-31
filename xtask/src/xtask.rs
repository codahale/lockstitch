use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};
use clap::{ArgAction, Parser, Subcommand};
use xshell::{cmd, Shell};

#[derive(Debug, Parser)]
struct XTask {
    #[clap(subcommand)]
    cmd: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Format, build, test, and lint.
    CI,

    // Run benchmarks.
    Bench {
        /// Additional arguments.
        #[arg(action(ArgAction::Append), allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Spin up stuff on GCE for perf testings.
    Cloud {
        #[clap(subcommand)]
        cmd: CloudCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CloudCommand {
    Create,
    Setup,
    Bench {
        #[arg(long, default_value = "main")]
        branch: String,
    },
    Test {
        #[arg(long, default_value = "main")]
        branch: String,
    },
    Ssh,
    Delete,
}

fn main() -> Result<()> {
    let xtask = XTask::parse();

    let sh = Shell::new()?;
    sh.change_dir(project_root());

    match xtask.cmd.unwrap_or(Command::CI) {
        Command::CI => ci(&sh),
        Command::Bench { args } => bench(&sh, args),
        Command::Cloud { cmd } => match cmd {
            CloudCommand::Create => cloud_create(&sh),
            CloudCommand::Setup => cloud_setup(&sh),
            CloudCommand::Bench { branch } => cloud_bench(&sh, &branch),
            CloudCommand::Test { branch } => cloud_test(&sh, &branch),
            CloudCommand::Ssh => cloud_ssh(),
            CloudCommand::Delete => cloud_delete(&sh),
        },
    }
}

fn ci(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo fmt --check").run()?;
    cmd!(sh, "cargo build --no-default-features").run()?;
    cmd!(sh, "cargo build --all-targets --all-features").run()?;
    cmd!(sh, "cargo test").run()?;
    cmd!(sh, "cargo clippy --all-features --tests --benches").run()?;

    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const RUSTFLAGS: &str = "-C target-cpu=native";

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
const RUSTFLAGS: &str = "";

fn bench(sh: &Shell, args: Vec<String>) -> Result<()> {
    cmd!(sh, "cargo bench -p benchmarks --bench benchmarks -- {args...}")
        .env("RUSTFLAGS", RUSTFLAGS)
        .run()?;

    Ok(())
}

fn cloud_create(sh: &Shell) -> Result<()> {
    cmd!(sh, "gcloud compute instances create lockstitch --zone=us-central1-a --machine-type=c4-standard-4 --min-cpu-platform 'Intel Emerald Rapids' --image-project 'debian-cloud' --image-family 'debian-12'").run()?;

    Ok(())
}

fn cloud_setup(sh: &Shell) -> Result<()> {
    cmd!(sh, "gcloud compute ssh lockstitch --zone=us-central1-a --command 'sudo apt-get install build-essential git -y'").run()?;
    cmd!(sh, "gcloud compute ssh lockstitch --zone=us-central1-a --command 'curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'").run()?;
    cmd!(sh, "gcloud compute ssh lockstitch --zone=us-central1-a --command 'git clone https://github.com/codahale/lockstitch'").run()?;

    Ok(())
}

fn cloud_test(sh: &Shell, branch: &str) -> Result<()> {
    let cmd = format!("source ~/.cargo/env && cd lockstitch && git fetch && git reset --hard origin/{branch} && cargo test");
    cmd!(sh, "gcloud compute ssh lockstitch --zone=us-central1-a --command {cmd}").run()?;

    Ok(())
}

fn cloud_bench(sh: &Shell, branch: &str) -> Result<()> {
    let cmd = format!("source ~/.cargo/env && cd lockstitch && git fetch && git reset --hard origin/{branch} && cargo xtask bench -- --quiet 2> /dev/null");
    cmd!(sh, "gcloud compute ssh lockstitch --zone=us-central1-a --command {cmd}").run()?;

    Ok(())
}

fn cloud_ssh() -> Result<()> {
    let mut cmd = std::process::Command::new("gcloud");
    cmd.args(["compute", "ssh", "lockstitch", "--zone=us-central1-a"]);
    let mut child = cmd.spawn()?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        bail!("non-zero exit code returned: {}", status);
    }
}

fn cloud_delete(sh: &Shell) -> Result<()> {
    cmd!(sh, "gcloud compute instances delete lockstitch --zone=us-central1-a --quiet").run()?;

    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(
        &env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_owned()),
    )
    .ancestors()
    .nth(1)
    .unwrap()
    .to_path_buf()
}
