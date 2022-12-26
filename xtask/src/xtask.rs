use std::env;
use std::path::{Path, PathBuf};

use anyhow::Result;
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
        /// Enable NEON optimization.
        #[clap(long, default_value = "false")]
        neon: bool,

        /// Additional arguments for criterion.
        #[clap(action(ArgAction::Append), allow_hyphen_values = true)]
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
    Ssh,
    Delete,
}

fn main() -> Result<()> {
    let xtask = XTask::parse();

    let sh = Shell::new()?;
    sh.change_dir(project_root());

    match xtask.cmd.unwrap_or(Command::CI) {
        Command::CI => ci(&sh),
        Command::Bench { neon, args } => bench(&sh, neon, args),
        Command::Cloud { cmd } => match cmd {
            CloudCommand::Create => cloud_create(&sh),
            CloudCommand::Setup => cloud_setup(&sh),
            CloudCommand::Bench { branch } => cloud_bench(&sh, &branch),
            CloudCommand::Ssh => cloud_ssh(&sh),
            CloudCommand::Delete => cloud_delete(&sh),
        },
    }
}

fn ci(sh: &Shell) -> Result<()> {
    cmd!(sh, "cargo fmt --check").run()?;
    cmd!(sh, "cargo build --no-default-features").run()?;
    cmd!(sh, "cargo build --all-targets --all-features").run()?;
    cmd!(sh, "cargo test --all-features").run()?;
    cmd!(sh, "cargo clippy --all-features --tests --benches").run()?;

    Ok(())
}

fn bench(sh: &Shell, neon: bool, args: Vec<String>) -> Result<()> {
    let args = args.join(" ");
    if neon {
        cmd!(sh, "cargo criterion --features=neon {args}")
            .env("RUSTFLAGS", "-C target-cpu=native")
            .run()?;
    } else {
        cmd!(sh, "cargo criterion {args}").env("RUSTFLAGS", "-C target-cpu=native").run()?;
    }

    Ok(())
}

fn cloud_create(sh: &Shell) -> Result<()> {
    cmd!(sh, "gcloud compute instances create lockstitch-benchmark --zone=us-central1-a --machine-type=n2-standard-4 --min-cpu-platform 'Intel Ice Lake' --image-project 'debian-cloud' --image-family 'debian-11'").run()?;

    Ok(())
}

fn cloud_setup(sh: &Shell) -> Result<()> {
    cmd!(sh, "gcloud compute ssh lockstitch-benchmark --zone=us-central1-a --command 'sudo apt-get install build-essential git -y'").run()?;
    cmd!(sh, "gcloud compute ssh lockstitch-benchmark --zone=us-central1-a --command 'curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'").run()?;
    cmd!(sh, "gcloud compute ssh lockstitch-benchmark --zone=us-central1-a --command 'source ~/.cargo/env && cargo install cargo-criterion'")
        .run()?;
    cmd!(sh, "gcloud compute ssh lockstitch-benchmark --zone=us-central1-a --command 'git clone https://github.com/codahale/lockstitch'").run()?;

    Ok(())
}

fn cloud_bench(sh: &Shell, branch: &str) -> Result<()> {
    cmd!(sh, "rm -rf ./target/criterion-remote").run()?;
    let cmd = format!("source ~/.cargo/env && cd lockstitch && git pull && git checkout {branch} && rm -rf target/criterion && cargo criterion");
    cmd!(sh, "gcloud compute ssh lockstitch-benchmark --zone=us-central1-a --command {cmd}")
        .run()?;
    cmd!(sh, " gcloud compute scp --zone=us-central1-a --recurse lockstitch-benchmark:~/lockstitch/target/criterion ./target/criterion-remote").run()?;

    Ok(())
}

fn cloud_ssh(sh: &Shell) -> Result<()> {
    cmd!(sh, "gcloud compute ssh lockstitch-benchmark --zone=us-central1-a").run()?;

    Ok(())
}

fn cloud_delete(sh: &Shell) -> Result<()> {
    cmd!(sh, "gcloud compute instances delete lockstitch-benchmark --zone=us-central1-a").run()?;

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
