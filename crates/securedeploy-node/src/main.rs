//! Binary entry point for the SecureDeploySol off-chain audit service.

use clap::Parser;
use securedeploy_node::config::{Cli, Command, ServeArgs};
use securedeploy_node::{demo, startup, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    telemetry::init_tracing();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Demo) => demo::run(&cli.governance).await,
        Some(Command::Serve(args)) => startup::serve(&cli.governance, &args).await,
        None => startup::serve(&cli.governance, &ServeArgs::default()).await,
    }
}
