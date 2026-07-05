//! Command-line configuration for the SecureDeploySol node.

use clap::{Args, Parser, Subcommand};

/// SecureDeploySol off-chain audit & governance-mirror service.
#[derive(Debug, Parser)]
#[command(name = "securedeploy-node", version, about)]
pub struct Cli {
    #[command(flatten)]
    pub governance: GovernanceArgs,
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Governance parameters mirrored from the on-chain program.
#[derive(Debug, Clone, Args)]
pub struct GovernanceArgs {
    /// Authority key (base58 string).
    #[arg(long, env = "SD_AUTHORITY", default_value = "authority")]
    pub authority: String,
    /// Comma-separated guardian keys.
    #[arg(
        long,
        env = "SD_GUARDIANS",
        value_delimiter = ',',
        default_value = "g1,g2,g3"
    )]
    pub guardians: Vec<String>,
    /// Approvals required to execute a proposal.
    #[arg(long, env = "SD_THRESHOLD", default_value_t = 2)]
    pub threshold: u8,
    /// Timelock in seconds between proposal and execution.
    #[arg(long, env = "SD_TIMELOCK", default_value_t = 86_400)]
    pub timelock_seconds: i64,
}

impl Default for GovernanceArgs {
    fn default() -> Self {
        Self {
            authority: "authority".into(),
            guardians: vec!["g1".into(), "g2".into(), "g3".into()],
            threshold: 2,
            timelock_seconds: 86_400,
        }
    }
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the GraphQL server.
    Serve(ServeArgs),
    /// Run a self-contained demo of the audit flow.
    Demo,
}

/// Serve-command arguments.
#[derive(Debug, Clone, Args)]
pub struct ServeArgs {
    /// Address to bind.
    #[arg(long, env = "SD_BIND_ADDR", default_value = "0.0.0.0:8080")]
    pub bind_addr: String,
    /// Mutation rate limit (requests/sec).
    #[arg(long, env = "SD_RATE_LIMIT_RPS", default_value_t = 50)]
    pub rate_limit_rps: u32,
}

impl Default for ServeArgs {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".into(),
            rate_limit_rps: 50,
        }
    }
}
