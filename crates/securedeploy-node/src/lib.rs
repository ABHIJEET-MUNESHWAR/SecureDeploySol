//! Library surface for the SecureDeploySol node (composition root).
#![forbid(unsafe_code)]

pub mod config;
pub mod demo;
pub mod startup;
pub mod telemetry;

pub use config::{Cli, Command, GovernanceArgs, ServeArgs};
