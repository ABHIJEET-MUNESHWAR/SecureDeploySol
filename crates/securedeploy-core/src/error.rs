use securedeploy_types::SecureError as DomainError;
use thiserror::Error;

/// Errors surfaced by the engine layer.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("storage error: {0}")]
    Store(String),
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error("not found: {0}")]
    NotFound(String),
}

pub type Result<T> = core::result::Result<T, EngineError>;
