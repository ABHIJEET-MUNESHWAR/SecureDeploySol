//! Optional Postgres proposal store (feature `postgres`).
//!
//! Uses runtime queries (not the compile-time macros) so the crate builds
//! without a live database at compile time.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use securedeploy_core::{EngineError, ProposalRecord, ProposalStore, Result};
use securedeploy_types::{ProgramId, ProposalId, ProposalStatus};

/// Postgres-backed proposal store.
pub struct PgProposalStore {
    pool: PgPool,
}

impl PgProposalStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn status_str(s: ProposalStatus) -> &'static str {
    match s {
        ProposalStatus::Pending => "pending",
        ProposalStatus::Approved => "approved",
        ProposalStatus::Executed => "executed",
        ProposalStatus::Cancelled => "cancelled",
    }
}

fn parse_status(s: &str) -> ProposalStatus {
    match s {
        "approved" => ProposalStatus::Approved,
        "executed" => ProposalStatus::Executed,
        "cancelled" => ProposalStatus::Cancelled,
        _ => ProposalStatus::Pending,
    }
}

fn map_row(row: &sqlx::postgres::PgRow) -> ProposalRecord {
    ProposalRecord {
        id: ProposalId(row.get::<i64, _>("id") as u64),
        program_id: ProgramId(row.get("program_id")),
        build_hash: row.get("build_hash"),
        proposer: row.get("proposer"),
        eta: row.get("eta"),
        approvals: row.get::<i32, _>("approvals") as u8,
        threshold: row.get::<i32, _>("threshold") as u8,
        status: parse_status(row.get::<String, _>("status").as_str()),
        created_at: row.get("created_at"),
    }
}

#[async_trait]
impl ProposalStore for PgProposalStore {
    async fn upsert(&self, r: ProposalRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO proposals \
             (id, program_id, build_hash, proposer, eta, approvals, threshold, status, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
             ON CONFLICT (id) DO UPDATE SET \
             approvals = EXCLUDED.approvals, status = EXCLUDED.status",
        )
        .bind(r.id.0 as i64)
        .bind(r.program_id.0)
        .bind(r.build_hash)
        .bind(r.proposer)
        .bind(r.eta)
        .bind(r.approvals as i32)
        .bind(r.threshold as i32)
        .bind(status_str(r.status))
        .bind(r.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| EngineError::Store(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, id: u64) -> Result<Option<ProposalRecord>> {
        let row = sqlx::query("SELECT * FROM proposals WHERE id = $1")
            .bind(id as i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| EngineError::Store(e.to_string()))?;
        Ok(row.as_ref().map(map_row))
    }

    async fn list(&self) -> Result<Vec<ProposalRecord>> {
        let rows = sqlx::query("SELECT * FROM proposals ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| EngineError::Store(e.to_string()))?;
        Ok(rows.iter().map(map_row).collect())
    }

    async fn count(&self) -> Result<u64> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM proposals")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| EngineError::Store(e.to_string()))?;
        Ok(row.get::<i64, _>("n") as u64)
    }
}
