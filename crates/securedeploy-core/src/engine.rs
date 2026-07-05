use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;

use securedeploy_types::{
    can_execute, compute_eta, validate_guardians, BuildHash, ProgramId, ProposalId, ProposalStatus,
    SecureError, Severity, ThreatClass,
};

use crate::domain::{DomainEvent, FindingRecord, GovernanceConfig, ProposalRecord};
use crate::error::{EngineError, Result};
use crate::ports::{EventSink, FindingStore, ProposalStore};

/// Wall-clock port so tests can pin time deterministically.
pub trait UnixClock: Send + Sync {
    fn now(&self) -> i64;
}

/// Production clock backed by the system time.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemUnixClock;

impl UnixClock for SystemUnixClock {
    fn now(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

/// Aggregate counters for observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EngineStats {
    pub proposals: u64,
    pub executed: u64,
    pub findings: u64,
    pub open_findings: u64,
}

/// The audit engine mirrors on-chain governance rules and maintains the
/// off-chain index. Generic over all ports + the clock (dependency inversion).
pub struct AuditEngine<P, F, E, C>
where
    P: ProposalStore,
    F: FindingStore,
    E: EventSink,
    C: UnixClock,
{
    proposals: Arc<P>,
    findings: Arc<F>,
    events: Arc<E>,
    clock: Arc<C>,
    config: RwLock<GovernanceConfig>,
    /// Per-proposal set of guardian keys that have approved (double-vote guard).
    approvals: RwLock<HashMap<u64, HashSet<String>>>,
}

impl<P, F, E, C> AuditEngine<P, F, E, C>
where
    P: ProposalStore,
    F: FindingStore,
    E: EventSink,
    C: UnixClock,
{
    /// Construct an engine, validating the initial guardian configuration.
    pub fn new(
        proposals: Arc<P>,
        findings: Arc<F>,
        events: Arc<E>,
        clock: Arc<C>,
        config: GovernanceConfig,
    ) -> Result<Self> {
        validate_guardians(&config.guardians, config.threshold)?;
        Ok(Self {
            proposals,
            findings,
            events,
            clock,
            config: RwLock::new(config),
            approvals: RwLock::new(HashMap::new()),
        })
    }

    #[must_use]
    pub fn config(&self) -> GovernanceConfig {
        self.config.read().clone()
    }

    /// Toggle the emergency pause.
    pub async fn set_paused(&self, paused: bool) -> Result<()> {
        self.config.write().paused = paused;
        self.events
            .publish(DomainEvent::PauseChanged { paused })
            .await?;
        Ok(())
    }

    /// Rotate the guardian set (re-validated).
    pub fn set_guardians(&self, guardians: Vec<String>, threshold: u8) -> Result<()> {
        validate_guardians(&guardians, threshold)?;
        let mut cfg = self.config.write();
        cfg.guardians = guardians;
        cfg.threshold = threshold;
        Ok(())
    }

    fn ensure_active(&self) -> Result<()> {
        if self.config.read().paused {
            return Err(SecureError::Paused.into());
        }
        Ok(())
    }

    /// Create a timelocked upgrade proposal. Only a guardian or the authority
    /// may propose; the build hash is validated non-zero.
    pub async fn propose(
        &self,
        program_id: ProgramId,
        build_hash_hex: &str,
        proposer: String,
    ) -> Result<ProposalRecord> {
        self.ensure_active()?;
        let hash = BuildHash::from_hex(build_hash_hex)?;

        let (id, eta, threshold) = {
            let cfg = self.config.read();
            if proposer != cfg.authority && !cfg.is_guardian(&proposer) {
                return Err(SecureError::NotGuardian.into());
            }
            let now = self.clock.now();
            let eta = compute_eta(now, cfg.timelock_seconds)?;
            (cfg.proposal_count, eta, cfg.threshold)
        };

        let record = ProposalRecord {
            id: ProposalId(id),
            program_id: program_id.clone(),
            build_hash: hash.to_hex(),
            proposer,
            eta,
            approvals: 0,
            threshold,
            status: ProposalStatus::Pending,
            created_at: self.clock.now(),
        };
        self.proposals.upsert(record.clone()).await?;

        {
            let mut cfg = self.config.write();
            cfg.proposal_count = cfg
                .proposal_count
                .checked_add(1)
                .ok_or(SecureError::Overflow)?;
        }
        self.events
            .publish(DomainEvent::ProposalCreated {
                id,
                program_id: program_id.0,
            })
            .await?;
        Ok(record)
    }

    /// Register a guardian approval. Rejects non-guardians, finalized
    /// proposals, and duplicate approvals.
    pub async fn approve(&self, id: u64, guardian: String) -> Result<ProposalRecord> {
        self.ensure_active()?;
        {
            let cfg = self.config.read();
            if !cfg.is_guardian(&guardian) {
                return Err(SecureError::NotGuardian.into());
            }
        }

        let mut record = self
            .proposals
            .get(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("proposal {id}")))?;
        if matches!(
            record.status,
            ProposalStatus::Executed | ProposalStatus::Cancelled
        ) {
            return Err(SecureError::AlreadyFinalized.into());
        }

        {
            let mut map = self.approvals.write();
            let set = map.entry(id).or_default();
            if !set.insert(guardian.clone()) {
                return Err(SecureError::DuplicateApproval.into());
            }
            record.approvals = set.len() as u8;
        }
        if record.approvals >= record.threshold {
            record.status = ProposalStatus::Approved;
        }
        self.proposals.upsert(record.clone()).await?;
        self.events
            .publish(DomainEvent::ProposalApproved {
                id,
                approvals: record.approvals,
            })
            .await?;
        Ok(record)
    }

    /// Execute a proposal once threshold + timelock gates pass.
    pub async fn execute(&self, id: u64) -> Result<ProposalRecord> {
        self.ensure_active()?;
        let mut record = self
            .proposals
            .get(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("proposal {id}")))?;
        if matches!(
            record.status,
            ProposalStatus::Executed | ProposalStatus::Cancelled
        ) {
            return Err(SecureError::AlreadyFinalized.into());
        }
        can_execute(
            self.clock.now(),
            record.eta,
            record.approvals,
            record.threshold,
        )?;
        record.status = ProposalStatus::Executed;
        self.proposals.upsert(record.clone()).await?;
        self.events
            .publish(DomainEvent::ProposalExecuted { id })
            .await?;
        Ok(record)
    }

    /// Cancel a not-yet-finalized proposal (authority action, enforced by API).
    pub async fn cancel(&self, id: u64) -> Result<ProposalRecord> {
        let mut record = self
            .proposals
            .get(id)
            .await?
            .ok_or_else(|| EngineError::NotFound(format!("proposal {id}")))?;
        if matches!(
            record.status,
            ProposalStatus::Executed | ProposalStatus::Cancelled
        ) {
            return Err(SecureError::AlreadyFinalized.into());
        }
        record.status = ProposalStatus::Cancelled;
        self.proposals.upsert(record.clone()).await?;
        self.events
            .publish(DomainEvent::ProposalCancelled { id })
            .await?;
        Ok(record)
    }

    /// Record a security finding.
    pub async fn raise_finding(
        &self,
        id: String,
        program_id: ProgramId,
        threat: ThreatClass,
        severity: Severity,
        title: String,
    ) -> Result<FindingRecord> {
        let record = FindingRecord {
            id: id.clone(),
            program_id,
            threat,
            severity,
            title,
            resolved: false,
            created_at: self.clock.now(),
        };
        self.findings.insert(record.clone()).await?;
        self.events
            .publish(DomainEvent::FindingRaised { id, severity })
            .await?;
        Ok(record)
    }

    pub async fn proposal(&self, id: u64) -> Result<Option<ProposalRecord>> {
        self.proposals.get(id).await
    }

    pub async fn list_proposals(&self) -> Result<Vec<ProposalRecord>> {
        self.proposals.list().await
    }

    pub async fn finding(&self, id: &str) -> Result<Option<FindingRecord>> {
        self.findings.get(id).await
    }

    pub async fn list_findings(&self) -> Result<Vec<FindingRecord>> {
        self.findings.list().await
    }

    pub async fn stats(&self) -> Result<EngineStats> {
        let proposals = self.proposals.list().await?;
        let findings = self.findings.list().await?;
        Ok(EngineStats {
            proposals: proposals.len() as u64,
            executed: proposals
                .iter()
                .filter(|p| p.status == ProposalStatus::Executed)
                .count() as u64,
            findings: findings.len() as u64,
            open_findings: findings.iter().filter(|f| !f.resolved).count() as u64,
        })
    }
}
