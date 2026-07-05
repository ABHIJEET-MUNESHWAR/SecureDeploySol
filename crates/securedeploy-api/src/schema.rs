//! GraphQL schema: queries, mutations, and subscriptions over the audit engine.

use async_graphql::{Context, Enum, InputObject, Object, Schema, SimpleObject, Subscription};
use futures::Stream;
use tokio_stream::StreamExt;

use securedeploy_core::domain::{DomainEvent, FindingRecord, ProposalRecord};
use securedeploy_types::{ProgramId, ProposalStatus, Severity, ThreatClass};

use crate::state::ServiceState;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Severity level exposed over GraphQL.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum GqlSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<GqlSeverity> for Severity {
    fn from(s: GqlSeverity) -> Self {
        match s {
            GqlSeverity::Info => Severity::Info,
            GqlSeverity::Low => Severity::Low,
            GqlSeverity::Medium => Severity::Medium,
            GqlSeverity::High => Severity::High,
            GqlSeverity::Critical => Severity::Critical,
        }
    }
}

/// Solana attack-class taxonomy exposed over GraphQL.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum GqlThreatClass {
    MissingSignerCheck,
    MissingOwnerCheck,
    AccountConfusion,
    ArbitraryCpi,
    PdaSeedCollision,
    IntegerOverflow,
    Reinitialization,
    TypeCosplay,
    UpgradeAuthorityAbuse,
    UnboundedAccount,
}

impl From<GqlThreatClass> for ThreatClass {
    fn from(t: GqlThreatClass) -> Self {
        match t {
            GqlThreatClass::MissingSignerCheck => ThreatClass::MissingSignerCheck,
            GqlThreatClass::MissingOwnerCheck => ThreatClass::MissingOwnerCheck,
            GqlThreatClass::AccountConfusion => ThreatClass::AccountConfusion,
            GqlThreatClass::ArbitraryCpi => ThreatClass::ArbitraryCpi,
            GqlThreatClass::PdaSeedCollision => ThreatClass::PdaSeedCollision,
            GqlThreatClass::IntegerOverflow => ThreatClass::IntegerOverflow,
            GqlThreatClass::Reinitialization => ThreatClass::Reinitialization,
            GqlThreatClass::TypeCosplay => ThreatClass::TypeCosplay,
            GqlThreatClass::UpgradeAuthorityAbuse => ThreatClass::UpgradeAuthorityAbuse,
            GqlThreatClass::UnboundedAccount => ThreatClass::UnboundedAccount,
        }
    }
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// An upgrade proposal exposed over GraphQL.
#[derive(SimpleObject)]
pub struct GqlProposal {
    pub id: u64,
    pub program_id: String,
    pub build_hash: String,
    pub proposer: String,
    pub eta: i64,
    pub approvals: u8,
    pub threshold: u8,
    pub status: String,
    pub created_at: i64,
}

fn status_str(s: ProposalStatus) -> String {
    match s {
        ProposalStatus::Pending => "pending",
        ProposalStatus::Approved => "approved",
        ProposalStatus::Executed => "executed",
        ProposalStatus::Cancelled => "cancelled",
    }
    .into()
}

impl From<ProposalRecord> for GqlProposal {
    fn from(r: ProposalRecord) -> Self {
        Self {
            id: r.id.0,
            program_id: r.program_id.0,
            build_hash: r.build_hash,
            proposer: r.proposer,
            eta: r.eta,
            approvals: r.approvals,
            threshold: r.threshold,
            status: status_str(r.status),
            created_at: r.created_at,
        }
    }
}

/// A security finding exposed over GraphQL.
#[derive(SimpleObject)]
pub struct GqlFinding {
    pub id: String,
    pub program_id: String,
    pub threat_code: String,
    pub severity: String,
    pub title: String,
    pub resolved: bool,
    pub created_at: i64,
}

impl From<FindingRecord> for GqlFinding {
    fn from(r: FindingRecord) -> Self {
        Self {
            id: r.id,
            program_id: r.program_id.0,
            threat_code: r.threat.code().into(),
            severity: format!("{:?}", r.severity).to_lowercase(),
            title: r.title,
            resolved: r.resolved,
            created_at: r.created_at,
        }
    }
}

/// Aggregate statistics.
#[derive(SimpleObject)]
pub struct GqlStats {
    pub proposals: u64,
    pub executed: u64,
    pub findings: u64,
    pub open_findings: u64,
}

/// Governance configuration.
#[derive(SimpleObject)]
pub struct GqlConfig {
    pub authority: String,
    pub guardians: Vec<String>,
    pub threshold: u8,
    pub timelock_seconds: i64,
    pub paused: bool,
    pub proposal_count: u64,
}

/// An event delivered over the subscription stream.
#[derive(SimpleObject, Clone)]
pub struct GqlEvent {
    pub kind: String,
    pub id: Option<String>,
    pub detail: Option<String>,
}

impl From<DomainEvent> for GqlEvent {
    fn from(e: DomainEvent) -> Self {
        match e {
            DomainEvent::ProposalCreated { id, program_id } => GqlEvent {
                kind: "PROPOSAL_CREATED".into(),
                id: Some(id.to_string()),
                detail: Some(program_id),
            },
            DomainEvent::ProposalApproved { id, approvals } => GqlEvent {
                kind: "PROPOSAL_APPROVED".into(),
                id: Some(id.to_string()),
                detail: Some(format!("approvals={approvals}")),
            },
            DomainEvent::ProposalExecuted { id } => GqlEvent {
                kind: "PROPOSAL_EXECUTED".into(),
                id: Some(id.to_string()),
                detail: None,
            },
            DomainEvent::ProposalCancelled { id } => GqlEvent {
                kind: "PROPOSAL_CANCELLED".into(),
                id: Some(id.to_string()),
                detail: None,
            },
            DomainEvent::FindingRaised { id, severity } => GqlEvent {
                kind: "FINDING_RAISED".into(),
                id: Some(id),
                detail: Some(format!("{severity:?}")),
            },
            DomainEvent::PauseChanged { paused } => GqlEvent {
                kind: "PAUSE_CHANGED".into(),
                id: None,
                detail: Some(paused.to_string()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

/// Fields describing a new upgrade proposal.
#[derive(InputObject)]
pub struct ProposeInput {
    pub program_id: String,
    /// Hex sha256 build hash (64 chars).
    pub build_hash: String,
    pub proposer: String,
}

/// Fields describing a new security finding.
#[derive(InputObject)]
pub struct FindingInput {
    pub id: String,
    pub program_id: String,
    pub threat: GqlThreatClass,
    pub severity: GqlSeverity,
    pub title: String,
}

// ---------------------------------------------------------------------------
// Query root
// ---------------------------------------------------------------------------

/// GraphQL query root.
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Liveness probe.
    async fn health(&self) -> bool {
        true
    }

    /// Fetches a proposal by id.
    async fn proposal(
        &self,
        ctx: &Context<'_>,
        id: u64,
    ) -> async_graphql::Result<Option<GqlProposal>> {
        let state = ctx.data::<ServiceState>()?;
        let rec = state.engine.proposal(id).await.map_err(to_err)?;
        Ok(rec.map(GqlProposal::from))
    }

    /// Lists all proposals.
    async fn proposals(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<GqlProposal>> {
        let state = ctx.data::<ServiceState>()?;
        let list = state.engine.list_proposals().await.map_err(to_err)?;
        Ok(list.into_iter().map(GqlProposal::from).collect())
    }

    /// Fetches a finding by id.
    async fn finding(
        &self,
        ctx: &Context<'_>,
        id: String,
    ) -> async_graphql::Result<Option<GqlFinding>> {
        let state = ctx.data::<ServiceState>()?;
        let rec = state.engine.finding(&id).await.map_err(to_err)?;
        Ok(rec.map(GqlFinding::from))
    }

    /// Lists all findings.
    async fn findings(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<GqlFinding>> {
        let state = ctx.data::<ServiceState>()?;
        let list = state.engine.list_findings().await.map_err(to_err)?;
        Ok(list.into_iter().map(GqlFinding::from).collect())
    }

    /// Aggregate statistics.
    async fn stats(&self, ctx: &Context<'_>) -> async_graphql::Result<GqlStats> {
        let state = ctx.data::<ServiceState>()?;
        let s = state.engine.stats().await.map_err(to_err)?;
        Ok(GqlStats {
            proposals: s.proposals,
            executed: s.executed,
            findings: s.findings,
            open_findings: s.open_findings,
        })
    }

    /// Current governance configuration.
    async fn config(&self, ctx: &Context<'_>) -> async_graphql::Result<GqlConfig> {
        let state = ctx.data::<ServiceState>()?;
        let cfg = state.engine.config();
        Ok(GqlConfig {
            authority: cfg.authority,
            guardians: cfg.guardians,
            threshold: cfg.threshold,
            timelock_seconds: cfg.timelock_seconds,
            paused: cfg.paused,
            proposal_count: cfg.proposal_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Mutation root
// ---------------------------------------------------------------------------

/// GraphQL mutation root.
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Creates a timelocked upgrade proposal.
    async fn propose_upgrade(
        &self,
        ctx: &Context<'_>,
        input: ProposeInput,
    ) -> async_graphql::Result<GqlProposal> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        let rec = state
            .engine
            .propose(
                ProgramId(input.program_id),
                &input.build_hash,
                input.proposer,
            )
            .await
            .map_err(to_err)?;
        Ok(rec.into())
    }

    /// Registers a guardian approval.
    async fn approve_upgrade(
        &self,
        ctx: &Context<'_>,
        id: u64,
        guardian: String,
    ) -> async_graphql::Result<GqlProposal> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        let rec = state.engine.approve(id, guardian).await.map_err(to_err)?;
        Ok(rec.into())
    }

    /// Executes a proposal once threshold + timelock pass.
    async fn execute_upgrade(
        &self,
        ctx: &Context<'_>,
        id: u64,
    ) -> async_graphql::Result<GqlProposal> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        let rec = state.engine.execute(id).await.map_err(to_err)?;
        Ok(rec.into())
    }

    /// Cancels a proposal.
    async fn cancel_proposal(
        &self,
        ctx: &Context<'_>,
        id: u64,
    ) -> async_graphql::Result<GqlProposal> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        let rec = state.engine.cancel(id).await.map_err(to_err)?;
        Ok(rec.into())
    }

    /// Records a security finding.
    async fn raise_finding(
        &self,
        ctx: &Context<'_>,
        input: FindingInput,
    ) -> async_graphql::Result<GqlFinding> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        let rec = state
            .engine
            .raise_finding(
                input.id,
                ProgramId(input.program_id),
                input.threat.into(),
                input.severity.into(),
                input.title,
            )
            .await
            .map_err(to_err)?;
        Ok(rec.into())
    }

    /// Sets or clears the pause flag.
    async fn set_paused(&self, ctx: &Context<'_>, paused: bool) -> async_graphql::Result<bool> {
        let state = ctx.data::<ServiceState>()?;
        rate_limit(state)?;
        state.engine.set_paused(paused).await.map_err(to_err)?;
        Ok(paused)
    }
}

// ---------------------------------------------------------------------------
// Subscription root
// ---------------------------------------------------------------------------

/// GraphQL subscription root.
pub struct SubscriptionRoot;

#[Subscription]
impl SubscriptionRoot {
    /// Streams domain events as the audit state changes.
    async fn events(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<impl Stream<Item = GqlEvent>> {
        let state = ctx.data::<ServiceState>()?;
        let stream = state.events.subscribe();
        Ok(stream.filter_map(|r| r.ok().map(GqlEvent::from)))
    }
}

// ---------------------------------------------------------------------------
// Helpers & schema builder
// ---------------------------------------------------------------------------

/// The concrete schema type.
pub type SecureDeploySchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

/// Builds the GraphQL schema with the shared [`ServiceState`] injected.
#[must_use]
pub fn build_schema(state: ServiceState) -> SecureDeploySchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .data(state)
        .finish()
}

fn to_err(e: impl std::fmt::Display) -> async_graphql::Error {
    async_graphql::Error::new(e.to_string())
}

fn rate_limit(state: &ServiceState) -> async_graphql::Result<()> {
    state
        .rate_limiter
        .try_acquire()
        .map_err(|_| async_graphql::Error::new("rate limit exceeded"))
}
