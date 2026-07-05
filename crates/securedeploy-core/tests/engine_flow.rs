use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use securedeploy_core::{
    AuditEngine, DomainEvent, EventSink, FindingRecord, FindingStore, GovernanceConfig,
    ProposalRecord, ProposalStore, Result, UnixClock,
};
use securedeploy_types::{BuildHash, ProgramId, ProposalStatus, Severity, ThreatClass};

#[derive(Default)]
struct MemProposals(Mutex<Vec<ProposalRecord>>);

#[async_trait]
impl ProposalStore for MemProposals {
    async fn upsert(&self, record: ProposalRecord) -> Result<()> {
        let mut v = self.0.lock();
        if let Some(existing) = v.iter_mut().find(|r| r.id == record.id) {
            *existing = record;
        } else {
            v.push(record);
        }
        Ok(())
    }
    async fn get(&self, id: u64) -> Result<Option<ProposalRecord>> {
        Ok(self.0.lock().iter().find(|r| r.id.0 == id).cloned())
    }
    async fn list(&self) -> Result<Vec<ProposalRecord>> {
        Ok(self.0.lock().clone())
    }
    async fn count(&self) -> Result<u64> {
        Ok(self.0.lock().len() as u64)
    }
}

#[derive(Default)]
struct MemFindings(Mutex<Vec<FindingRecord>>);

#[async_trait]
impl FindingStore for MemFindings {
    async fn insert(&self, record: FindingRecord) -> Result<()> {
        self.0.lock().push(record);
        Ok(())
    }
    async fn get(&self, id: &str) -> Result<Option<FindingRecord>> {
        Ok(self.0.lock().iter().find(|r| r.id == id).cloned())
    }
    async fn list(&self) -> Result<Vec<FindingRecord>> {
        Ok(self.0.lock().clone())
    }
}

#[derive(Default)]
struct RecordingSink(Mutex<Vec<DomainEvent>>);

#[async_trait]
impl EventSink for RecordingSink {
    async fn publish(&self, event: DomainEvent) -> Result<()> {
        self.0.lock().push(event);
        Ok(())
    }
}

struct FixedClock(std::sync::atomic::AtomicI64);
impl UnixClock for FixedClock {
    fn now(&self) -> i64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

fn engine_with(
    timelock: i64,
) -> (
    AuditEngine<MemProposals, MemFindings, RecordingSink, FixedClock>,
    Arc<FixedClock>,
) {
    let clock = Arc::new(FixedClock(std::sync::atomic::AtomicI64::new(1_000)));
    let cfg = GovernanceConfig::new(
        "authority".into(),
        vec!["g1".into(), "g2".into(), "g3".into()],
        2,
        timelock,
    );
    let engine = AuditEngine::new(
        Arc::new(MemProposals::default()),
        Arc::new(MemFindings::default()),
        Arc::new(RecordingSink::default()),
        clock.clone(),
        cfg,
    )
    .unwrap();
    (engine, clock)
}

fn hash_hex() -> String {
    BuildHash::of(b"artifact").to_hex()
}

#[tokio::test]
async fn full_approval_and_execute_flow() {
    let (engine, clock) = engine_with(100);
    let p = engine
        .propose(ProgramId("Prog1".into()), &hash_hex(), "g1".into())
        .await
        .unwrap();
    assert_eq!(p.status, ProposalStatus::Pending);

    engine.approve(0, "g1".into()).await.unwrap();
    let after = engine.approve(0, "g2".into()).await.unwrap();
    assert_eq!(after.status, ProposalStatus::Approved);
    assert_eq!(after.approvals, 2);

    // timelock still active
    assert!(engine.execute(0).await.is_err());

    clock.0.store(2_000, std::sync::atomic::Ordering::SeqCst);
    let done = engine.execute(0).await.unwrap();
    assert_eq!(done.status, ProposalStatus::Executed);
}

#[tokio::test]
async fn duplicate_approval_rejected() {
    let (engine, _clock) = engine_with(0);
    engine
        .propose(ProgramId("P".into()), &hash_hex(), "authority".into())
        .await
        .unwrap();
    engine.approve(0, "g1".into()).await.unwrap();
    assert!(engine.approve(0, "g1".into()).await.is_err());
}

#[tokio::test]
async fn non_guardian_cannot_approve() {
    let (engine, _clock) = engine_with(0);
    engine
        .propose(ProgramId("P".into()), &hash_hex(), "authority".into())
        .await
        .unwrap();
    assert!(engine.approve(0, "intruder".into()).await.is_err());
}

#[tokio::test]
async fn non_guardian_cannot_propose() {
    let (engine, _clock) = engine_with(0);
    let res = engine
        .propose(ProgramId("P".into()), &hash_hex(), "intruder".into())
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn execute_below_threshold_rejected() {
    let (engine, _clock) = engine_with(0);
    engine
        .propose(ProgramId("P".into()), &hash_hex(), "authority".into())
        .await
        .unwrap();
    engine.approve(0, "g1".into()).await.unwrap();
    assert!(engine.execute(0).await.is_err());
}

#[tokio::test]
async fn pause_blocks_proposals() {
    let (engine, _clock) = engine_with(0);
    engine.set_paused(true).await.unwrap();
    assert!(engine
        .propose(ProgramId("P".into()), &hash_hex(), "authority".into())
        .await
        .is_err());
}

#[tokio::test]
async fn cancel_prevents_execution() {
    let (engine, _clock) = engine_with(0);
    engine
        .propose(ProgramId("P".into()), &hash_hex(), "authority".into())
        .await
        .unwrap();
    engine.approve(0, "g1".into()).await.unwrap();
    engine.approve(0, "g2".into()).await.unwrap();
    engine.cancel(0).await.unwrap();
    assert!(engine.execute(0).await.is_err());
}

#[tokio::test]
async fn findings_and_stats() {
    let (engine, _clock) = engine_with(0);
    engine
        .raise_finding(
            "F-1".into(),
            ProgramId("P".into()),
            ThreatClass::MissingSignerCheck,
            Severity::High,
            "no signer check".into(),
        )
        .await
        .unwrap();
    let stats = engine.stats().await.unwrap();
    assert_eq!(stats.findings, 1);
    assert_eq!(stats.open_findings, 1);
}
