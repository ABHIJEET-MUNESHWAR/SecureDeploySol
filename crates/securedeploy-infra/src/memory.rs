use async_trait::async_trait;
use dashmap::DashMap;

use securedeploy_core::{
    EngineError, FindingRecord, FindingStore, ProposalRecord, ProposalStore, Result,
};

/// Lock-striped in-memory proposal store.
#[derive(Default)]
pub struct InMemoryProposalStore {
    records: DashMap<u64, ProposalRecord>,
}

#[async_trait]
impl ProposalStore for InMemoryProposalStore {
    async fn upsert(&self, record: ProposalRecord) -> Result<()> {
        self.records.insert(record.id.0, record);
        Ok(())
    }
    async fn get(&self, id: u64) -> Result<Option<ProposalRecord>> {
        Ok(self.records.get(&id).map(|r| r.clone()))
    }
    async fn list(&self) -> Result<Vec<ProposalRecord>> {
        let mut v: Vec<_> = self.records.iter().map(|r| r.clone()).collect();
        v.sort_by_key(|r| r.id.0);
        Ok(v)
    }
    async fn count(&self) -> Result<u64> {
        Ok(self.records.len() as u64)
    }
}

/// Lock-striped in-memory finding store.
#[derive(Default)]
pub struct InMemoryFindingStore {
    records: DashMap<String, FindingRecord>,
}

#[async_trait]
impl FindingStore for InMemoryFindingStore {
    async fn insert(&self, record: FindingRecord) -> Result<()> {
        if self.records.contains_key(&record.id) {
            return Err(EngineError::Store(format!(
                "duplicate finding {}",
                record.id
            )));
        }
        self.records.insert(record.id.clone(), record);
        Ok(())
    }
    async fn get(&self, id: &str) -> Result<Option<FindingRecord>> {
        Ok(self.records.get(id).map(|r| r.clone()))
    }
    async fn list(&self) -> Result<Vec<FindingRecord>> {
        Ok(self.records.iter().map(|r| r.clone()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use securedeploy_types::{ProgramId, ProposalId, ProposalStatus, Severity, ThreatClass};

    fn proposal(id: u64) -> ProposalRecord {
        ProposalRecord {
            id: ProposalId(id),
            program_id: ProgramId("P".into()),
            build_hash: "ab".into(),
            proposer: "g1".into(),
            eta: 0,
            approvals: 0,
            threshold: 2,
            status: ProposalStatus::Pending,
            created_at: 0,
        }
    }

    #[tokio::test]
    async fn proposal_upsert_and_list() {
        let store = InMemoryProposalStore::default();
        store.upsert(proposal(1)).await.unwrap();
        store.upsert(proposal(0)).await.unwrap();
        let list = store.list().await.unwrap();
        assert_eq!(list[0].id.0, 0);
        assert_eq!(store.count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn finding_dedup() {
        let store = InMemoryFindingStore::default();
        let f = FindingRecord {
            id: "F1".into(),
            program_id: ProgramId("P".into()),
            threat: ThreatClass::MissingOwnerCheck,
            severity: Severity::Medium,
            title: "t".into(),
            resolved: false,
            created_at: 0,
        };
        store.insert(f.clone()).await.unwrap();
        assert!(store.insert(f).await.is_err());
    }
}
