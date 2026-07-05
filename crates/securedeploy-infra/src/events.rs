use async_trait::async_trait;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

use securedeploy_core::{DomainEvent, EventSink, Result};

/// Broadcast-backed event sink for GraphQL subscription fan-out.
pub struct BroadcastEventSink {
    tx: broadcast::Sender<DomainEvent>,
}

impl BroadcastEventSink {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// A stream of future events (lagged items are skipped).
    #[must_use]
    pub fn subscribe(&self) -> BroadcastStream<DomainEvent> {
        BroadcastStream::new(self.tx.subscribe())
    }
}

impl Default for BroadcastEventSink {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[async_trait]
impl EventSink for BroadcastEventSink {
    async fn publish(&self, event: DomainEvent) -> Result<()> {
        // No subscribers is not an error.
        let _ = self.tx.send(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn delivers_to_subscribers() {
        let sink = BroadcastEventSink::new(8);
        let mut stream = sink.subscribe();
        sink.publish(DomainEvent::PauseChanged { paused: true })
            .await
            .unwrap();
        let got = stream.next().await.unwrap().unwrap();
        assert_eq!(got, DomainEvent::PauseChanged { paused: true });
    }

    #[tokio::test]
    async fn publish_without_subscribers_ok() {
        let sink = BroadcastEventSink::new(8);
        assert!(sink
            .publish(DomainEvent::ProposalExecuted { id: 1 })
            .await
            .is_ok());
    }
}
