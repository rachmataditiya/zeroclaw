//! Message debounce pipeline for channel message processing.
//!
//! When a user sends multiple messages in rapid succession, this pipeline
//! coalesces them into a single message to avoid redundant LLM calls.
//! After receiving the first message from a sender, the pipeline waits
//! `debounce_ms` for additional messages before yielding the combined text.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

/// Debounce pipeline that coalesces rapid messages per sender.
#[derive(Clone)]
pub struct MessagePipeline {
    debounce: Duration,
    pending: Arc<Mutex<HashMap<String, PendingMessage>>>,
}

struct PendingMessage {
    parts: Vec<String>,
    first_received: Instant,
}

impl MessagePipeline {
    /// Create a new pipeline with the given debounce window.
    /// If `debounce_ms` is 0, messages pass through immediately.
    pub fn new(debounce_ms: u64) -> Self {
        Self {
            debounce: Duration::from_millis(debounce_ms),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Enqueue a message from `sender`. Returns `Some(coalesced)` when the
    /// debounce window has elapsed and the combined message is ready,
    /// or `None` if the message was absorbed into a pending batch.
    pub async fn enqueue(&self, sender: &str, message: String) -> Option<String> {
        if self.debounce.is_zero() {
            return Some(message);
        }

        {
            let mut pending = self.pending.lock().await;
            let entry = pending
                .entry(sender.to_string())
                .or_insert_with(|| PendingMessage {
                    parts: Vec::new(),
                    first_received: Instant::now(),
                });
            entry.parts.push(message);

            // If we've already been waiting longer than debounce, flush now
            if entry.first_received.elapsed() >= self.debounce {
                let entry = pending.remove(sender).unwrap();
                return Some(entry.parts.join("\n"));
            }
        }

        // Wait for the debounce window to expire
        tokio::time::sleep(self.debounce).await;

        // After sleeping, drain whatever has accumulated
        let mut pending = self.pending.lock().await;
        if let Some(entry) = pending.remove(sender) {
            Some(entry.parts.join("\n"))
        } else {
            // Another concurrent call already drained this sender
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn zero_debounce_passes_through() {
        let pipeline = MessagePipeline::new(0);
        let result = pipeline.enqueue("user_a", "hello".into()).await;
        assert_eq!(result, Some("hello".to_string()));
    }

    #[tokio::test]
    async fn single_message_returned_after_debounce() {
        let pipeline = MessagePipeline::new(50);
        let result = pipeline.enqueue("user_a", "hello".into()).await;
        assert_eq!(result, Some("hello".to_string()));
    }

    #[tokio::test]
    async fn rapid_messages_coalesced() {
        let pipeline = MessagePipeline::new(100);
        let p1 = pipeline.clone();
        let p2 = pipeline.clone();

        // First message starts the debounce window
        let handle1 = tokio::spawn(async move { p1.enqueue("user_a", "first".into()).await });

        // Second message arrives within debounce window
        tokio::time::sleep(Duration::from_millis(30)).await;
        let handle2 = tokio::spawn(async move { p2.enqueue("user_a", "second".into()).await });

        let r1 = handle1.await.unwrap();
        let r2 = handle2.await.unwrap();

        // One of them should get the coalesced message, the other None
        let results: Vec<Option<String>> = vec![r1, r2];
        let non_none: Vec<&String> = results.iter().filter_map(|r| r.as_ref()).collect();

        // At least one result should contain both messages
        assert!(
            non_none
                .iter()
                .any(|r| r.contains("first") && r.contains("second")),
            "Expected coalesced message containing both parts, got: {non_none:?}"
        );
    }

    #[tokio::test]
    async fn different_senders_independent() {
        let pipeline = MessagePipeline::new(50);
        let p1 = pipeline.clone();
        let p2 = pipeline.clone();

        let handle1 = tokio::spawn(async move { p1.enqueue("user_a", "msg_a".into()).await });
        let handle2 = tokio::spawn(async move { p2.enqueue("user_b", "msg_b".into()).await });

        let r1 = handle1.await.unwrap();
        let r2 = handle2.await.unwrap();

        assert_eq!(r1, Some("msg_a".to_string()));
        assert_eq!(r2, Some("msg_b".to_string()));
    }
}
