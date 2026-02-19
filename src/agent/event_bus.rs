use serde::{Deserialize, Serialize};

/// Events that can be delivered to the agent loop between tool iterations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentEvent {
    /// A background process session completed.
    ProcessCompleted {
        session_id: String,
        exit_code: i32,
        output_tail: String,
    },
    /// A background sub-agent completed its task.
    SubAgentCompleted {
        task_id: String,
        agent_name: String,
        result: String,
    },
    /// A webhook event was received.
    WebhookReceived {
        source: String,
        payload: serde_json::Value,
    },
    /// A cron job was triggered.
    CronTriggered { job_name: String },
    /// A generic notification.
    Notification { source: String, message: String },
}

impl AgentEvent {
    /// Format the event as a system message for injection into the conversation.
    pub fn to_system_message(&self) -> String {
        match self {
            Self::ProcessCompleted {
                session_id,
                exit_code,
                output_tail,
            } => {
                let status = if *exit_code == 0 { "success" } else { "failed" };
                let tail = if output_tail.len() > 500 {
                    format!("...{}", &output_tail[output_tail.len() - 500..])
                } else {
                    output_tail.clone()
                };
                format!(
                    "[System] Background process session '{session_id}' completed ({status}, exit {exit_code}). Last output:\n{tail}"
                )
            }
            Self::SubAgentCompleted {
                task_id,
                agent_name,
                result,
            } => {
                let truncated = if result.len() > 1000 {
                    format!("{}...", &result[..1000])
                } else {
                    result.clone()
                };
                format!(
                    "[System] Sub-agent '{agent_name}' completed task '{task_id}':\n{truncated}"
                )
            }
            Self::WebhookReceived { source, payload } => {
                let payload_str = serde_json::to_string_pretty(payload)
                    .unwrap_or_else(|_| format!("{payload:?}"));
                let truncated = if payload_str.len() > 500 {
                    format!("{}...", &payload_str[..500])
                } else {
                    payload_str
                };
                format!("[System] Webhook received from '{source}':\n{truncated}")
            }
            Self::CronTriggered { job_name } => {
                format!("[System] Cron job '{job_name}' triggered.")
            }
            Self::Notification { source, message } => {
                format!("[System] Notification from '{source}': {message}")
            }
        }
    }
}

/// Async mailbox for receiving events in the agent loop.
pub struct AgentMailbox {
    receiver: tokio::sync::mpsc::Receiver<AgentEvent>,
    sender: tokio::sync::mpsc::Sender<AgentEvent>,
}

impl AgentMailbox {
    /// Create a new mailbox with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
        Self { receiver, sender }
    }

    /// Get a sender handle for posting events to this mailbox.
    pub fn sender(&self) -> tokio::sync::mpsc::Sender<AgentEvent> {
        self.sender.clone()
    }

    /// Non-blocking: drain all pending events.
    pub fn drain(&mut self) -> Vec<AgentEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.receiver.try_recv() {
            events.push(event);
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_completed_message() {
        let event = AgentEvent::ProcessCompleted {
            session_id: "abc123".into(),
            exit_code: 0,
            output_tail: "build successful".into(),
        };
        let msg = event.to_system_message();
        assert!(msg.contains("abc123"));
        assert!(msg.contains("success"));
        assert!(msg.contains("build successful"));
    }

    #[test]
    fn sub_agent_completed_message() {
        let event = AgentEvent::SubAgentCompleted {
            task_id: "task-1".into(),
            agent_name: "researcher".into(),
            result: "Found 5 relevant files".into(),
        };
        let msg = event.to_system_message();
        assert!(msg.contains("researcher"));
        assert!(msg.contains("task-1"));
        assert!(msg.contains("Found 5 relevant files"));
    }

    #[test]
    fn webhook_message() {
        let event = AgentEvent::WebhookReceived {
            source: "github".into(),
            payload: serde_json::json!({"action": "push"}),
        };
        let msg = event.to_system_message();
        assert!(msg.contains("github"));
        assert!(msg.contains("push"));
    }

    #[tokio::test]
    async fn mailbox_send_and_drain() {
        let mut mailbox = AgentMailbox::new(10);
        let sender = mailbox.sender();

        sender
            .send(AgentEvent::Notification {
                source: "test".into(),
                message: "hello".into(),
            })
            .await
            .unwrap();

        sender
            .send(AgentEvent::CronTriggered {
                job_name: "cleanup".into(),
            })
            .await
            .unwrap();

        let events = mailbox.drain();
        assert_eq!(events.len(), 2);
    }

    #[tokio::test]
    async fn mailbox_drain_empty() {
        let mut mailbox = AgentMailbox::new(10);
        let events = mailbox.drain();
        assert!(events.is_empty());
    }
}
