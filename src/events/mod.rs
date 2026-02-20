//! Event-driven agent triggers — external event sources that feed the agent loop.
//!
//! This module provides:
//! - `EventSource` trait: abstraction for external event listeners (AMQP, etc.)
//! - `EventProcessor`: orchestrator that connects sources, routes events, and runs the agent loop
//! - `EventRoute`: pattern-based routing from events to skills

#[cfg(feature = "amqp")]
pub mod amqp;

use crate::agent::event_bus::AgentEvent;
use crate::gateway::WebhookAgentContext;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

/// Abstraction for an external event listener that produces `AgentEvent`s.
#[async_trait]
pub trait EventSource: Send + Sync {
    /// Human-readable name of this source (e.g., "erp-events").
    fn name(&self) -> &str;

    /// Establish connection to the event backend.
    async fn connect(&mut self) -> Result<()>;

    /// Await and return the next event. Blocks until an event is available.
    async fn next_event(&mut self) -> Result<AgentEvent>;

    /// Acknowledge successful processing of an event by its delivery ID.
    async fn acknowledge(&self, event_id: &str) -> Result<()>;

    /// Disconnect from the event backend.
    async fn disconnect(&mut self) -> Result<()>;

    /// Whether this source currently has an active connection.
    fn is_connected(&self) -> bool;
}

/// Pattern-based routing rule: maps events from a source to a skill/prompt template.
#[derive(Debug, Clone)]
pub struct EventRoute {
    /// Event source name to match against.
    pub source: String,
    /// Optional glob pattern for routing key matching.
    pub pattern: Option<String>,
    /// Skill to activate (None = use all available skills).
    pub skill: Option<String>,
    /// Prompt template with `{source}`, `{payload}`, `{metadata}` placeholders.
    pub prompt_template: String,
}

impl EventRoute {
    /// Check whether this route matches a given source and routing key.
    pub fn matches(&self, source: &str, routing_key: Option<&str>) -> bool {
        if self.source != source {
            return false;
        }

        match (&self.pattern, routing_key) {
            (None, _) => true,
            (Some(pattern), Some(key)) => glob_match(pattern, key),
            (Some(_), None) => false,
        }
    }

    /// Format the prompt template with event data.
    pub fn format_prompt(&self, source: &str, payload: &str) -> String {
        self.prompt_template
            .replace("{source}", source)
            .replace("{payload}", payload)
    }
}

/// Simple glob matching — supports `*` as wildcard for any segment.
fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('.').collect();
    let value_parts: Vec<&str> = value.split('.').collect();

    if pattern_parts.len() != value_parts.len() {
        return false;
    }

    pattern_parts
        .iter()
        .zip(value_parts.iter())
        .all(|(p, v)| *p == "*" || p == v)
}

/// Default prompt template when no route matches.
const DEFAULT_PROMPT_TEMPLATE: &str = "Received event from {source}: {payload}";

/// Orchestrator that connects event sources, routes events, and runs the agent loop.
pub struct EventProcessor {
    sources: Vec<Box<dyn EventSource>>,
    agent_context: Arc<WebhookAgentContext>,
    routes: Vec<EventRoute>,
    observer: Arc<dyn crate::observability::Observer>,
    skills: Vec<crate::skills::Skill>,
}

impl EventProcessor {
    pub fn new(
        sources: Vec<Box<dyn EventSource>>,
        agent_context: Arc<WebhookAgentContext>,
        routes: Vec<EventRoute>,
        observer: Arc<dyn crate::observability::Observer>,
    ) -> Self {
        Self {
            sources,
            agent_context,
            routes,
            observer,
            skills: Vec::new(),
        }
    }

    /// Attach loaded skills so event routes can inject skill-specific instructions.
    pub fn with_skills(mut self, skills: Vec<crate::skills::Skill>) -> Self {
        self.skills = skills;
        self
    }

    /// Run the event processing loop. Connects all sources and processes events.
    pub async fn run(&mut self) -> Result<()> {
        if self.sources.is_empty() {
            tracing::info!("No event sources configured; event processor idle");
            // Sleep forever to keep the supervisor happy
            futures::future::pending::<()>().await;
            return Ok(());
        }

        // Connect all sources
        for source in &mut self.sources {
            let name = source.name().to_string();
            match source.connect().await {
                Ok(()) => {
                    tracing::info!("Event source '{name}' connected");
                    crate::health::mark_component_ok(&format!("event_source_{name}"));
                }
                Err(e) => {
                    tracing::error!("Event source '{name}' failed to connect: {e}");
                    crate::health::mark_component_error(
                        &format!("event_source_{name}"),
                        e.to_string(),
                    );
                    return Err(e);
                }
            }
        }

        crate::health::mark_component_ok("event_processor");

        // Process events from sources sequentially.
        // Uses index-based iteration to avoid borrow conflicts.
        loop {
            for i in 0..self.sources.len() {
                let source_name = self.sources[i].name().to_string();

                if !self.sources[i].is_connected() {
                    tracing::warn!("Event source '{source_name}' disconnected, reconnecting...");
                    if let Err(e) = self.sources[i].connect().await {
                        tracing::error!("Event source '{source_name}' reconnection failed: {e}");
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        continue;
                    }
                }

                let event_result = self.sources[i].next_event().await;

                match event_result {
                    Ok(event) => {
                        let event_id = match &event {
                            AgentEvent::WebhookReceived { source, .. }
                            | AgentEvent::Notification { source, .. } => source.clone(),
                            AgentEvent::CronTriggered { job_name } => job_name.clone(),
                            _ => "unknown".to_string(),
                        };

                        self.observer.record_event(
                            &crate::observability::ObserverEvent::AgentStart {
                                provider: "event_processor".to_string(),
                                model: "event".to_string(),
                            },
                        );

                        if let Err(e) = self.process_event(&event, &source_name).await {
                            tracing::error!(
                                "Event processing failed for source '{source_name}': {e}"
                            );
                            // Don't ack — message will redeliver
                            continue;
                        }

                        // Acknowledge successful processing
                        if let Err(e) = self.sources[i].acknowledge(&event_id).await {
                            tracing::warn!("Event acknowledgment failed for '{event_id}': {e}");
                        }
                    }
                    Err(e) => {
                        tracing::error!("Event source '{source_name}' error receiving event: {e}");
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
            }
        }
    }

    /// Process a single event: match routes, format prompt, run agent loop.
    async fn process_event(&self, event: &AgentEvent, source_name: &str) -> Result<()> {
        let (payload_str, routing_key) = match event {
            AgentEvent::WebhookReceived { payload, source } => {
                let payload_str =
                    serde_json::to_string(payload).unwrap_or_else(|_| format!("{payload:?}"));
                (payload_str, Some(source.as_str()))
            }
            other => (other.to_system_message(), None),
        };

        // Find matching route
        let matched_route = self
            .routes
            .iter()
            .find(|r| r.matches(source_name, routing_key));

        let prompt = if let Some(route) = matched_route {
            route.format_prompt(source_name, &payload_str)
        } else {
            DEFAULT_PROMPT_TEMPLATE
                .replace("{source}", source_name)
                .replace("{payload}", &payload_str)
        };

        let skill_name = matched_route.and_then(|r| r.skill.as_deref());

        tracing::info!(
            source = source_name,
            skill = skill_name.unwrap_or("all"),
            "Processing event"
        );

        // Inject skill-specific instructions when the route targets a named skill.
        let final_prompt = if let Some(name) = skill_name {
            if let Some(skill) = self.skills.iter().find(|s| s.name == name) {
                use std::fmt::Write;
                let mut enriched = String::with_capacity(prompt.len() + 512);
                let _ = writeln!(enriched, "[Skill: {}]", skill.name);
                if !skill.prompts.is_empty() {
                    enriched.push_str("[Instructions]\n");
                    for instruction in &skill.prompts {
                        enriched.push_str(instruction);
                        enriched.push('\n');
                    }
                    enriched.push('\n');
                }
                if !skill.tools.is_empty() {
                    enriched.push_str("[Skill tools]\n");
                    for tool in &skill.tools {
                        let _ = writeln!(
                            enriched,
                            "- {} ({}): {}",
                            tool.name, tool.kind, tool.description
                        );
                    }
                    enriched.push('\n');
                }
                enriched.push_str(&prompt);
                enriched
            } else {
                tracing::warn!(skill = name, "Route references unknown skill");
                prompt
            }
        } else {
            prompt
        };

        // Run the agent with the formatted prompt
        let _response = self
            .agent_context
            .process_message(&final_prompt, Some(source_name), None)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_exact() {
        assert!(glob_match(
            "tasks.inventory.update",
            "tasks.inventory.update"
        ));
    }

    #[test]
    fn glob_match_wildcard() {
        assert!(glob_match("tasks.inventory.*", "tasks.inventory.update"));
        assert!(glob_match("tasks.*.update", "tasks.inventory.update"));
        assert!(glob_match("*.inventory.update", "tasks.inventory.update"));
    }

    #[test]
    fn glob_match_no_match() {
        assert!(!glob_match("tasks.inventory.*", "tasks.orders.update"));
        assert!(!glob_match("tasks.inventory", "tasks.inventory.update"));
    }

    #[test]
    fn event_route_matches_source_only() {
        let route = EventRoute {
            source: "erp-events".into(),
            pattern: None,
            skill: None,
            prompt_template: DEFAULT_PROMPT_TEMPLATE.into(),
        };
        assert!(route.matches("erp-events", None));
        assert!(route.matches("erp-events", Some("anything")));
        assert!(!route.matches("other-source", None));
    }

    #[test]
    fn event_route_matches_source_and_pattern() {
        let route = EventRoute {
            source: "erp-events".into(),
            pattern: Some("tasks.inventory.*".into()),
            skill: Some("data-checker".into()),
            prompt_template: "Check: {payload}".into(),
        };
        assert!(route.matches("erp-events", Some("tasks.inventory.update")));
        assert!(!route.matches("erp-events", Some("tasks.orders.create")));
        assert!(!route.matches("erp-events", None));
        assert!(!route.matches("other", Some("tasks.inventory.update")));
    }

    #[test]
    fn event_route_no_match_uses_default() {
        let routes = [EventRoute {
            source: "specific-source".into(),
            pattern: None,
            skill: None,
            prompt_template: "Specific: {payload}".into(),
        }];
        let matched = routes.iter().find(|r| r.matches("other-source", None));
        assert!(matched.is_none());
    }

    #[test]
    fn event_route_format_prompt() {
        let route = EventRoute {
            source: "erp".into(),
            pattern: None,
            skill: None,
            prompt_template: "Event from {source}: {payload}".into(),
        };
        let result = route.format_prompt("erp-system", r#"{"action":"update"}"#);
        assert_eq!(result, r#"Event from erp-system: {"action":"update"}"#);
    }
}
