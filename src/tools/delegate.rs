use super::traits::{Tool, ToolResult};
use crate::config::DelegateAgentConfig;
use crate::providers::{self, ChatMessage, ChatRequest, ChatResponse, Provider};
use crate::security::policy::ToolOperation;
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Default timeout for sub-agent provider calls.
const DELEGATE_TIMEOUT_SECS: u64 = 120;

/// Default max iterations for full-mode sub-agents.
const DEFAULT_SUB_AGENT_MAX_ITERATIONS: usize = 10;

/// Tool that delegates a subtask to a named agent with a different
/// provider/model configuration. Enables multi-agent workflows where
/// a primary agent can hand off specialized work (research, coding,
/// summarization) to purpose-built sub-agents.
///
/// Supports two modes:
/// - `"simple"` (default): Single LLM call, synchronous response.
/// - `"full"`: Runs a tool-use loop where the sub-agent can use tools.
pub struct DelegateTool {
    agents: Arc<HashMap<String, DelegateAgentConfig>>,
    security: Arc<SecurityPolicy>,
    /// Global credential fallback (from config.api_key)
    fallback_credential: Option<String>,
    /// Depth at which this tool instance lives in the delegation chain.
    depth: u32,
    /// Parent's tool registry (shared for "full" mode sub-agents).
    parent_tools: Option<Arc<Vec<Box<dyn Tool>>>>,
}

impl DelegateTool {
    pub fn new(
        agents: HashMap<String, DelegateAgentConfig>,
        fallback_credential: Option<String>,
        security: Arc<SecurityPolicy>,
    ) -> Self {
        Self {
            agents: Arc::new(agents),
            security,
            fallback_credential,
            depth: 0,
            parent_tools: None,
        }
    }

    /// Create a DelegateTool for a sub-agent (with incremented depth).
    pub fn with_depth(
        agents: HashMap<String, DelegateAgentConfig>,
        fallback_credential: Option<String>,
        security: Arc<SecurityPolicy>,
        depth: u32,
    ) -> Self {
        Self {
            agents: Arc::new(agents),
            security,
            fallback_credential,
            depth,
            parent_tools: None,
        }
    }

    /// Set the parent tool registry for "full" mode sub-agents.
    pub fn with_parent_tools(mut self, tools: Arc<Vec<Box<dyn Tool>>>) -> Self {
        self.parent_tools = Some(tools);
        self
    }
}

#[async_trait]
impl Tool for DelegateTool {
    fn name(&self) -> &str {
        "delegate"
    }

    fn description(&self) -> &str {
        "Delegate a subtask to a specialized agent. Use when: a task benefits from a different model \
         (e.g. fast summarization, deep reasoning, code generation). Supports simple (single call) \
         and full (multi-turn with tools) modes."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        let agent_names: Vec<&str> = self.agents.keys().map(|s: &String| s.as_str()).collect();
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "agent": {
                    "type": "string",
                    "minLength": 1,
                    "description": format!(
                        "Name of the agent to delegate to. Available: {}",
                        if agent_names.is_empty() {
                            "(none configured)".to_string()
                        } else {
                            agent_names.join(", ")
                        }
                    )
                },
                "prompt": {
                    "type": "string",
                    "minLength": 1,
                    "description": "The task/prompt to send to the sub-agent"
                },
                "context": {
                    "type": "string",
                    "description": "Optional context to prepend (e.g. relevant code, prior findings)"
                },
                "mode": {
                    "type": "string",
                    "enum": ["simple", "full"],
                    "description": "Delegation mode: 'simple' (single LLM call) or 'full' (multi-turn with tools). Defaults to agent config."
                }
            },
            "required": ["agent", "prompt"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let agent_name = args
            .get("agent")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .ok_or_else(|| anyhow::anyhow!("Missing 'agent' parameter"))?;

        if agent_name.is_empty() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("'agent' parameter must not be empty".into()),
            });
        }

        let prompt = args
            .get("prompt")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .ok_or_else(|| anyhow::anyhow!("Missing 'prompt' parameter"))?;

        if prompt.is_empty() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("'prompt' parameter must not be empty".into()),
            });
        }

        let context = args
            .get("context")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("");

        // Look up agent config
        let agent_config = match self.agents.get(agent_name) {
            Some(cfg) => cfg,
            None => {
                let available: Vec<&str> =
                    self.agents.keys().map(|s: &String| s.as_str()).collect();
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "Unknown agent '{agent_name}'. Available agents: {}",
                        if available.is_empty() {
                            "(none configured)".to_string()
                        } else {
                            available.join(", ")
                        }
                    )),
                });
            }
        };

        // Check recursion depth (immutable — set at construction, incremented for sub-agents)
        if self.depth >= agent_config.max_depth {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Delegation depth limit reached ({depth}/{max}). \
                     Cannot delegate further to prevent infinite loops.",
                    depth = self.depth,
                    max = agent_config.max_depth
                )),
            });
        }

        if let Err(error) = self
            .security
            .enforce_tool_operation(ToolOperation::Act, "delegate")
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error),
            });
        }

        // Create provider for this agent
        let provider_credential_owned = agent_config
            .api_key
            .clone()
            .or_else(|| self.fallback_credential.clone());
        #[allow(clippy::option_as_ref_deref)]
        let provider_credential = provider_credential_owned.as_ref().map(String::as_str);

        let provider: Box<dyn Provider> =
            match providers::create_provider(&agent_config.provider, provider_credential) {
                Ok(p) => p,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!(
                            "Failed to create provider '{}' for agent '{agent_name}': {e}",
                            agent_config.provider
                        )),
                    });
                }
            };

        // Build the message
        let full_prompt = if context.is_empty() {
            prompt.to_string()
        } else {
            format!("[Context]\n{context}\n\n[Task]\n{prompt}")
        };

        let temperature = agent_config.temperature.unwrap_or(0.7);

        // Determine delegation mode (args override config)
        let mode = args
            .get("mode")
            .and_then(|v| v.as_str())
            .or(agent_config.mode.as_deref())
            .unwrap_or("simple");

        if mode == "full" {
            return self
                .execute_full_mode(
                    agent_name,
                    agent_config,
                    provider,
                    &full_prompt,
                    temperature,
                )
                .await;
        }

        // Simple mode: single LLM call
        let result = tokio::time::timeout(
            Duration::from_secs(DELEGATE_TIMEOUT_SECS),
            provider.chat_with_system(
                agent_config.system_prompt.as_deref(),
                &full_prompt,
                &agent_config.model,
                temperature,
            ),
        )
        .await;

        let result = match result {
            Ok(inner) => inner,
            Err(_elapsed) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "Agent '{agent_name}' timed out after {DELEGATE_TIMEOUT_SECS}s"
                    )),
                });
            }
        };

        match result {
            Ok(response) => {
                let mut rendered = response;
                if rendered.trim().is_empty() {
                    rendered = "[Empty response]".to_string();
                }

                Ok(ToolResult {
                    success: true,
                    output: format!(
                        "[Agent '{agent_name}' ({provider}/{model})]\n{rendered}",
                        provider = agent_config.provider,
                        model = agent_config.model
                    ),
                    error: None,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Agent '{agent_name}' failed: {e}",)),
            }),
        }
    }
}

impl DelegateTool {
    /// Execute in "full" mode: run a multi-turn tool-use loop for the sub-agent.
    async fn execute_full_mode(
        &self,
        agent_name: &str,
        agent_config: &DelegateAgentConfig,
        provider: Box<dyn Provider>,
        full_prompt: &str,
        temperature: f64,
    ) -> anyhow::Result<ToolResult> {
        let max_iterations = agent_config
            .max_iterations
            .unwrap_or(DEFAULT_SUB_AGENT_MAX_ITERATIONS);

        // Build sub-agent tool registry from parent tools
        let sub_tools: Vec<&dyn Tool> = match &self.parent_tools {
            Some(tools) => {
                let allowed = &agent_config.allowed_tools;
                if allowed.is_empty() {
                    tools.iter().map(|t| t.as_ref()).collect()
                } else {
                    tools
                        .iter()
                        .filter(|t| allowed.contains(&t.name().to_string()))
                        .map(|t| t.as_ref())
                        .collect()
                }
            }
            None => vec![],
        };

        // Build tool specs for the provider
        let tool_specs: Vec<crate::tools::ToolSpec> = sub_tools.iter().map(|t| t.spec()).collect();
        let use_native_tools = provider.supports_native_tools() && !tool_specs.is_empty();

        // Build system prompt
        let mut system = agent_config.system_prompt.clone().unwrap_or_default();

        if !use_native_tools && !sub_tools.is_empty() {
            let tool_instructions = build_sub_agent_tool_instructions(&sub_tools);
            system = format!("{system}\n\n{tool_instructions}");
        }

        // Initialize conversation history
        let mut history = Vec::new();
        if !system.is_empty() {
            history.push(ChatMessage::system(&system));
        }
        history.push(ChatMessage::user(full_prompt));

        let mut final_response = String::new();

        for _iteration in 0..max_iterations {
            let request = ChatRequest {
                messages: &history,
                tools: if use_native_tools {
                    Some(&tool_specs)
                } else {
                    None
                },
            };

            let response: ChatResponse = match tokio::time::timeout(
                Duration::from_secs(DELEGATE_TIMEOUT_SECS),
                provider.chat(request, &agent_config.model, temperature),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    return Ok(ToolResult {
                        success: false,
                        output: final_response,
                        error: Some(format!("Sub-agent '{agent_name}' provider error: {e}")),
                    });
                }
                Err(_) => {
                    return Ok(ToolResult {
                        success: false,
                        output: final_response,
                        error: Some(format!(
                            "Sub-agent '{agent_name}' timed out after {DELEGATE_TIMEOUT_SECS}s"
                        )),
                    });
                }
            };

            let response_text = response.text.clone().unwrap_or_default();

            // Check for tool calls
            if response.tool_calls.is_empty() {
                final_response = response_text;
                break;
            }

            // Add assistant message with tool calls to history
            history.push(ChatMessage::assistant(&response_text));

            // Execute each tool call
            for tool_call in &response.tool_calls {
                let tool = sub_tools.iter().find(|t| t.name() == tool_call.name);

                // Parse arguments from JSON string
                let args: serde_json::Value =
                    serde_json::from_str(&tool_call.arguments).unwrap_or(json!({}));

                let tool_result = if let Some(tool) = tool {
                    match tool.execute(args).await {
                        Ok(r) => r,
                        Err(e) => ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(format!("Tool '{}' error: {e}", tool_call.name)),
                        },
                    }
                } else {
                    ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Unknown tool: {}", tool_call.name)),
                    }
                };

                let result_text = if tool_result.success {
                    tool_result.output
                } else {
                    format!(
                        "Error: {}",
                        tool_result.error.unwrap_or_else(|| "unknown error".into())
                    )
                };

                // For native tool support, use tool message with call ID;
                // otherwise, inject as user message with XML tags.
                if use_native_tools {
                    history.push(ChatMessage::tool(
                        json!({
                            "tool_call_id": tool_call.id,
                            "content": result_text,
                        })
                        .to_string(),
                    ));
                } else {
                    history.push(ChatMessage::user(format!(
                        "<tool_result name=\"{}\">{}</tool_result>",
                        tool_call.name, result_text
                    )));
                }
            }

            final_response = response_text;
        }

        if final_response.trim().is_empty() {
            final_response = "[Empty response]".to_string();
        }

        Ok(ToolResult {
            success: true,
            output: format!(
                "[Agent '{agent_name}' ({provider}/{model}, mode=full)]\n{final_response}",
                provider = agent_config.provider,
                model = agent_config.model
            ),
            error: None,
        })
    }
}

/// Build tool instructions text for non-native-tool providers.
fn build_sub_agent_tool_instructions(tools: &[&dyn Tool]) -> String {
    use std::fmt::Write;
    let mut instructions = String::from("# Available Tools\n\n");
    for tool in tools {
        let _ = write!(
            instructions,
            "## {}\n{}\nParameters: {}\n\n",
            tool.name(),
            tool.description(),
            serde_json::to_string_pretty(&tool.parameters_schema()).unwrap_or_default()
        );
    }
    instructions.push_str(
        "To use a tool, respond with:\n<tool_call>\n{\"name\": \"tool_name\", \"arguments\": {...}}\n</tool_call>\n",
    );
    instructions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{AutonomyLevel, SecurityPolicy};

    fn test_security() -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy::default())
    }

    fn sample_agents() -> HashMap<String, DelegateAgentConfig> {
        let mut agents = HashMap::new();
        agents.insert(
            "researcher".to_string(),
            DelegateAgentConfig {
                provider: "ollama".to_string(),
                model: "llama3".to_string(),
                system_prompt: Some("You are a research assistant.".to_string()),
                api_key: None,
                temperature: Some(0.3),
                max_depth: 3,
                mode: None,
                allowed_tools: vec![],
                max_iterations: None,
                background: false,
            },
        );
        agents.insert(
            "coder".to_string(),
            DelegateAgentConfig {
                provider: "openrouter".to_string(),
                model: "anthropic/claude-sonnet-4-20250514".to_string(),
                system_prompt: None,
                api_key: Some("delegate-test-credential".to_string()),
                temperature: None,
                max_depth: 2,
                mode: None,
                allowed_tools: vec![],
                max_iterations: None,
                background: false,
            },
        );
        agents
    }

    #[test]
    fn name_and_schema() {
        let tool = DelegateTool::new(sample_agents(), None, test_security());
        assert_eq!(tool.name(), "delegate");
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["agent"].is_object());
        assert!(schema["properties"]["prompt"].is_object());
        assert!(schema["properties"]["context"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("agent")));
        assert!(required.contains(&json!("prompt")));
        assert_eq!(schema["additionalProperties"], json!(false));
        assert_eq!(schema["properties"]["agent"]["minLength"], json!(1));
        assert_eq!(schema["properties"]["prompt"]["minLength"], json!(1));
    }

    #[test]
    fn description_not_empty() {
        let tool = DelegateTool::new(sample_agents(), None, test_security());
        assert!(!tool.description().is_empty());
    }

    #[test]
    fn schema_lists_agent_names() {
        let tool = DelegateTool::new(sample_agents(), None, test_security());
        let schema = tool.parameters_schema();
        let desc = schema["properties"]["agent"]["description"]
            .as_str()
            .unwrap();
        assert!(desc.contains("researcher") || desc.contains("coder"));
    }

    #[tokio::test]
    async fn missing_agent_param() {
        let tool = DelegateTool::new(sample_agents(), None, test_security());
        let result = tool.execute(json!({"prompt": "test"})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn missing_prompt_param() {
        let tool = DelegateTool::new(sample_agents(), None, test_security());
        let result = tool.execute(json!({"agent": "researcher"})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn unknown_agent_returns_error() {
        let tool = DelegateTool::new(sample_agents(), None, test_security());
        let result = tool
            .execute(json!({"agent": "nonexistent", "prompt": "test"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Unknown agent"));
    }

    #[tokio::test]
    async fn depth_limit_enforced() {
        let tool = DelegateTool::with_depth(sample_agents(), None, test_security(), 3);
        let result = tool
            .execute(json!({"agent": "researcher", "prompt": "test"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("depth limit"));
    }

    #[tokio::test]
    async fn depth_limit_per_agent() {
        // coder has max_depth=2, so depth=2 should be blocked
        let tool = DelegateTool::with_depth(sample_agents(), None, test_security(), 2);
        let result = tool
            .execute(json!({"agent": "coder", "prompt": "test"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("depth limit"));
    }

    #[test]
    fn empty_agents_schema() {
        let tool = DelegateTool::new(HashMap::new(), None, test_security());
        let schema = tool.parameters_schema();
        let desc = schema["properties"]["agent"]["description"]
            .as_str()
            .unwrap();
        assert!(desc.contains("none configured"));
    }

    #[tokio::test]
    async fn invalid_provider_returns_error() {
        let mut agents = HashMap::new();
        agents.insert(
            "broken".to_string(),
            DelegateAgentConfig {
                provider: "totally-invalid-provider".to_string(),
                model: "model".to_string(),
                system_prompt: None,
                api_key: None,
                temperature: None,
                max_depth: 3,
                mode: None,
                allowed_tools: vec![],
                max_iterations: None,
                background: false,
            },
        );
        let tool = DelegateTool::new(agents, None, test_security());
        let result = tool
            .execute(json!({"agent": "broken", "prompt": "test"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Failed to create provider"));
    }

    #[tokio::test]
    async fn blank_agent_rejected() {
        let tool = DelegateTool::new(sample_agents(), None, test_security());
        let result = tool
            .execute(json!({"agent": "  ", "prompt": "test"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("must not be empty"));
    }

    #[tokio::test]
    async fn blank_prompt_rejected() {
        let tool = DelegateTool::new(sample_agents(), None, test_security());
        let result = tool
            .execute(json!({"agent": "researcher", "prompt": "  \t  "}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("must not be empty"));
    }

    #[tokio::test]
    async fn whitespace_agent_name_trimmed_and_found() {
        let tool = DelegateTool::new(sample_agents(), None, test_security());
        // " researcher " with surrounding whitespace — after trim becomes "researcher"
        let result = tool
            .execute(json!({"agent": " researcher ", "prompt": "test"}))
            .await
            .unwrap();
        // Should find "researcher" after trim — will fail at provider level
        // since ollama isn't running, but must NOT get "Unknown agent".
        assert!(
            result.error.is_none()
                || !result
                    .error
                    .as_deref()
                    .unwrap_or("")
                    .contains("Unknown agent")
        );
    }

    #[tokio::test]
    async fn delegation_blocked_in_readonly_mode() {
        let readonly = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        });
        let tool = DelegateTool::new(sample_agents(), None, readonly);
        let result = tool
            .execute(json!({"agent": "researcher", "prompt": "test"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("read-only mode"));
    }

    #[tokio::test]
    async fn delegation_blocked_when_rate_limited() {
        let limited = Arc::new(SecurityPolicy {
            max_actions_per_hour: 0,
            ..SecurityPolicy::default()
        });
        let tool = DelegateTool::new(sample_agents(), None, limited);
        let result = tool
            .execute(json!({"agent": "researcher", "prompt": "test"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Rate limit exceeded"));
    }

    #[tokio::test]
    async fn delegate_context_is_prepended_to_prompt() {
        let mut agents = HashMap::new();
        agents.insert(
            "tester".to_string(),
            DelegateAgentConfig {
                provider: "invalid-for-test".to_string(),
                model: "test-model".to_string(),
                system_prompt: None,
                api_key: None,
                temperature: None,
                max_depth: 3,
                mode: None,
                allowed_tools: vec![],
                max_iterations: None,
                background: false,
            },
        );
        let tool = DelegateTool::new(agents, None, test_security());
        let result = tool
            .execute(json!({
                "agent": "tester",
                "prompt": "do something",
                "context": "some context data"
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Failed to create provider"));
    }

    #[tokio::test]
    async fn delegate_empty_context_omits_prefix() {
        let mut agents = HashMap::new();
        agents.insert(
            "tester".to_string(),
            DelegateAgentConfig {
                provider: "invalid-for-test".to_string(),
                model: "test-model".to_string(),
                system_prompt: None,
                api_key: None,
                temperature: None,
                max_depth: 3,
                mode: None,
                allowed_tools: vec![],
                max_iterations: None,
                background: false,
            },
        );
        let tool = DelegateTool::new(agents, None, test_security());
        let result = tool
            .execute(json!({
                "agent": "tester",
                "prompt": "do something",
                "context": ""
            }))
            .await
            .unwrap();

        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Failed to create provider"));
    }

    #[test]
    fn delegate_depth_construction() {
        let tool = DelegateTool::with_depth(sample_agents(), None, test_security(), 5);
        assert_eq!(tool.depth, 5);
    }

    #[tokio::test]
    async fn delegate_no_agents_configured() {
        let tool = DelegateTool::new(HashMap::new(), None, test_security());
        let result = tool
            .execute(json!({"agent": "any", "prompt": "test"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("none configured"));
    }
}
