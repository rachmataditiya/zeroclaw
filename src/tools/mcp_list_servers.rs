//! MCP management tool — list configured servers and their status.

use crate::mcp::manager::McpManager;
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use std::sync::Arc;

/// Tool that lists all configured MCP servers with their connection status.
pub struct McpListServersTool {
    manager: Arc<McpManager>,
}

impl McpListServersTool {
    pub fn new(manager: Arc<McpManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl Tool for McpListServersTool {
    fn name(&self) -> &str {
        "mcp_list_servers"
    }

    fn description(&self) -> &str {
        "List all configured MCP (Model Context Protocol) servers and their connection status"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {}
        })
    }

    async fn execute(&self, _args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let statuses = self.manager.server_statuses().await;

        let servers: Vec<serde_json::Value> = statuses
            .iter()
            .map(|(name, status)| {
                let transport = self
                    .manager
                    .config()
                    .servers
                    .get(name)
                    .map(|c| format!("{:?}", c.transport))
                    .unwrap_or_else(|| "unknown".to_string())
                    .to_lowercase();
                serde_json::json!({
                    "name": name,
                    "status": status.to_string(),
                    "transport": transport,
                })
            })
            .collect();

        let output = serde_json::to_string_pretty(&servers)?;

        Ok(ToolResult {
            success: true,
            output,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpConfig;

    #[tokio::test]
    async fn list_servers_empty() {
        let config = McpConfig::default();
        let manager = Arc::new(McpManager::new(config));
        let tool = McpListServersTool::new(manager);

        let result = tool.execute(serde_json::json!({})).await.unwrap();
        assert!(result.success);
        assert_eq!(result.output, "[]");
    }

    #[test]
    fn tool_metadata() {
        let config = McpConfig::default();
        let manager = Arc::new(McpManager::new(config));
        let tool = McpListServersTool::new(manager);

        assert_eq!(tool.name(), "mcp_list_servers");
        assert!(!tool.description().is_empty());
        assert!(tool.parameters_schema().is_object());
    }
}
