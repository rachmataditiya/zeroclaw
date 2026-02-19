//! MCP management tool — list tools available from MCP servers.

use crate::mcp::manager::McpManager;
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use std::sync::Arc;

/// Tool that lists tools available from connected MCP servers.
pub struct McpServerToolsTool {
    manager: Arc<McpManager>,
}

impl McpServerToolsTool {
    pub fn new(manager: Arc<McpManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl Tool for McpServerToolsTool {
    fn name(&self) -> &str {
        "mcp_server_tools"
    }

    fn description(&self) -> &str {
        "List tools available from connected MCP servers. Optionally filter by server name."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "server": {
                    "type": "string",
                    "description": "Filter by server name (optional)"
                }
            }
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let server_filter = args.get("server").and_then(serde_json::Value::as_str);

        let tools = if let Some(server) = server_filter {
            match self.manager.server_tools(server).await {
                Some(server_tools) => server_tools
                    .into_iter()
                    .map(|t| {
                        serde_json::json!({
                            "server": server,
                            "name": t.name,
                            "description": t.description.unwrap_or_default(),
                        })
                    })
                    .collect::<Vec<_>>(),
                None => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("MCP server '{server}' not found or not connected")),
                    });
                }
            }
        } else {
            self.manager
                .all_tools()
                .await
                .into_iter()
                .map(|(server, t)| {
                    serde_json::json!({
                        "server": server,
                        "name": t.name,
                        "description": t.description.unwrap_or_default(),
                    })
                })
                .collect::<Vec<_>>()
        };

        let output = serde_json::to_string_pretty(&tools)?;

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
    async fn list_tools_empty() {
        let config = McpConfig::default();
        let manager = Arc::new(McpManager::new(config));
        let tool = McpServerToolsTool::new(manager);

        let result = tool.execute(serde_json::json!({})).await.unwrap();
        assert!(result.success);
        assert_eq!(result.output, "[]");
    }

    #[tokio::test]
    async fn list_tools_nonexistent_server() {
        let config = McpConfig::default();
        let manager = Arc::new(McpManager::new(config));
        let tool = McpServerToolsTool::new(manager);

        let result = tool
            .execute(serde_json::json!({"server": "nonexistent"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn tool_metadata() {
        let config = McpConfig::default();
        let manager = Arc::new(McpManager::new(config));
        let tool = McpServerToolsTool::new(manager);

        assert_eq!(tool.name(), "mcp_server_tools");
        assert!(!tool.description().is_empty());
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["server"].is_object());
    }
}
