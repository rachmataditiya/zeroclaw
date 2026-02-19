//! MCP proxy tool — wraps an MCP server tool as a native ZeroClaw Tool.

use crate::mcp::manager::McpManager;
use crate::mcp::types::McpToolDefinition;
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use std::sync::Arc;

/// Proxy tool that delegates execution to an MCP server.
pub struct McpProxyTool {
    server_name: String,
    tool_def: McpToolDefinition,
    qualified_name: String,
    manager: Arc<McpManager>,
}

impl McpProxyTool {
    pub fn new(server_name: String, tool_def: McpToolDefinition, manager: Arc<McpManager>) -> Self {
        let qualified_name = format!(
            "mcp__{}__{}",
            sanitize_name(&server_name),
            sanitize_name(&tool_def.name)
        );
        Self {
            server_name,
            tool_def,
            qualified_name,
            manager,
        }
    }
}

/// Sanitize a name for use in tool naming: lowercase, replace non-alphanumeric with underscore.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .to_lowercase()
}

#[async_trait]
impl Tool for McpProxyTool {
    fn name(&self) -> &str {
        &self.qualified_name
    }

    fn description(&self) -> &str {
        self.tool_def
            .description
            .as_deref()
            .unwrap_or("MCP tool (no description)")
    }

    fn parameters_schema(&self) -> serde_json::Value {
        self.tool_def
            .input_schema
            .clone()
            .unwrap_or_else(|| serde_json::json!({"type": "object", "properties": {}}))
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        match self
            .manager
            .call_tool(&self.server_name, &self.tool_def.name, args)
            .await
        {
            Ok(result) => {
                let output: String = result
                    .content
                    .iter()
                    .map(|c| c.as_text())
                    .collect::<Vec<_>>()
                    .join("\n");

                Ok(ToolResult {
                    success: !result.is_error,
                    output,
                    error: if result.is_error {
                        Some("MCP tool returned error".to_string())
                    } else {
                        None
                    },
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("MCP call failed: {e}")),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_name_alphanumeric() {
        assert_eq!(sanitize_name("read_file"), "read_file");
        assert_eq!(sanitize_name("ReadFile"), "readfile");
    }

    #[test]
    fn sanitize_name_special_chars() {
        assert_eq!(sanitize_name("my-tool"), "my_tool");
        assert_eq!(sanitize_name("tool.name"), "tool_name");
        assert_eq!(sanitize_name("tool/name"), "tool_name");
    }

    #[test]
    fn qualified_name_format() {
        let tool_def = McpToolDefinition {
            name: "read_file".to_string(),
            description: Some("Read a file".to_string()),
            input_schema: None,
        };

        let config = crate::config::McpConfig::default();
        let manager = Arc::new(McpManager::new(config));
        let proxy = McpProxyTool::new("filesystem".to_string(), tool_def, manager);

        assert_eq!(proxy.name(), "mcp__filesystem__read_file");
    }

    #[test]
    fn description_fallback() {
        let tool_def = McpToolDefinition {
            name: "test".to_string(),
            description: None,
            input_schema: None,
        };

        let config = crate::config::McpConfig::default();
        let manager = Arc::new(McpManager::new(config));
        let proxy = McpProxyTool::new("server".to_string(), tool_def, manager);

        assert_eq!(proxy.description(), "MCP tool (no description)");
    }

    #[test]
    fn parameters_schema_fallback() {
        let tool_def = McpToolDefinition {
            name: "test".to_string(),
            description: None,
            input_schema: None,
        };

        let config = crate::config::McpConfig::default();
        let manager = Arc::new(McpManager::new(config));
        let proxy = McpProxyTool::new("server".to_string(), tool_def, manager);

        let schema = proxy.parameters_schema();
        assert_eq!(schema["type"], "object");
    }
}
