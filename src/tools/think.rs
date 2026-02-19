use super::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::json;

/// Zero-side-effect reasoning scratchpad. Allows the agent to perform
/// explicit chain-of-thought reasoning before taking actions. The thought
/// is returned verbatim with no side effects.
pub struct ThinkTool;

impl ThinkTool {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Tool for ThinkTool {
    fn name(&self) -> &str {
        "think"
    }

    fn description(&self) -> &str {
        "Record a reasoning step without side effects. Use to plan, analyze, or think through a problem before acting."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "thought": {
                    "type": "string",
                    "description": "Your reasoning, analysis, or plan"
                }
            },
            "required": ["thought"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let thought = args
            .get("thought")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'thought' parameter"))?;

        Ok(ToolResult {
            success: true,
            output: thought.to_string(),
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn think_name() {
        let tool = ThinkTool::new();
        assert_eq!(tool.name(), "think");
    }

    #[test]
    fn think_schema() {
        let tool = ThinkTool::new();
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["thought"].is_object());
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("thought")));
    }

    #[tokio::test]
    async fn think_returns_thought_verbatim() {
        let tool = ThinkTool::new();
        let result = tool
            .execute(json!({"thought": "I should check the file first"}))
            .await
            .unwrap();
        assert!(result.success);
        assert_eq!(result.output, "I should check the file first");
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn think_missing_param() {
        let tool = ThinkTool::new();
        let result = tool.execute(json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn think_empty_thought() {
        let tool = ThinkTool::new();
        let result = tool.execute(json!({"thought": ""})).await.unwrap();
        assert!(result.success);
        assert_eq!(result.output, "");
    }
}
