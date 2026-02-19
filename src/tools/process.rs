use super::traits::{Tool, ToolResult};
use crate::process::ProcessSessionManager;
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

/// Tool for managing background and interactive processes.
/// Supports spawning, polling, reading output, writing input,
/// and killing process sessions.
pub struct ProcessTool {
    security: Arc<SecurityPolicy>,
    manager: Arc<ProcessSessionManager>,
    workspace_dir: std::path::PathBuf,
}

impl ProcessTool {
    pub fn new(
        security: Arc<SecurityPolicy>,
        manager: Arc<ProcessSessionManager>,
        workspace_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            security,
            manager,
            workspace_dir,
        }
    }
}

#[async_trait]
impl Tool for ProcessTool {
    fn name(&self) -> &str {
        "process"
    }

    fn description(&self) -> &str {
        "Manage background processes. Actions: spawn, poll, log, write, submit, kill, list. \
         Use for long-running commands, interactive processes, or background tasks."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["spawn", "poll", "log", "write", "submit", "kill", "list"],
                    "description": "Action to perform"
                },
                "command": {
                    "type": "string",
                    "description": "Shell command to run (required for 'spawn')"
                },
                "session_id": {
                    "type": "string",
                    "description": "Session ID (required for poll/log/write/submit/kill)"
                },
                "input": {
                    "type": "string",
                    "description": "Input to send (for 'write' and 'submit')"
                },
                "pty": {
                    "type": "boolean",
                    "description": "Use PTY for interactive processes (default: false)"
                },
                "approved": {
                    "type": "boolean",
                    "description": "Set true to approve medium-risk commands in supervised mode",
                    "default": false
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Process timeout in seconds (optional)"
                },
                "offset": {
                    "type": "integer",
                    "description": "Byte offset for log reading (default: 0)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max bytes to read for log (optional)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'action' parameter"))?;

        match action {
            "spawn" => self.handle_spawn(&args),
            "poll" => self.handle_poll(&args),
            "log" => self.handle_log(&args),
            "write" => self.handle_write(&args, false),
            "submit" => self.handle_write(&args, true),
            "kill" => self.handle_kill(&args),
            "list" => self.handle_list(),
            _ => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Unknown action: {action}. Use: spawn, poll, log, write, submit, kill, list"
                )),
            }),
        }
    }
}

impl ProcessTool {
    fn handle_spawn(&self, args: &serde_json::Value) -> anyhow::Result<ToolResult> {
        let command = match args.get("command").and_then(|v| v.as_str()) {
            Some(c) if !c.trim().is_empty() => c,
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("'command' is required for spawn".into()),
                });
            }
        };

        if !self.security.can_act() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Action blocked: autonomy is read-only".into()),
            });
        }

        if self.security.is_rate_limited() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: too many actions in the last hour".into()),
            });
        }

        // Validate command against security policy
        let approved = args
            .get("approved")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let validation = self.security.validate_command_execution(command, approved);

        if let Err(msg) = validation {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Command blocked: {msg}")),
            });
        }

        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: action budget exhausted".into()),
            });
        }

        let use_pty = args.get("pty").and_then(|v| v.as_bool()).unwrap_or(false);

        let timeout_secs = args.get("timeout_secs").and_then(|v| v.as_u64());

        match self
            .manager
            .spawn(command, &self.workspace_dir, use_pty, timeout_secs)
        {
            Ok(session_id) => Ok(ToolResult {
                success: true,
                output: json!({
                    "session_id": session_id,
                    "command": command,
                    "pty": use_pty,
                })
                .to_string(),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            }),
        }
    }

    fn handle_poll(&self, args: &serde_json::Value) -> anyhow::Result<ToolResult> {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("'session_id' is required for poll".into()),
                });
            }
        };

        match self.manager.poll(session_id) {
            Ok(proc_status) => {
                let status_str = proc_status.to_string();
                Ok(ToolResult {
                    success: true,
                    output: json!({
                        "session_id": session_id,
                        "status": status_str,
                    })
                    .to_string(),
                    error: None,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            }),
        }
    }

    fn handle_log(&self, args: &serde_json::Value) -> anyhow::Result<ToolResult> {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("'session_id' is required for log".into()),
                });
            }
        };

        #[allow(clippy::cast_possible_truncation)]
        let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

        #[allow(clippy::cast_possible_truncation)]
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);

        match self.manager.read_log(session_id, offset, limit) {
            Ok((output, total_bytes)) => Ok(ToolResult {
                success: true,
                output: json!({
                    "session_id": session_id,
                    "output": output,
                    "total_bytes": total_bytes,
                    "offset": offset,
                })
                .to_string(),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            }),
        }
    }

    fn handle_write(
        &self,
        args: &serde_json::Value,
        append_newline: bool,
    ) -> anyhow::Result<ToolResult> {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("'session_id' is required for write/submit".into()),
                });
            }
        };

        let input = args.get("input").and_then(|v| v.as_str()).unwrap_or("");

        if !self.security.can_act() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Action blocked: autonomy is read-only".into()),
            });
        }

        let data = if append_newline {
            format!("{input}\n")
        } else {
            input.to_string()
        };

        match self.manager.write_input(session_id, data.as_bytes()) {
            Ok(()) => Ok(ToolResult {
                success: true,
                output: format!("Sent {} bytes to session {session_id}", data.len()),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            }),
        }
    }

    fn handle_kill(&self, args: &serde_json::Value) -> anyhow::Result<ToolResult> {
        let session_id = match args.get("session_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("'session_id' is required for kill".into()),
                });
            }
        };

        if !self.security.can_act() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Action blocked: autonomy is read-only".into()),
            });
        }

        match self.manager.kill(session_id) {
            Ok(()) => Ok(ToolResult {
                success: true,
                output: format!("Session {session_id} killed"),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e),
            }),
        }
    }

    fn handle_list(&self) -> anyhow::Result<ToolResult> {
        let sessions = self.manager.list();
        let output =
            serde_json::to_string_pretty(&sessions).unwrap_or_else(|_| format!("{sessions:?}"));

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
    use crate::security::{AutonomyLevel, SecurityPolicy};

    fn test_setup() -> (
        Arc<SecurityPolicy>,
        Arc<ProcessSessionManager>,
        std::path::PathBuf,
    ) {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Full,
            ..SecurityPolicy::default()
        });
        let manager = Arc::new(ProcessSessionManager::new());
        let workspace = std::env::temp_dir();
        (security, manager, workspace)
    }

    #[test]
    fn process_tool_name() {
        let (sec, mgr, ws) = test_setup();
        let tool = ProcessTool::new(sec, mgr, ws);
        assert_eq!(tool.name(), "process");
    }

    #[test]
    fn process_tool_schema() {
        let (sec, mgr, ws) = test_setup();
        let tool = ProcessTool::new(sec, mgr, ws);
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["action"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("action")));
    }

    #[tokio::test]
    async fn process_spawn_and_poll() {
        let (sec, mgr, ws) = test_setup();
        let tool = ProcessTool::new(sec, mgr, ws);

        let result = tool
            .execute(json!({"action": "spawn", "command": "echo hello"}))
            .await
            .unwrap();
        assert!(result.success, "spawn failed: {:?}", result.error);

        let output: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        let session_id = output["session_id"].as_str().unwrap();

        // Wait for process to finish
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let result = tool
            .execute(json!({"action": "poll", "session_id": session_id}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("exited(0)"));
    }

    #[tokio::test]
    async fn process_list() {
        let (sec, mgr, ws) = test_setup();
        let tool = ProcessTool::new(sec, mgr, ws);

        let result = tool.execute(json!({"action": "list"})).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn process_spawn_blocked_readonly() {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::ReadOnly,
            ..SecurityPolicy::default()
        });
        let mgr = Arc::new(ProcessSessionManager::new());
        let tool = ProcessTool::new(security, mgr, std::env::temp_dir());

        let result = tool
            .execute(json!({"action": "spawn", "command": "echo test"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("read-only"));
    }

    #[tokio::test]
    async fn process_unknown_action() {
        let (sec, mgr, ws) = test_setup();
        let tool = ProcessTool::new(sec, mgr, ws);

        let result = tool.execute(json!({"action": "invalid"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("Unknown action"));
    }

    #[tokio::test]
    async fn process_spawn_approved_medium_risk() {
        let security = Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            allowed_commands: vec!["curl".into()],
            workspace_dir: std::env::temp_dir(),
            ..SecurityPolicy::default()
        });
        let mgr = Arc::new(ProcessSessionManager::new());
        let tool = ProcessTool::new(security, mgr, std::env::temp_dir());

        // Without approved, curl (medium-risk) should be blocked
        let denied = tool
            .execute(json!({"action": "spawn", "command": "curl --version"}))
            .await
            .unwrap();
        assert!(!denied.success);
        assert!(denied
            .error
            .as_deref()
            .unwrap_or("")
            .contains("explicit approval"));

        // With approved=true, curl should succeed
        let allowed = tool
            .execute(json!({
                "action": "spawn",
                "command": "curl --version",
                "approved": true
            }))
            .await
            .unwrap();
        assert!(
            allowed.success,
            "spawn with approved=true failed: {:?}",
            allowed.error
        );
    }

    #[test]
    fn process_tool_schema_has_approved() {
        let (sec, mgr, ws) = test_setup();
        let tool = ProcessTool::new(sec, mgr, ws);
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["approved"].is_object());
    }
}
