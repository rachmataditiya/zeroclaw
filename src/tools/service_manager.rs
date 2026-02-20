use crate::security::SecurityPolicy;
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tokio::time::Duration;

const TIMEOUT_SECS: u64 = 60;
const MAX_OUTPUT_BYTES: usize = 1_048_576;

/// Service and container management tool.
///
/// Manages system services (systemd/launchd) and Docker containers.
pub struct ServiceManagerTool {
    security: Arc<SecurityPolicy>,
    allowed_actions: Vec<String>,
}

impl ServiceManagerTool {
    pub fn new(security: Arc<SecurityPolicy>, allowed_actions: Vec<String>) -> Self {
        Self {
            security,
            allowed_actions,
        }
    }

    fn is_action_allowed(&self, action: &str) -> bool {
        self.allowed_actions.is_empty()
            || self
                .allowed_actions
                .iter()
                .any(|a| a.eq_ignore_ascii_case(action))
    }
}

#[async_trait]
impl Tool for ServiceManagerTool {
    fn name(&self) -> &str {
        "service_manager"
    }

    fn description(&self) -> &str {
        "Manage system services (systemd/launchd) and Docker containers. Actions: status, start, stop, restart, logs, list for services; docker_run, docker_ps, docker_stop for containers."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["status", "start", "stop", "restart", "logs", "list",
                             "docker_run", "docker_ps", "docker_stop"],
                    "description": "Service action to perform"
                },
                "service": {
                    "type": "string",
                    "description": "Service name (for status/start/stop/restart/logs) or container name/ID (for docker_stop)"
                },
                "lines": {
                    "type": "integer",
                    "description": "Number of log lines to tail (default: 50)",
                    "default": 50,
                    "minimum": 1,
                    "maximum": 1000
                },
                "image": {
                    "type": "string",
                    "description": "Docker image for docker_run"
                },
                "ports": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Port mappings for docker_run (e.g. ['8080:80', '443:443'])"
                },
                "env": {
                    "type": "object",
                    "description": "Environment variables for docker_run (key: value pairs)"
                },
                "docker_args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Additional arguments for docker_run (e.g. ['--rm', '-d', '--name', 'myapp'])"
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

        // Security checks
        if self.security.is_rate_limited() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded".into()),
            });
        }

        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: action budget exhausted".into()),
            });
        }

        if !self.is_action_allowed(action) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Action '{action}' not allowed. Allowed: {:?}",
                    self.allowed_actions
                )),
            });
        }

        let service = args.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let lines = args.get("lines").and_then(|v| v.as_u64()).unwrap_or(50);

        match action {
            "status" | "start" | "stop" | "restart" => {
                if service.is_empty() {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!(
                            "'service' parameter required for '{action}' action"
                        )),
                    });
                }
                if !is_safe_service_name(service) {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Invalid service name: '{service}'")),
                    });
                }
                exec_service_action(action, service).await
            }
            "logs" => {
                if service.is_empty() {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some("'service' parameter required for 'logs' action".into()),
                    });
                }
                if !is_safe_service_name(service) {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Invalid service name: '{service}'")),
                    });
                }
                exec_service_logs(service, lines).await
            }
            "list" => exec_service_list().await,
            "docker_run" => {
                let image = args.get("image").and_then(|v| v.as_str()).unwrap_or("");
                if image.is_empty() {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some("'image' parameter required for docker_run".into()),
                    });
                }
                if !is_safe_docker_name(image) {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Invalid Docker image name: '{image}'")),
                    });
                }

                let ports: Vec<String> = args
                    .get("ports")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                let env: Vec<(String, String)> = args
                    .get("env")
                    .and_then(|v| v.as_object())
                    .map(|obj| {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_str().map(|val| (k.clone(), val.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();

                let docker_args: Vec<String> = args
                    .get("docker_args")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                exec_docker_run(image, &ports, &env, &docker_args).await
            }
            "docker_ps" => exec_docker_ps().await,
            "docker_stop" => {
                if service.is_empty() {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(
                            "'service' parameter required for docker_stop (container name/ID)"
                                .into(),
                        ),
                    });
                }
                if !is_safe_docker_name(service) {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Invalid container name: '{service}'")),
                    });
                }
                exec_docker_stop(service).await
            }
            other => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Unknown action '{other}'. Valid: status, start, stop, restart, logs, list, docker_run, docker_ps, docker_stop"
                )),
            }),
        }
    }
}

fn is_safe_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 256
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || "-_.@".contains(c))
}

fn is_safe_docker_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 512
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || "-_./:@".contains(c))
}

fn detect_init_system() -> &'static str {
    if cfg!(target_os = "macos") {
        "launchctl"
    } else {
        // Default to systemd on Linux
        "systemd"
    }
}

async fn exec_service_action(action: &str, service: &str) -> anyhow::Result<ToolResult> {
    let init = detect_init_system();

    let (program, args): (&str, Vec<String>) = match init {
        "systemd" => ("systemctl", vec![action.to_string(), service.to_string()]),
        "launchctl" => {
            let launchctl_action = match action {
                "start" => "load",
                "stop" => "unload",
                "restart" => "kickstart",
                "status" => "print",
                _ => action,
            };
            if action == "restart" {
                (
                    "launchctl",
                    vec![
                        "kickstart".to_string(),
                        "-k".to_string(),
                        format!("system/{service}"),
                    ],
                )
            } else if action == "status" {
                (
                    "launchctl",
                    vec!["print".to_string(), format!("system/{service}")],
                )
            } else {
                (
                    "launchctl",
                    vec![launchctl_action.to_string(), service.to_string()],
                )
            }
        }
        _ => {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Unsupported init system: {init}")),
            })
        }
    };

    run_service_command(program, &args).await
}

async fn exec_service_logs(service: &str, lines: u64) -> anyhow::Result<ToolResult> {
    let init = detect_init_system();

    let (program, args): (&str, Vec<String>) = match init {
        "systemd" => (
            "journalctl",
            vec![
                "-u".to_string(),
                service.to_string(),
                "-n".to_string(),
                lines.to_string(),
                "--no-pager".to_string(),
            ],
        ),
        "launchctl" => {
            // macOS: try to read from /var/log or use log show
            (
                "log",
                vec![
                    "show".to_string(),
                    "--predicate".to_string(),
                    format!("subsystem == '{service}'"),
                    "--last".to_string(),
                    format!("{lines}s"),
                    "--style".to_string(),
                    "compact".to_string(),
                ],
            )
        }
        _ => {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Unsupported init system for logs: {init}")),
            })
        }
    };

    run_service_command(program, &args).await
}

async fn exec_service_list() -> anyhow::Result<ToolResult> {
    let init = detect_init_system();

    let (program, args): (&str, Vec<String>) = match init {
        "systemd" => (
            "systemctl",
            vec![
                "list-units".to_string(),
                "--type=service".to_string(),
                "--state=running".to_string(),
                "--no-pager".to_string(),
            ],
        ),
        "launchctl" => ("launchctl", vec!["list".to_string()]),
        _ => {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Unsupported init system for list: {init}")),
            })
        }
    };

    run_service_command(program, &args).await
}

async fn exec_docker_run(
    image: &str,
    ports: &[String],
    env: &[(String, String)],
    extra_args: &[String],
) -> anyhow::Result<ToolResult> {
    let mut args: Vec<String> = vec!["run".to_string()];

    for port in ports {
        args.push("-p".to_string());
        args.push(port.clone());
    }

    for (key, value) in env {
        args.push("-e".to_string());
        args.push(format!("{key}={value}"));
    }

    args.extend(extra_args.iter().cloned());
    args.push(image.to_string());

    run_service_command("docker", &args).await
}

async fn exec_docker_ps() -> anyhow::Result<ToolResult> {
    run_service_command(
        "docker",
        &[
            "ps".to_string(),
            "--format".to_string(),
            "table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}".to_string(),
        ],
    )
    .await
}

async fn exec_docker_stop(container: &str) -> anyhow::Result<ToolResult> {
    run_service_command("docker", &["stop".to_string(), container.to_string()]).await
}

async fn run_service_command(program: &str, args: &[String]) -> anyhow::Result<ToolResult> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);

    let result = tokio::time::timeout(Duration::from_secs(TIMEOUT_SECS), cmd.output()).await;

    match result {
        Ok(Ok(output)) => {
            let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            if stdout.len() > MAX_OUTPUT_BYTES {
                stdout.truncate(stdout.floor_char_boundary(MAX_OUTPUT_BYTES));
                stdout.push_str("\n... [output truncated]");
            }

            let result_json = json!({
                "exit_code": output.status.code().unwrap_or(-1),
                "stdout": stdout,
                "stderr": if stderr.is_empty() { None } else { Some(stderr) },
            });

            Ok(ToolResult {
                success: output.status.success(),
                output: serde_json::to_string_pretty(&result_json)?,
                error: if output.status.success() {
                    None
                } else {
                    Some(format!(
                        "Command failed with exit code {}",
                        output.status.code().unwrap_or(-1)
                    ))
                },
            })
        }
        Ok(Err(e)) => Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(format!("Failed to execute '{program}': {e}")),
        }),
        Err(_) => Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(format!("Command timed out after {TIMEOUT_SECS}s")),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_manager_tool_metadata() {
        let tool = ServiceManagerTool::new(Arc::new(SecurityPolicy::default()), vec![]);
        assert_eq!(tool.name(), "service_manager");
        assert!(!tool.description().is_empty());
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["action"].is_object());
    }

    #[test]
    fn safe_service_names() {
        assert!(is_safe_service_name("nginx"));
        assert!(is_safe_service_name("postgresql.service"));
        assert!(is_safe_service_name("com.apple.finder"));
        assert!(is_safe_service_name("docker-compose_app"));

        assert!(!is_safe_service_name(""));
        assert!(!is_safe_service_name("svc; rm -rf /"));
        assert!(!is_safe_service_name("svc$(evil)"));
    }

    #[test]
    fn safe_docker_names() {
        assert!(is_safe_docker_name("nginx:latest"));
        assert!(is_safe_docker_name("registry.example.com/app:v1.2"));
        assert!(is_safe_docker_name("ghcr.io/org/image"));

        assert!(!is_safe_docker_name(""));
        assert!(!is_safe_docker_name("img; evil"));
        assert!(!is_safe_docker_name("img$(evil)"));
    }

    #[tokio::test]
    async fn service_manager_requires_service_for_status() {
        let tool = ServiceManagerTool::new(Arc::new(SecurityPolicy::default()), vec![]);
        let result = tool.execute(json!({"action": "status"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("service"));
    }

    #[tokio::test]
    async fn service_manager_rejects_unsafe_service_names() {
        let tool = ServiceManagerTool::new(Arc::new(SecurityPolicy::default()), vec![]);
        let result = tool
            .execute(json!({"action": "status", "service": "evil; rm -rf /"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Invalid service name"));
    }

    #[tokio::test]
    async fn service_manager_action_restriction() {
        let tool = ServiceManagerTool::new(
            Arc::new(SecurityPolicy::default()),
            vec!["status".to_string(), "list".to_string()],
        );
        let result = tool
            .execute(json!({"action": "stop", "service": "nginx"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("not allowed"));
    }

    #[tokio::test]
    async fn service_manager_docker_run_requires_image() {
        let tool = ServiceManagerTool::new(Arc::new(SecurityPolicy::default()), vec![]);
        let result = tool.execute(json!({"action": "docker_run"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("image"));
    }

    #[tokio::test]
    async fn service_manager_unknown_action() {
        let tool = ServiceManagerTool::new(Arc::new(SecurityPolicy::default()), vec![]);
        let result = tool.execute(json!({"action": "unknown"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Unknown action"));
    }
}
