use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;

/// Read-only tool for querying host system state.
///
/// Actions: overview, processes, network, disk, env, installed.
pub struct SystemInfoTool;

impl SystemInfoTool {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Tool for SystemInfoTool {
    fn name(&self) -> &str {
        "system_info"
    }

    fn description(&self) -> &str {
        "Query host system information: OS, CPU, memory, disk, processes, network, environment variables, and installed commands. Read-only and safe."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["overview", "processes", "network", "disk", "env", "installed"],
                    "description": "What to query: overview (OS/CPU/memory/hostname), processes (top N by CPU/memory), network (interfaces/connections), disk (filesystem usage), env (environment variables with secrets redacted), installed (check if commands exist in PATH)"
                },
                "filter": {
                    "type": "string",
                    "description": "Filter string: for 'env' filters variable names, for 'installed' is a comma-separated list of commands to check, for 'processes' filters by name"
                },
                "top_n": {
                    "type": "integer",
                    "description": "Number of results for 'processes' action (default: 10)",
                    "default": 10,
                    "minimum": 1,
                    "maximum": 100
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

        let filter = args.get("filter").and_then(|v| v.as_str()).unwrap_or("");
        let top_n: usize = args
            .get("top_n")
            .and_then(|v| v.as_u64())
            .unwrap_or(10)
            .try_into()
            .unwrap_or(usize::MAX);

        match action {
            "overview" => execute_overview(),
            "processes" => execute_processes(filter, top_n),
            "network" => execute_network().await,
            "disk" => execute_disk(),
            "env" => execute_env(filter),
            "installed" => execute_installed(filter).await,
            other => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Unknown action '{other}'. Valid: overview, processes, network, disk, env, installed"
                )),
            }),
        }
    }
}

fn execute_overview() -> anyhow::Result<ToolResult> {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all();

    let info = json!({
        "os": System::name().unwrap_or_else(|| "unknown".into()),
        "os_version": System::os_version().unwrap_or_else(|| "unknown".into()),
        "kernel_version": System::kernel_version().unwrap_or_else(|| "unknown".into()),
        "hostname": System::host_name().unwrap_or_else(|| "unknown".into()),
        "arch": std::env::consts::ARCH,
        "cpu_count": sys.cpus().len(),
        "cpu_brand": sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default(),
        "total_memory_mb": sys.total_memory() / 1024 / 1024,
        "used_memory_mb": sys.used_memory() / 1024 / 1024,
        "available_memory_mb": (sys.total_memory() - sys.used_memory()) / 1024 / 1024,
        "total_swap_mb": sys.total_swap() / 1024 / 1024,
        "used_swap_mb": sys.used_swap() / 1024 / 1024,
        "uptime_secs": System::uptime(),
    });

    Ok(ToolResult {
        success: true,
        output: serde_json::to_string_pretty(&info)?,
        error: None,
    })
}

fn execute_processes(filter: &str, top_n: usize) -> anyhow::Result<ToolResult> {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all();

    let mut procs: Vec<_> = sys
        .processes()
        .values()
        .filter(|p| {
            if filter.is_empty() {
                true
            } else {
                p.name()
                    .to_string_lossy()
                    .to_lowercase()
                    .contains(&filter.to_lowercase())
            }
        })
        .map(|p| {
            json!({
                "pid": p.pid().as_u32(),
                "name": p.name().to_string_lossy(),
                "cpu_usage": format!("{:.1}%", p.cpu_usage()),
                "memory_mb": p.memory() / 1024 / 1024,
                "status": format!("{:?}", p.status()),
            })
        })
        .collect();

    // Sort by memory descending (proxy for "heaviest")
    procs.sort_by(|a, b| {
        let mem_a = a["memory_mb"].as_u64().unwrap_or(0);
        let mem_b = b["memory_mb"].as_u64().unwrap_or(0);
        mem_b.cmp(&mem_a)
    });
    procs.truncate(top_n);

    let result = json!({
        "count": procs.len(),
        "processes": procs,
    });

    Ok(ToolResult {
        success: true,
        output: serde_json::to_string_pretty(&result)?,
        error: None,
    })
}

async fn execute_network() -> anyhow::Result<ToolResult> {
    // Use system commands for network info (sysinfo crate network support varies)
    let output = if cfg!(target_os = "macos") {
        tokio::process::Command::new("ifconfig").output().await.ok()
    } else {
        tokio::process::Command::new("ip")
            .args(["addr", "show"])
            .output()
            .await
            .ok()
    };

    let interfaces = match output {
        Some(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
        _ => "Could not retrieve network interfaces".to_string(),
    };

    // Get listening ports
    let listeners = if cfg!(target_os = "macos") {
        tokio::process::Command::new("lsof")
            .args(["-iTCP", "-sTCP:LISTEN", "-P", "-n"])
            .output()
            .await
            .ok()
    } else {
        tokio::process::Command::new("ss")
            .args(["-tlnp"])
            .output()
            .await
            .ok()
    };

    let listening = match listeners {
        Some(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
        _ => "Could not retrieve listening ports".to_string(),
    };

    let result = json!({
        "interfaces": interfaces,
        "listening_ports": listening,
    });

    Ok(ToolResult {
        success: true,
        output: serde_json::to_string_pretty(&result)?,
        error: None,
    })
}

fn execute_disk() -> anyhow::Result<ToolResult> {
    use sysinfo::Disks;

    let disks = Disks::new_with_refreshed_list();

    let disk_info: Vec<_> = disks
        .iter()
        .map(|d: &sysinfo::Disk| {
            json!({
                "name": d.name().to_string_lossy(),
                "mount_point": d.mount_point().to_string_lossy(),
                "file_system": String::from_utf8_lossy(d.file_system().as_encoded_bytes()),
                "total_gb": format!("{:.1}", d.total_space() as f64 / 1024.0 / 1024.0 / 1024.0),
                "available_gb": format!("{:.1}", d.available_space() as f64 / 1024.0 / 1024.0 / 1024.0),
                "used_gb": format!("{:.1}", (d.total_space() - d.available_space()) as f64 / 1024.0 / 1024.0 / 1024.0),
                "usage_percent": if d.total_space() > 0 {
                    format!("{:.1}%", ((d.total_space() - d.available_space()) as f64 / d.total_space() as f64) * 100.0)
                } else {
                    "N/A".to_string()
                },
                "removable": d.is_removable(),
            })
        })
        .collect();

    let result = json!({
        "count": disk_info.len(),
        "disks": disk_info,
    });

    Ok(ToolResult {
        success: true,
        output: serde_json::to_string_pretty(&result)?,
        error: None,
    })
}

/// Secret-like environment variable patterns to redact.
const SECRET_PATTERNS: &[&str] = &[
    "KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASS",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE",
];

fn is_secret_var(name: &str) -> bool {
    let upper = name.to_uppercase();
    SECRET_PATTERNS.iter().any(|p| upper.contains(p))
}

fn execute_env(filter: &str) -> anyhow::Result<ToolResult> {
    let mut vars: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| {
            if filter.is_empty() {
                true
            } else {
                k.to_lowercase().contains(&filter.to_lowercase())
            }
        })
        .map(|(k, v)| {
            if is_secret_var(&k) {
                (k, "[REDACTED]".to_string())
            } else {
                (k, v)
            }
        })
        .collect();

    // Always redact PATH-like vars that could leak info about other secrets
    // PATH itself is fine to show
    for key in ["LS_COLORS", "LSCOLORS"] {
        if let Some(v) = vars.get_mut(key) {
            if v.len() > 200 {
                *v = format!("{}... [truncated]", &v[..200]);
            }
        }
    }

    let result = json!({
        "count": vars.len(),
        "variables": vars,
    });

    Ok(ToolResult {
        success: true,
        output: serde_json::to_string_pretty(&result)?,
        error: None,
    })
}

async fn execute_installed(filter: &str) -> anyhow::Result<ToolResult> {
    if filter.is_empty() {
        return Ok(ToolResult {
            success: false,
            output: String::new(),
            error: Some(
                "Please provide a comma-separated list of commands to check in the 'filter' parameter"
                    .into(),
            ),
        });
    }

    let commands: Vec<&str> = filter.split(',').map(|s| s.trim()).collect();
    let mut results: HashMap<String, serde_json::Value> = HashMap::new();

    for cmd in &commands {
        if cmd.is_empty() {
            continue;
        }

        let which_cmd = if cfg!(target_os = "windows") {
            "where"
        } else {
            "which"
        };

        let output = tokio::process::Command::new(which_cmd)
            .arg(cmd)
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                results.insert(cmd.to_string(), json!({ "installed": true, "path": path }));
            }
            _ => {
                results.insert(cmd.to_string(), json!({ "installed": false }));
            }
        }
    }

    let result = json!({
        "checked": results.len(),
        "commands": results,
    });

    Ok(ToolResult {
        success: true,
        output: serde_json::to_string_pretty(&result)?,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_info_tool_metadata() {
        let tool = SystemInfoTool::new();
        assert_eq!(tool.name(), "system_info");
        assert!(!tool.description().is_empty());
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["action"].is_object());
    }

    #[tokio::test]
    async fn system_info_overview() {
        let tool = SystemInfoTool::new();
        let result = tool.execute(json!({"action": "overview"})).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains("os"));
        assert!(result.output.contains("total_memory_mb"));
    }

    #[tokio::test]
    async fn system_info_processes() {
        let tool = SystemInfoTool::new();
        let result = tool
            .execute(json!({"action": "processes", "top_n": 3}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("processes"));
    }

    #[tokio::test]
    async fn system_info_disk() {
        let tool = SystemInfoTool::new();
        let result = tool.execute(json!({"action": "disk"})).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains("disks"));
    }

    #[tokio::test]
    async fn system_info_env() {
        let tool = SystemInfoTool::new();
        let result = tool
            .execute(json!({"action": "env", "filter": "PATH"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("PATH"));
    }

    #[tokio::test]
    async fn system_info_env_redacts_secrets() {
        // Set a test secret
        std::env::set_var("ZEROCLAW_TEST_SECRET_KEY", "super-secret-value");
        let tool = SystemInfoTool::new();
        let result = tool
            .execute(json!({"action": "env", "filter": "ZEROCLAW_TEST_SECRET"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("[REDACTED]"));
        assert!(!result.output.contains("super-secret-value"));
        std::env::remove_var("ZEROCLAW_TEST_SECRET_KEY");
    }

    #[tokio::test]
    async fn system_info_installed() {
        let tool = SystemInfoTool::new();
        let result = tool
            .execute(json!({"action": "installed", "filter": "ls,nonexistent_cmd_xyz"}))
            .await
            .unwrap();
        assert!(result.success);
        let parsed: serde_json::Value = serde_json::from_str(&result.output).unwrap();
        assert!(parsed["commands"]["ls"]["installed"].as_bool().unwrap());
        assert!(!parsed["commands"]["nonexistent_cmd_xyz"]["installed"]
            .as_bool()
            .unwrap());
    }

    #[tokio::test]
    async fn system_info_installed_requires_filter() {
        let tool = SystemInfoTool::new();
        let result = tool.execute(json!({"action": "installed"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn system_info_unknown_action() {
        let tool = SystemInfoTool::new();
        let result = tool.execute(json!({"action": "unknown"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Unknown action"));
    }
}
