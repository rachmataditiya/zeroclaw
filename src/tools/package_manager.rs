use crate::security::SecurityPolicy;
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tokio::time::Duration;

const TIMEOUT_SECS: u64 = 120;
const MAX_OUTPUT_BYTES: usize = 1_048_576;

/// Cross-platform package management tool.
///
/// Auto-detects: brew (macOS), apt (Debian/Ubuntu), dnf (Fedora),
/// pacman (Arch), apk (Alpine).
pub struct PackageManagerTool {
    security: Arc<SecurityPolicy>,
    allowed_managers: Vec<String>,
}

impl PackageManagerTool {
    pub fn new(security: Arc<SecurityPolicy>, allowed_managers: Vec<String>) -> Self {
        Self {
            security,
            allowed_managers,
        }
    }
}

#[async_trait]
impl Tool for PackageManagerTool {
    fn name(&self) -> &str {
        "package_manager"
    }

    fn description(&self) -> &str {
        "Cross-platform package management: install, remove, search, list, and update packages. Auto-detects OS package manager (brew/apt/dnf/pacman/apk)."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["install", "remove", "search", "list", "update"],
                    "description": "install: install packages, remove: uninstall packages, search: find packages, list: list installed (optionally filtered), update: update index and/or upgrade packages"
                },
                "packages": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Package names (required for install/remove/search)"
                },
                "manager_override": {
                    "type": "string",
                    "enum": ["brew", "apt", "dnf", "pacman", "apk"],
                    "description": "Force a specific package manager instead of auto-detecting"
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

        let packages: Vec<String> = args
            .get("packages")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let manager_override = args
            .get("manager_override")
            .and_then(|v| v.as_str())
            .map(String::from);

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

        // Detect or override package manager
        let manager = match manager_override {
            Some(m) => m,
            None => detect_package_manager().await,
        };

        // Check if manager is allowed
        if !self.allowed_managers.is_empty()
            && !self
                .allowed_managers
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&manager))
        {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Package manager '{manager}' not allowed. Allowed: {:?}",
                    self.allowed_managers
                )),
            });
        }

        // Validate packages for install/remove/search
        if matches!(action, "install" | "remove" | "search") && packages.is_empty() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("'packages' parameter required for install/remove/search".into()),
            });
        }

        // Validate package names (prevent command injection)
        for pkg in &packages {
            if !is_safe_package_name(pkg) {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "Invalid package name: '{pkg}'. Only alphanumeric, hyphens, underscores, dots, forward slashes, and @ are allowed."
                    )),
                });
            }
        }

        let (program, cmd_args) = build_command(&manager, action, &packages);

        if program.is_empty() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "No package manager detected or unsupported manager '{manager}'"
                )),
            });
        }

        run_package_command(&program, &cmd_args).await
    }
}

/// Validate package name to prevent command injection.
fn is_safe_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 256
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || "-_./@:+".contains(c))
}

async fn detect_package_manager() -> String {
    // Check in order of platform preference
    let candidates = if cfg!(target_os = "macos") {
        vec!["brew"]
    } else {
        vec!["apt", "dnf", "pacman", "apk"]
    };

    for candidate in candidates {
        let which = if cfg!(target_os = "windows") {
            "where"
        } else {
            "which"
        };
        if let Ok(output) = tokio::process::Command::new(which)
            .arg(candidate)
            .output()
            .await
        {
            if output.status.success() {
                return candidate.to_string();
            }
        }
    }

    "unknown".to_string()
}

fn build_command(manager: &str, action: &str, packages: &[String]) -> (String, Vec<String>) {
    let pkg_strs: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();

    match (manager, action) {
        // brew
        ("brew", "install") => (
            "brew".into(),
            [&["install"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("brew", "remove") => (
            "brew".into(),
            [&["uninstall"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("brew", "search") => (
            "brew".into(),
            [&["search"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("brew", "list") => ("brew".into(), vec!["list".into()]),
        ("brew", "update") => ("brew".into(), vec!["update".into()]),

        // apt
        ("apt", "install") => (
            "apt-get".into(),
            [&["install", "-y"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("apt", "remove") => (
            "apt-get".into(),
            [&["remove", "-y"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("apt", "search") => (
            "apt-cache".into(),
            [&["search"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("apt", "list") => ("dpkg".into(), vec!["--list".into()]),
        ("apt", "update") => ("apt-get".into(), vec!["update".into()]),

        // dnf
        ("dnf", "install") => (
            "dnf".into(),
            [&["install", "-y"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("dnf", "remove") => (
            "dnf".into(),
            [&["remove", "-y"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("dnf", "search") => (
            "dnf".into(),
            [&["search"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("dnf", "list") => ("dnf".into(), vec!["list".into(), "installed".into()]),
        ("dnf", "update") => ("dnf".into(), vec!["upgrade".into(), "-y".into()]),

        // pacman
        ("pacman", "install") => (
            "pacman".into(),
            [&["-S", "--noconfirm"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("pacman", "remove") => (
            "pacman".into(),
            [&["-R", "--noconfirm"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("pacman", "search") => (
            "pacman".into(),
            [&["-Ss"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("pacman", "list") => ("pacman".into(), vec!["-Q".into()]),
        ("pacman", "update") => ("pacman".into(), vec!["-Syu".into(), "--noconfirm".into()]),

        // apk
        ("apk", "install") => (
            "apk".into(),
            [&["add"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("apk", "remove") => (
            "apk".into(),
            [&["del"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("apk", "search") => (
            "apk".into(),
            [&["search"][..], &pkg_strs]
                .concat()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ("apk", "list") => ("apk".into(), vec!["list".into(), "--installed".into()]),
        ("apk", "update") => ("apk".into(), vec!["upgrade".into()]),

        _ => (String::new(), vec![]),
    }
}

async fn run_package_command(program: &str, args: &[String]) -> anyhow::Result<ToolResult> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);

    // Preserve environment for package managers (they need PATH, HOME, etc.)
    // But clear known secret variables
    for var in &[
        "API_KEY",
        "SECRET_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
    ] {
        cmd.env_remove(var);
    }

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
    fn package_manager_tool_metadata() {
        let tool = PackageManagerTool::new(Arc::new(SecurityPolicy::default()), vec![]);
        assert_eq!(tool.name(), "package_manager");
        assert!(!tool.description().is_empty());
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["action"].is_object());
        assert!(schema["properties"]["packages"].is_object());
    }

    #[test]
    fn safe_package_names() {
        assert!(is_safe_package_name("git"));
        assert!(is_safe_package_name("libssl-dev"));
        assert!(is_safe_package_name("python3.11"));
        assert!(is_safe_package_name("@types/node"));
        assert!(is_safe_package_name("gcc-arm-none-eabi"));

        assert!(!is_safe_package_name(""));
        assert!(!is_safe_package_name("pkg; rm -rf /"));
        assert!(!is_safe_package_name("pkg$(evil)"));
        assert!(!is_safe_package_name("pkg`evil`"));
        assert!(!is_safe_package_name("pkg && evil"));
    }

    #[test]
    fn build_brew_commands() {
        let (prog, args) = build_command("brew", "install", &["jq".into(), "ripgrep".into()]);
        assert_eq!(prog, "brew");
        assert_eq!(args, vec!["install", "jq", "ripgrep"]);
    }

    #[test]
    fn build_apt_commands() {
        let (prog, args) = build_command("apt", "install", &["curl".into()]);
        assert_eq!(prog, "apt-get");
        assert_eq!(args, vec!["install", "-y", "curl"]);
    }

    #[test]
    fn build_unknown_manager() {
        let (prog, _) = build_command("unknown", "install", &["pkg".into()]);
        assert!(prog.is_empty());
    }

    #[tokio::test]
    async fn package_manager_requires_packages_for_install() {
        let tool = PackageManagerTool::new(Arc::new(SecurityPolicy::default()), vec![]);
        let result = tool.execute(json!({"action": "install"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("packages"));
    }

    #[tokio::test]
    async fn package_manager_rejects_unsafe_names() {
        let tool = PackageManagerTool::new(Arc::new(SecurityPolicy::default()), vec![]);
        let result = tool
            .execute(json!({
                "action": "install",
                "packages": ["valid-pkg", "evil; rm -rf /"]
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Invalid package name"));
    }

    #[tokio::test]
    async fn package_manager_manager_restriction() {
        let tool = PackageManagerTool::new(
            Arc::new(SecurityPolicy::default()),
            vec!["brew".to_string()],
        );
        let result = tool
            .execute(json!({
                "action": "list",
                "manager_override": "apt"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("not allowed"));
    }
}
