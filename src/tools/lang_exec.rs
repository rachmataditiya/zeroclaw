use crate::security::SecurityPolicy;
use crate::tools::traits::{Tool, ToolResult};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tokio::time::Duration;

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_TIMEOUT_SECS: u64 = 300;
const MAX_OUTPUT_BYTES: usize = 1_048_576; // 1 MB

/// Multi-language code execution tool.
///
/// Supports: python, bash, c, cpp, rust.
/// Compiles (when needed), executes, and returns stdout/stderr/exit_code.
pub struct LangExecTool {
    security: Arc<SecurityPolicy>,
    timeout_secs: u64,
    allowed_languages: Vec<String>,
}

impl LangExecTool {
    pub fn new(
        security: Arc<SecurityPolicy>,
        timeout_secs: u64,
        allowed_languages: Vec<String>,
    ) -> Self {
        Self {
            security,
            timeout_secs: timeout_secs.min(MAX_TIMEOUT_SECS),
            allowed_languages,
        }
    }

    fn is_language_allowed(&self, lang: &str) -> bool {
        self.allowed_languages.is_empty()
            || self
                .allowed_languages
                .iter()
                .any(|a| a.eq_ignore_ascii_case(lang))
    }
}

#[async_trait]
impl Tool for LangExecTool {
    fn name(&self) -> &str {
        "lang_exec"
    }

    fn description(&self) -> &str {
        "Execute code in multiple languages (python, bash, c, cpp, rust). Compiles if needed, runs with timeout, returns stdout/stderr/exit_code. Use 'check' action to compile/lint without executing."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["run", "check"],
                    "description": "run: compile+execute, check: compile/lint only"
                },
                "language": {
                    "type": "string",
                    "enum": ["python", "bash", "c", "cpp", "rust"],
                    "description": "Programming language"
                },
                "code": {
                    "type": "string",
                    "description": "Source code to execute"
                },
                "args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Command-line arguments passed to the program"
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default: 30, max: 300)",
                    "minimum": 1,
                    "maximum": 300
                }
            },
            "required": ["action", "language", "code"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'action' parameter"))?;

        let language = args
            .get("language")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'language' parameter"))?;

        let code = args
            .get("code")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'code' parameter"))?;

        let extra_args: Vec<String> = args
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let timeout = args
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(self.timeout_secs)
            .min(MAX_TIMEOUT_SECS);

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

        if !self.is_language_allowed(language) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Language '{language}' not allowed. Allowed: {:?}",
                    self.allowed_languages
                )),
            });
        }

        let check_only = action == "check";

        match language {
            "python" => exec_python(code, &extra_args, timeout, check_only).await,
            "bash" => exec_bash(code, &extra_args, timeout, check_only).await,
            "c" => exec_compiled(code, "c", &extra_args, timeout, check_only).await,
            "cpp" => exec_compiled(code, "cpp", &extra_args, timeout, check_only).await,
            "rust" => exec_compiled(code, "rust", &extra_args, timeout, check_only).await,
            other => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Unsupported language '{other}'. Valid: python, bash, c, cpp, rust"
                )),
            }),
        }
    }
}

fn truncate_output(s: &str) -> String {
    if s.len() > MAX_OUTPUT_BYTES {
        let boundary = s.floor_char_boundary(MAX_OUTPUT_BYTES);
        format!("{}\n... [output truncated]", &s[..boundary])
    } else {
        s.to_string()
    }
}

/// Create a unique temp file path based on a hash of the code.
fn temp_source_path(ext: &str) -> std::path::PathBuf {
    let id = uuid::Uuid::new_v4();
    std::env::temp_dir().join(format!("zeroclaw_exec_{id}.{ext}"))
}

fn temp_binary_path() -> std::path::PathBuf {
    let id = uuid::Uuid::new_v4();
    std::env::temp_dir().join(format!("zeroclaw_exec_{id}"))
}

async fn exec_python(
    code: &str,
    args: &[String],
    timeout: u64,
    check_only: bool,
) -> anyhow::Result<ToolResult> {
    let src = temp_source_path("py");
    tokio::fs::write(&src, code).await?;

    let result = if check_only {
        // Use python -m py_compile for syntax checking
        run_command(
            "python3",
            &["-m", "py_compile", &src.to_string_lossy()],
            timeout,
        )
        .await
    } else {
        let mut cmd_args: Vec<String> = vec![src.to_string_lossy().to_string()];
        cmd_args.extend_from_slice(args);
        let str_args: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
        run_command("python3", &str_args, timeout).await
    };

    let _ = tokio::fs::remove_file(&src).await;
    result
}

async fn exec_bash(
    code: &str,
    args: &[String],
    timeout: u64,
    check_only: bool,
) -> anyhow::Result<ToolResult> {
    let src = temp_source_path("sh");
    tokio::fs::write(&src, code).await?;

    let result = if check_only {
        // bash -n for syntax check
        run_command("bash", &["-n", &src.to_string_lossy()], timeout).await
    } else {
        let mut cmd_args: Vec<String> = vec![src.to_string_lossy().to_string()];
        cmd_args.extend_from_slice(args);
        let str_args: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
        run_command("bash", &str_args, timeout).await
    };

    let _ = tokio::fs::remove_file(&src).await;
    result
}

async fn exec_compiled(
    code: &str,
    lang: &str,
    args: &[String],
    timeout: u64,
    check_only: bool,
) -> anyhow::Result<ToolResult> {
    let (ext, compiler, compile_args) = match lang {
        "c" => ("c", "cc", vec!["-O2".to_string(), "-Wall".to_string()]),
        "cpp" => (
            "cpp",
            "c++",
            vec![
                "-std=c++20".to_string(),
                "-O2".to_string(),
                "-Wall".to_string(),
            ],
        ),
        "rust" => ("rs", "rustc", vec!["-O".to_string()]),
        _ => unreachable!(),
    };

    let src = temp_source_path(ext);
    let bin = temp_binary_path();
    tokio::fs::write(&src, code).await?;

    // Compile
    let mut full_compile_args: Vec<String> = compile_args;
    if check_only && lang != "rust" {
        // For C/C++: -fsyntax-only checks without producing binary
        full_compile_args.push("-fsyntax-only".to_string());
        full_compile_args.push(src.to_string_lossy().to_string());
    } else if check_only && lang == "rust" {
        // rustc --edition 2021 -Z parse-only is unstable; just compile without running
        full_compile_args.push("-o".to_string());
        full_compile_args.push(bin.to_string_lossy().to_string());
        full_compile_args.push(src.to_string_lossy().to_string());
    } else {
        full_compile_args.push("-o".to_string());
        full_compile_args.push(bin.to_string_lossy().to_string());
        full_compile_args.push(src.to_string_lossy().to_string());
    }

    let compile_str_args: Vec<&str> = full_compile_args.iter().map(|s| s.as_str()).collect();
    let compile_result = run_command(compiler, &compile_str_args, timeout).await?;

    // Clean up source
    let _ = tokio::fs::remove_file(&src).await;

    if !compile_result.success || check_only {
        let _ = tokio::fs::remove_file(&bin).await;
        if check_only && compile_result.success {
            return Ok(ToolResult {
                success: true,
                output: format!("{lang} code compiles successfully"),
                error: None,
            });
        }
        return Ok(compile_result);
    }

    // Execute
    let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let exec_result = run_command(&bin.to_string_lossy(), &str_args, timeout).await;

    // Clean up binary
    let _ = tokio::fs::remove_file(&bin).await;

    exec_result
}

async fn run_command(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> anyhow::Result<ToolResult> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);

    // Clear environment to prevent secret leakage (same pattern as ShellTool)
    cmd.env_clear();
    for var in &[
        "PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "USER", "SHELL", "TMPDIR",
    ] {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    let result = tokio::time::timeout(Duration::from_secs(timeout_secs), cmd.output()).await;

    match result {
        Ok(Ok(output)) => {
            let stdout = truncate_output(&String::from_utf8_lossy(&output.stdout));
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            let result_json = json!({
                "exit_code": output.status.code().unwrap_or(-1),
                "stdout": stdout,
                "stderr": if stderr.is_empty() { None } else { Some(truncate_output(&stderr)) },
            });

            Ok(ToolResult {
                success: output.status.success(),
                output: serde_json::to_string_pretty(&result_json)?,
                error: if output.status.success() {
                    None
                } else {
                    Some(format!(
                        "Process exited with code {}",
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
            error: Some(format!("Execution timed out after {timeout_secs}s")),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityPolicy;

    fn make_tool() -> LangExecTool {
        LangExecTool::new(
            Arc::new(SecurityPolicy::default()),
            DEFAULT_TIMEOUT_SECS,
            vec![],
        )
    }

    #[test]
    fn lang_exec_tool_metadata() {
        let tool = make_tool();
        assert_eq!(tool.name(), "lang_exec");
        assert!(!tool.description().is_empty());
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["language"].is_object());
        assert!(schema["properties"]["code"].is_object());
    }

    #[tokio::test]
    async fn lang_exec_python_hello() {
        let tool = make_tool();
        let result = tool
            .execute(json!({
                "action": "run",
                "language": "python",
                "code": "print('hello from python')"
            }))
            .await
            .unwrap();
        assert!(result.success, "error: {:?}", result.error);
        assert!(result.output.contains("hello from python"));
    }

    #[tokio::test]
    async fn lang_exec_bash_hello() {
        let tool = make_tool();
        let result = tool
            .execute(json!({
                "action": "run",
                "language": "bash",
                "code": "echo 'hello from bash'"
            }))
            .await
            .unwrap();
        assert!(result.success, "error: {:?}", result.error);
        assert!(result.output.contains("hello from bash"));
    }

    #[tokio::test]
    async fn lang_exec_python_check_syntax_error() {
        let tool = make_tool();
        let result = tool
            .execute(json!({
                "action": "check",
                "language": "python",
                "code": "def foo(\n  invalid syntax here"
            }))
            .await
            .unwrap();
        assert!(!result.success);
    }

    #[tokio::test]
    async fn lang_exec_bash_check_valid() {
        let tool = make_tool();
        let result = tool
            .execute(json!({
                "action": "check",
                "language": "bash",
                "code": "echo hello"
            }))
            .await
            .unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn lang_exec_unsupported_language() {
        let tool = make_tool();
        let result = tool
            .execute(json!({
                "action": "run",
                "language": "haskell",
                "code": "main = putStrLn \"hello\""
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Unsupported language"));
    }

    #[tokio::test]
    async fn lang_exec_language_restriction() {
        let tool = LangExecTool::new(
            Arc::new(SecurityPolicy::default()),
            DEFAULT_TIMEOUT_SECS,
            vec!["python".to_string()],
        );
        let result = tool
            .execute(json!({
                "action": "run",
                "language": "bash",
                "code": "echo hello"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("not allowed"));
    }

    #[tokio::test]
    async fn lang_exec_python_with_args() {
        let tool = make_tool();
        let result = tool
            .execute(json!({
                "action": "run",
                "language": "python",
                "code": "import sys; print(sys.argv[1])",
                "args": ["test_arg"]
            }))
            .await
            .unwrap();
        assert!(result.success, "error: {:?}", result.error);
        assert!(result.output.contains("test_arg"));
    }
}
