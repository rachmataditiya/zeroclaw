use super::traits::{Tool, ToolResult};
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

/// Text search across files in the workspace. Avoids the need for
/// shell `grep`/`rg` commands and the associated approval overhead.
pub struct FileSearchTool {
    security: Arc<SecurityPolicy>,
}

impl FileSearchTool {
    pub fn new(security: Arc<SecurityPolicy>) -> Self {
        Self { security }
    }
}

#[async_trait]
impl Tool for FileSearchTool {
    fn name(&self) -> &str {
        "file_search"
    }

    fn description(&self) -> &str {
        "Search for text patterns in workspace files. Returns matching lines with file paths and line numbers."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for"
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (relative, default: workspace root)"
                },
                "glob": {
                    "type": "string",
                    "description": "File pattern to filter (e.g. '*.rs', '*.py')"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of matches to return (default: 50)"
                }
            },
            "required": ["pattern"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let pattern_str = args
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'pattern' parameter"))?;

        let search_path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");

        let glob_pattern = args.get("glob").and_then(|v| v.as_str());

        #[allow(clippy::cast_possible_truncation)] // max_results is small, never exceeds usize
        let max_results = args
            .get("max_results")
            .and_then(|v| v.as_u64())
            .unwrap_or(50) as usize;

        if self.security.is_rate_limited() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: too many actions in the last hour".into()),
            });
        }

        if !self.security.is_path_allowed(search_path) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Path not allowed by security policy: {search_path}"
                )),
            });
        }

        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: action budget exhausted".into()),
            });
        }

        let full_path = self.security.workspace_dir.join(search_path);

        let resolved_path = match tokio::fs::canonicalize(&full_path).await {
            Ok(p) => p,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to resolve search path: {e}")),
                });
            }
        };

        if !self.security.is_resolved_path_allowed(&resolved_path) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Resolved path escapes workspace: {}",
                    resolved_path.display()
                )),
            });
        }

        // Compile regex
        let regex = match regex::Regex::new(pattern_str) {
            Ok(r) => r,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Invalid regex pattern: {e}")),
                });
            }
        };

        // Compile glob filter
        let glob_matcher = if let Some(pat) = glob_pattern {
            match glob::Pattern::new(pat) {
                Ok(m) => Some(m),
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("Invalid glob pattern: {e}")),
                    });
                }
            }
        } else {
            None
        };

        // Perform search in a blocking task
        let workspace_dir = self.security.workspace_dir.clone();
        let results = tokio::task::spawn_blocking(move || {
            let mut matches = Vec::new();
            let walker = walkdir::WalkDir::new(&resolved_path)
                .max_depth(10)
                .sort_by_file_name();

            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() {
                    continue;
                }

                // Apply glob filter on filename
                if let Some(ref matcher) = glob_matcher {
                    let file_name = entry.file_name().to_string_lossy();
                    if !matcher.matches(&file_name) {
                        continue;
                    }
                }

                // Skip binary files (quick heuristic: check first 512 bytes)
                let path = entry.path();
                let content = match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(_) => continue, // skip unreadable/binary files
                };

                let relative = path
                    .strip_prefix(&workspace_dir)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();

                for (line_num, line) in content.lines().enumerate() {
                    if regex.is_match(line) {
                        matches.push(json!({
                            "file": relative,
                            "line": line_num + 1,
                            "content": if line.len() > 500 {
                                format!("{}...", &line[..500])
                            } else {
                                line.to_string()
                            }
                        }));
                        if matches.len() >= max_results {
                            return matches;
                        }
                    }
                }

                if matches.len() >= max_results {
                    break;
                }
            }
            matches
        })
        .await
        .map_err(|e| anyhow::anyhow!("Search task failed: {e}"))?;

        let total = results.len();
        let output =
            serde_json::to_string_pretty(&results).unwrap_or_else(|_| format!("{results:?}"));

        Ok(ToolResult {
            success: true,
            output: format!("{total} match(es) found:\n{output}"),
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{AutonomyLevel, SecurityPolicy};

    fn test_security(workspace: std::path::PathBuf) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: workspace,
            ..SecurityPolicy::default()
        })
    }

    #[test]
    fn file_search_name() {
        let tool = FileSearchTool::new(test_security(std::env::temp_dir()));
        assert_eq!(tool.name(), "file_search");
    }

    #[test]
    fn file_search_schema() {
        let tool = FileSearchTool::new(test_security(std::env::temp_dir()));
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["pattern"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("pattern")));
    }

    #[tokio::test]
    async fn file_search_finds_pattern() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_search");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("code.rs"),
            "fn main() {\n    println!(\"hello\");\n}\n",
        )
        .await
        .unwrap();
        tokio::fs::write(dir.join("other.txt"), "no match here")
            .await
            .unwrap();

        let tool = FileSearchTool::new(test_security(dir.clone()));
        let result = tool.execute(json!({"pattern": "println"})).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains("1 match"));
        assert!(result.output.contains("code.rs"));
        assert!(result.output.contains("println"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_search_with_glob() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_search_glob");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("a.rs"), "fn hello() {}\n")
            .await
            .unwrap();
        tokio::fs::write(dir.join("b.txt"), "fn hello() {}\n")
            .await
            .unwrap();

        let tool = FileSearchTool::new(test_security(dir.clone()));

        // Search only .rs files
        let result = tool
            .execute(json!({"pattern": "hello", "glob": "*.rs"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("a.rs"));
        assert!(!result.output.contains("b.txt"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_search_invalid_regex() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_search_bad_regex");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let tool = FileSearchTool::new(test_security(dir.clone()));
        let result = tool.execute(json!({"pattern": "[invalid"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("Invalid regex"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_search_blocks_path_traversal() {
        let tool = FileSearchTool::new(test_security(std::env::temp_dir()));
        let result = tool
            .execute(json!({"pattern": "root", "path": "../../../etc"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("not allowed"));
    }

    #[tokio::test]
    async fn file_search_max_results() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_search_max");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        // Create a file with many matches
        let content = (0..100)
            .map(|i| format!("line_{i} match"))
            .collect::<Vec<_>>()
            .join("\n");
        tokio::fs::write(dir.join("many.txt"), &content)
            .await
            .unwrap();

        let tool = FileSearchTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"pattern": "match", "max_results": 5}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("5 match"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
