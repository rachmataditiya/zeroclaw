use super::traits::{Tool, ToolResult};
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

/// List directory contents with optional recursive traversal and
/// glob filtering. Avoids the need for shell `ls`/`find` commands.
pub struct FileListTool {
    security: Arc<SecurityPolicy>,
}

impl FileListTool {
    pub fn new(security: Arc<SecurityPolicy>) -> Self {
        Self { security }
    }
}

#[async_trait]
impl Tool for FileListTool {
    fn name(&self) -> &str {
        "file_list"
    }

    fn description(&self) -> &str {
        "List directory contents. Returns file names, types, and sizes."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the directory within the workspace"
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Recurse into subdirectories (default: false)"
                },
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to filter entries (e.g. '*.rs', '*.toml')"
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum recursion depth (default: 3)"
                }
            },
            "required": ["path"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'path' parameter"))?;

        let recursive = args
            .get("recursive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let pattern = args.get("pattern").and_then(|v| v.as_str());

        #[allow(clippy::cast_possible_truncation)] // max_depth is small, never exceeds usize
        let max_depth = args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(3) as usize;

        if self.security.is_rate_limited() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: too many actions in the last hour".into()),
            });
        }

        if !self.security.is_path_allowed(path) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Path not allowed by security policy: {path}")),
            });
        }

        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: action budget exhausted".into()),
            });
        }

        let full_path = self.security.workspace_dir.join(path);

        let resolved_path = match tokio::fs::canonicalize(&full_path).await {
            Ok(p) => p,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to resolve directory path: {e}")),
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

        // Compile glob pattern if provided
        let glob_matcher = if let Some(pat) = pattern {
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

        // Perform directory listing (blocking I/O in spawn_blocking)
        let depth = if recursive { max_depth } else { 1 };
        let glob_clone = glob_matcher.clone();
        let resolved_clone = resolved_path.clone();

        let entries = tokio::task::spawn_blocking(move || {
            let mut results = Vec::new();
            let walker = walkdir::WalkDir::new(&resolved_clone)
                .max_depth(depth)
                .min_depth(1)
                .sort_by_file_name();

            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                let file_name = entry.file_name().to_string_lossy().to_string();

                // Apply glob filter
                if let Some(ref matcher) = glob_clone {
                    if !matcher.matches(&file_name) {
                        continue;
                    }
                }

                let file_type = if entry.file_type().is_dir() {
                    "directory"
                } else if entry.file_type().is_symlink() {
                    "symlink"
                } else {
                    "file"
                };

                let relative = entry
                    .path()
                    .strip_prefix(&resolved_clone)
                    .unwrap_or(entry.path());

                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);

                results.push(json!({
                    "name": relative.to_string_lossy(),
                    "type": file_type,
                    "size": size,
                }));
            }
            results
        })
        .await
        .map_err(|e| anyhow::anyhow!("Directory listing failed: {e}"))?;

        let output =
            serde_json::to_string_pretty(&entries).unwrap_or_else(|_| format!("{entries:?}"));

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

    fn test_security(workspace: std::path::PathBuf) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: AutonomyLevel::Supervised,
            workspace_dir: workspace,
            ..SecurityPolicy::default()
        })
    }

    #[test]
    fn file_list_name() {
        let tool = FileListTool::new(test_security(std::env::temp_dir()));
        assert_eq!(tool.name(), "file_list");
    }

    #[test]
    fn file_list_schema() {
        let tool = FileListTool::new(test_security(std::env::temp_dir()));
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["path"].is_object());
        assert!(schema["properties"]["recursive"].is_object());
        assert!(schema["properties"]["pattern"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("path")));
    }

    #[tokio::test]
    async fn file_list_directory() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_list");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("a.txt"), "aaa").await.unwrap();
        tokio::fs::write(dir.join("b.rs"), "bbb").await.unwrap();
        tokio::fs::create_dir_all(dir.join("sub")).await.unwrap();

        let tool = FileListTool::new(test_security(dir.clone()));
        let result = tool.execute(json!({"path": "."})).await.unwrap();
        assert!(result.success);
        let entries: Vec<serde_json::Value> = serde_json::from_str(&result.output).unwrap();
        let names: Vec<&str> = entries.iter().filter_map(|e| e["name"].as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.rs"));
        assert!(names.contains(&"sub"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_list_with_glob() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_list_glob");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("a.txt"), "aaa").await.unwrap();
        tokio::fs::write(dir.join("b.rs"), "bbb").await.unwrap();

        let tool = FileListTool::new(test_security(dir.clone()));
        let result = tool
            .execute(json!({"path": ".", "pattern": "*.rs"}))
            .await
            .unwrap();
        assert!(result.success);
        let entries: Vec<serde_json::Value> = serde_json::from_str(&result.output).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"].as_str().unwrap(), "b.rs");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_list_nonexistent() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_list_nope");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let tool = FileListTool::new(test_security(dir.clone()));
        let result = tool.execute(json!({"path": "nonexistent"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("Failed to resolve"));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn file_list_blocks_path_traversal() {
        let tool = FileListTool::new(test_security(std::env::temp_dir()));
        let result = tool.execute(json!({"path": "../../../etc"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("not allowed"));
    }

    #[tokio::test]
    async fn file_list_recursive() {
        let dir = std::env::temp_dir().join("zeroclaw_test_file_list_recursive");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(dir.join("sub")).await.unwrap();
        tokio::fs::write(dir.join("top.txt"), "top").await.unwrap();
        tokio::fs::write(dir.join("sub/deep.txt"), "deep")
            .await
            .unwrap();

        let tool = FileListTool::new(test_security(dir.clone()));

        // Non-recursive should not include sub/deep.txt
        let result = tool.execute(json!({"path": "."})).await.unwrap();
        let entries: Vec<serde_json::Value> = serde_json::from_str(&result.output).unwrap();
        let names: Vec<&str> = entries.iter().filter_map(|e| e["name"].as_str()).collect();
        assert!(!names.iter().any(|n| n.contains("deep")));

        // Recursive should include sub/deep.txt
        let result = tool
            .execute(json!({"path": ".", "recursive": true}))
            .await
            .unwrap();
        let entries: Vec<serde_json::Value> = serde_json::from_str(&result.output).unwrap();
        let names: Vec<&str> = entries.iter().filter_map(|e| e["name"].as_str()).collect();
        assert!(names.iter().any(|n| n.contains("deep")));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
