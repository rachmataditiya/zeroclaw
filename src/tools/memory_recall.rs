use super::traits::{Tool, ToolResult};
use crate::memory::Memory;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::fmt::Write;
use std::sync::Arc;

/// Let the agent search its own memory
pub struct MemoryRecallTool {
    memory: Arc<dyn Memory>,
}

impl MemoryRecallTool {
    pub fn new(memory: Arc<dyn Memory>) -> Self {
        Self { memory }
    }
}

#[async_trait]
impl Tool for MemoryRecallTool {
    fn name(&self) -> &str {
        "memory_recall"
    }

    fn description(&self) -> &str {
        "Search long-term memory for relevant facts, preferences, or context. Returns scored results ranked by relevance."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Keywords or phrase to search for in memory"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results to return (default: 5)"
                },
                "since": {
                    "type": "string",
                    "description": "Filter: ISO date ('2026-02-01') or duration ('7d', '24h', '1h'). Only return memories created after this time."
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'query' parameter"))?;

        #[allow(clippy::cast_possible_truncation)]
        let limit = args
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .map_or(5, |v| v as usize);

        let since_cutoff = args
            .get("since")
            .and_then(|v| v.as_str())
            .map(parse_since)
            .transpose()?;

        // Over-fetch when filtering by time so we have enough after filtering
        let fetch_limit = if since_cutoff.is_some() {
            limit * 3
        } else {
            limit
        };

        match self.memory.recall(query, fetch_limit, None).await {
            Ok(entries) => {
                let filtered: Vec<_> = if let Some(cutoff) = since_cutoff {
                    entries
                        .into_iter()
                        .filter(|e| {
                            DateTime::parse_from_rfc3339(&e.timestamp)
                                .map(|ts| ts >= cutoff)
                                .unwrap_or(false)
                        })
                        .take(limit)
                        .collect()
                } else {
                    entries
                };

                if filtered.is_empty() {
                    return Ok(ToolResult {
                        success: true,
                        output: "No memories found matching that query.".into(),
                        error: None,
                    });
                }

                let mut output = format!("Found {} memories:\n", filtered.len());
                for entry in &filtered {
                    let score = entry
                        .score
                        .map_or_else(String::new, |s| format!(" [{s:.0}%]"));
                    let _ = writeln!(
                        output,
                        "- [{}] {}: {}{score}",
                        entry.category, entry.key, entry.content
                    );
                }
                Ok(ToolResult {
                    success: true,
                    output,
                    error: None,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Memory recall failed: {e}")),
            }),
        }
    }
}

/// Parse a `since` value as either an ISO date/datetime or a duration shorthand.
/// Duration formats: `7d` (days), `24h` (hours), `30m` (minutes).
fn parse_since(value: &str) -> anyhow::Result<DateTime<Utc>> {
    // Try ISO 8601 datetime first (e.g. "2026-02-01T00:00:00Z")
    if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try date-only (e.g. "2026-02-01") → midnight UTC
    if let Ok(date) = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        let dt = date
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid date: {value}"))?;
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
    }

    // Try duration shorthand: "7d", "24h", "30m"
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let (num_str, unit) = trimmed.split_at(trimmed.len() - 1);
        if let Ok(n) = num_str.parse::<i64>() {
            let duration = match unit {
                "d" => Duration::days(n),
                "h" => Duration::hours(n),
                "m" => Duration::minutes(n),
                _ => anyhow::bail!("Unknown since format: {value}. Use ISO date, or duration like '7d', '24h', '30m'."),
            };
            return Ok(Utc::now() - duration);
        }
    }

    anyhow::bail!(
        "Cannot parse since value: {value}. Use ISO date ('2026-02-01'), datetime, or duration ('7d', '24h', '30m')."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MemoryCategory, SqliteMemory};
    use tempfile::TempDir;

    fn seeded_mem() -> (TempDir, Arc<dyn Memory>) {
        let tmp = TempDir::new().unwrap();
        let mem = SqliteMemory::new(tmp.path()).unwrap();
        (tmp, Arc::new(mem))
    }

    #[tokio::test]
    async fn recall_empty() {
        let (_tmp, mem) = seeded_mem();
        let tool = MemoryRecallTool::new(mem);
        let result = tool.execute(json!({"query": "anything"})).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains("No memories found"));
    }

    #[tokio::test]
    async fn recall_finds_match() {
        let (_tmp, mem) = seeded_mem();
        mem.store("lang", "User prefers Rust", MemoryCategory::Core, None)
            .await
            .unwrap();
        mem.store("tz", "Timezone is EST", MemoryCategory::Core, None)
            .await
            .unwrap();

        let tool = MemoryRecallTool::new(mem);
        let result = tool.execute(json!({"query": "Rust"})).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains("Rust"));
        assert!(result.output.contains("Found 1"));
    }

    #[tokio::test]
    async fn recall_respects_limit() {
        let (_tmp, mem) = seeded_mem();
        for i in 0..10 {
            mem.store(
                &format!("k{i}"),
                &format!("Rust fact {i}"),
                MemoryCategory::Core,
                None,
            )
            .await
            .unwrap();
        }

        let tool = MemoryRecallTool::new(mem);
        let result = tool
            .execute(json!({"query": "Rust", "limit": 3}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("Found 3"));
    }

    #[tokio::test]
    async fn recall_missing_query() {
        let (_tmp, mem) = seeded_mem();
        let tool = MemoryRecallTool::new(mem);
        let result = tool.execute(json!({})).await;
        assert!(result.is_err());
    }

    #[test]
    fn name_and_schema() {
        let (_tmp, mem) = seeded_mem();
        let tool = MemoryRecallTool::new(mem);
        assert_eq!(tool.name(), "memory_recall");
        assert!(tool.parameters_schema()["properties"]["query"].is_object());
        assert!(tool.parameters_schema()["properties"]["since"].is_object());
    }

    #[test]
    fn parse_since_iso_date() {
        let dt = parse_since("2026-02-01").unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2026-02-01");
    }

    #[test]
    fn parse_since_duration_days() {
        let dt = parse_since("7d").unwrap();
        let expected = Utc::now() - Duration::days(7);
        // Allow 2-second tolerance for test timing
        assert!((dt - expected).num_seconds().abs() < 2);
    }

    #[test]
    fn parse_since_duration_hours() {
        let dt = parse_since("24h").unwrap();
        let expected = Utc::now() - Duration::hours(24);
        assert!((dt - expected).num_seconds().abs() < 2);
    }

    #[test]
    fn parse_since_invalid() {
        assert!(parse_since("garbage").is_err());
    }

    #[tokio::test]
    async fn recall_with_since_filters() {
        let (_tmp, mem) = seeded_mem();
        mem.store("old", "Old fact from ages ago", MemoryCategory::Core, None)
            .await
            .unwrap();
        mem.store("new", "New fact just now", MemoryCategory::Core, None)
            .await
            .unwrap();

        let tool = MemoryRecallTool::new(mem);

        // All entries were just created, so "since 1h ago" should return them
        let result = tool
            .execute(json!({"query": "fact", "since": "1h"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("Found"));

        // A future date should filter out everything
        let result = tool
            .execute(json!({"query": "fact", "since": "2099-01-01"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("No memories found"));
    }

    #[tokio::test]
    async fn recall_without_since_unchanged() {
        let (_tmp, mem) = seeded_mem();
        mem.store("lang", "User prefers Rust", MemoryCategory::Core, None)
            .await
            .unwrap();

        let tool = MemoryRecallTool::new(mem);
        let result = tool.execute(json!({"query": "Rust"})).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains("Rust"));
    }
}
