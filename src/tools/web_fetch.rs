use super::traits::{Tool, ToolResult};
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Default timeout for fetching URLs (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default maximum content length (characters).
const DEFAULT_MAX_LENGTH: usize = 50_000;

/// Fetch a URL and extract readable text content from HTML.
/// Unlike `http_request` which returns raw HTML, this tool
/// converts HTML to clean readable text.
pub struct WebFetchTool {
    security: Arc<SecurityPolicy>,
    allowed_domains: Vec<String>,
    timeout_secs: u64,
}

impl WebFetchTool {
    pub fn new(
        security: Arc<SecurityPolicy>,
        allowed_domains: Vec<String>,
        timeout_secs: u64,
    ) -> Self {
        Self {
            security,
            allowed_domains,
            timeout_secs,
        }
    }
}

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &str {
        "web_fetch"
    }

    fn description(&self) -> &str {
        "Fetch a URL and extract readable text content. Converts HTML to clean text."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch"
                },
                "max_length": {
                    "type": "integer",
                    "description": "Maximum content length in characters (default: 50000)"
                }
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let url = args
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing 'url' parameter"))?;

        #[allow(clippy::cast_possible_truncation)]
        let max_length = args
            .get("max_length")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(DEFAULT_MAX_LENGTH);

        if self.security.is_rate_limited() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: too many actions in the last hour".into()),
            });
        }

        // Validate URL
        let parsed_url = match url::Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Invalid URL: {e}")),
                });
            }
        };

        // Only allow http and https
        let scheme = parsed_url.scheme();
        if scheme != "http" && scheme != "https" {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("Unsupported URL scheme: {scheme}")),
            });
        }

        // Check domain allowlist if configured
        if !self.allowed_domains.is_empty() {
            let host = parsed_url.host_str().unwrap_or("");
            let allowed = self.allowed_domains.iter().any(|d| {
                if d.starts_with("*.") {
                    let suffix = &d[1..]; // ".example.com"
                    host.ends_with(suffix) || host == &d[2..]
                } else {
                    host == d
                }
            });
            if !allowed {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "Domain not allowed: {host}. Allowed: {}",
                        self.allowed_domains.join(", ")
                    )),
                });
            }
        }

        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: action budget exhausted".into()),
            });
        }

        // Fetch the URL
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .user_agent("ZeroClaw/1.0")
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {e}"))?;

        let response = match client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to fetch URL: {e}")),
                });
            }
        };

        let status = response.status();
        if !status.is_success() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("HTTP {status} for {url}")),
            });
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let body = match response.text().await {
            Ok(b) => b,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to read response body: {e}")),
                });
            }
        };

        // Convert HTML to text, or return raw text for non-HTML
        let text =
            if content_type.contains("text/html") || content_type.contains("application/xhtml") {
                html2text::from_read(body.as_bytes(), 80).unwrap_or_else(|_| body)
            } else {
                body
            };

        // Truncate to max_length
        let output = if text.len() > max_length {
            format!(
                "{}\n\n[Truncated: showing {max_length} of {} characters]",
                &text[..max_length],
                text.len()
            )
        } else {
            text
        };

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
    use crate::security::SecurityPolicy;

    fn test_security() -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy::default())
    }

    #[test]
    fn web_fetch_name() {
        let tool = WebFetchTool::new(test_security(), vec![], DEFAULT_TIMEOUT_SECS);
        assert_eq!(tool.name(), "web_fetch");
    }

    #[test]
    fn web_fetch_schema() {
        let tool = WebFetchTool::new(test_security(), vec![], DEFAULT_TIMEOUT_SECS);
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["url"].is_object());
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("url")));
    }

    #[tokio::test]
    async fn web_fetch_invalid_url() {
        let tool = WebFetchTool::new(test_security(), vec![], DEFAULT_TIMEOUT_SECS);
        let result = tool.execute(json!({"url": "not a url"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_ref().unwrap().contains("Invalid URL"));
    }

    #[tokio::test]
    async fn web_fetch_blocks_ftp() {
        let tool = WebFetchTool::new(test_security(), vec![], DEFAULT_TIMEOUT_SECS);
        let result = tool
            .execute(json!({"url": "ftp://example.com/file"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_ref()
            .unwrap()
            .contains("Unsupported URL scheme"));
    }

    #[tokio::test]
    async fn web_fetch_domain_allowlist() {
        let tool = WebFetchTool::new(
            test_security(),
            vec!["example.com".to_string()],
            DEFAULT_TIMEOUT_SECS,
        );
        let result = tool
            .execute(json!({"url": "https://evil.com/page"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_ref()
            .unwrap()
            .contains("Domain not allowed"));
    }

    #[tokio::test]
    async fn web_fetch_rate_limited() {
        let security = Arc::new(SecurityPolicy {
            max_actions_per_hour: 0,
            ..SecurityPolicy::default()
        });
        let tool = WebFetchTool::new(security, vec![], DEFAULT_TIMEOUT_SECS);
        let result = tool
            .execute(json!({"url": "https://example.com"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Rate limit exceeded"));
    }

    #[tokio::test]
    async fn web_fetch_wildcard_domain() {
        let tool = WebFetchTool::new(
            test_security(),
            vec!["*.example.com".to_string()],
            DEFAULT_TIMEOUT_SECS,
        );
        // sub.example.com should be allowed (but will fail on connect)
        let result = tool
            .execute(json!({"url": "https://sub.example.com/page"}))
            .await
            .unwrap();
        // Should not be blocked by domain check (will fail at HTTP level)
        assert!(
            !result.success
                && !result
                    .error
                    .as_deref()
                    .unwrap_or("")
                    .contains("Domain not allowed")
        );
    }
}
