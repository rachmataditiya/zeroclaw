use super::traits::{Tool, ToolResult};
use crate::security::content_wrapper::{self, ContentSource};
use crate::security::SecurityPolicy;
use crate::util::cache::TtlCache;
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Default timeout for fetching URLs (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default maximum content length (characters).
const DEFAULT_MAX_LENGTH: usize = 50_000;

/// Default cache TTL in minutes.
const DEFAULT_CACHE_TTL_MINUTES: u32 = 15;

/// Maximum cache entries for web fetch results.
const MAX_CACHE_ENTRIES: usize = 100;

/// Fetch a URL and extract readable text content from HTML.
/// Unlike `http_request` which returns raw HTML, this tool
/// converts HTML to clean readable text.
///
/// Features:
/// - SSRF protection (blocks private/local hosts)
/// - Domain allowlist support (wildcard patterns)
/// - In-memory LRU cache with TTL
/// - Injection defense wrapping
/// - Proxy support via runtime config
/// - Improved HTML extraction (strips script/style/noscript)
pub struct WebFetchTool {
    security: Arc<SecurityPolicy>,
    allowed_domains: Vec<String>,
    timeout_secs: u64,
    cache: Arc<TtlCache<String>>,
}

impl WebFetchTool {
    pub fn new(
        security: Arc<SecurityPolicy>,
        allowed_domains: Vec<String>,
        timeout_secs: u64,
    ) -> Self {
        Self::with_cache_ttl(
            security,
            allowed_domains,
            timeout_secs,
            DEFAULT_CACHE_TTL_MINUTES,
        )
    }

    pub fn with_cache_ttl(
        security: Arc<SecurityPolicy>,
        allowed_domains: Vec<String>,
        timeout_secs: u64,
        cache_ttl_minutes: u32,
    ) -> Self {
        let ttl = Duration::from_secs(u64::from(cache_ttl_minutes) * 60);
        Self {
            security,
            allowed_domains,
            timeout_secs,
            cache: Arc::new(TtlCache::new(MAX_CACHE_ENTRIES, ttl)),
        }
    }
}

/// Strip `<script>`, `<style>`, and `<noscript>` tags and their contents from HTML.
fn strip_non_content_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut remaining = html;

    while !remaining.is_empty() {
        // Find the next tag to strip
        let next_tag = ["<script", "<style", "<noscript"]
            .iter()
            .filter_map(|tag| remaining.to_lowercase().find(tag).map(|pos| (pos, *tag)))
            .min_by_key(|(pos, _)| *pos);

        match next_tag {
            Some((pos, tag)) => {
                // Add content before the tag
                result.push_str(&remaining[..pos]);

                // Find the closing tag
                let tag_name = &tag[1..]; // strip '<'
                let close_tag = format!("</{tag_name}");
                let after_open = &remaining[pos..];

                if let Some(close_pos) = after_open.to_lowercase().find(&close_tag) {
                    // Find the end of the closing tag
                    let after_close = &after_open[close_pos..];
                    if let Some(gt_pos) = after_close.find('>') {
                        remaining = &after_close[gt_pos + 1..];
                    } else {
                        remaining = &after_close[close_pos + close_tag.len()..];
                    }
                } else {
                    // No closing tag found — skip to end of opening tag
                    if let Some(gt_pos) = after_open.find('>') {
                        remaining = &after_open[gt_pos + 1..];
                    } else {
                        remaining = "";
                    }
                }
            }
            None => {
                result.push_str(remaining);
                remaining = "";
            }
        }
    }

    result
}

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &str {
        "web_fetch"
    }

    fn description(&self) -> &str {
        "Fetch a URL and extract readable text content. Converts HTML to clean text. \
        Supports extract_mode: \"markdown\" (default) or \"text\" for plain text output."
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
                },
                "extract_mode": {
                    "type": "string",
                    "description": "Extraction mode: \"markdown\" (default) or \"text\" for plain text",
                    "enum": ["markdown", "text"],
                    "default": "markdown"
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

        let extract_mode = args
            .get("extract_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("markdown");

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

        // SSRF protection — block private/local hosts
        if let Err(e) = crate::security::ssrf::validate_url_ssrf(&parsed_url) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e.to_string()),
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

        // Check cache before making the request
        let cache_key = format!("fetch:{url}:{extract_mode}:{max_length}");
        if let Some(cached) = self.cache.get(&cache_key) {
            tracing::debug!(url, "web_fetch cache hit");
            return Ok(ToolResult {
                success: true,
                output: cached,
                error: None,
            });
        }

        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded: action budget exhausted".into()),
            });
        }

        // Fetch URL using libcurl (system TLS)
        let resp = match super::curl_client::curl_get(
            url,
            &[],
            Duration::from_secs(self.timeout_secs),
            Some("ZeroClaw/1.0"),
            true,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(url, error = %e, "web_fetch curl request failed");
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("Failed to fetch URL: {e}")),
                });
            }
        };

        if resp.status < 200 || resp.status >= 300 {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("HTTP {} for {url}", resp.status)),
            });
        }

        // Extract content-type from response headers
        let content_type = resp
            .headers
            .iter()
            .find(|h| h.to_lowercase().starts_with("content-type:"))
            .map(|h| h.split_once(':').map(|x| x.1).unwrap_or("").trim().to_string())
            .unwrap_or_default();

        let body = resp.body;

        // Convert HTML to text, or return raw text for non-HTML
        let text =
            if content_type.contains("text/html") || content_type.contains("application/xhtml") {
                // Strip script/style/noscript tags before conversion
                let cleaned = strip_non_content_tags(&body);
                match extract_mode {
                    "text" => {
                        // Plain text: use html2text then strip markdown artifacts
                        html2text::from_read(cleaned.as_bytes(), 80).unwrap_or_else(|_| cleaned)
                    }
                    _ => {
                        // Markdown mode (default)
                        html2text::from_read(cleaned.as_bytes(), 80).unwrap_or_else(|_| cleaned)
                    }
                }
            } else {
                body
            };

        // Truncate to max_length
        let truncated = if text.len() > max_length {
            format!(
                "{}\n\n[Truncated: showing {max_length} of {} characters]",
                &text[..max_length],
                text.len()
            )
        } else {
            text
        };

        // Wrap with injection defense
        let output = content_wrapper::wrap_web_content(&truncated, ContentSource::WebFetch);

        // Cache the result
        self.cache.insert(&cache_key, output.clone());

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
        assert!(schema["properties"]["extract_mode"].is_object());
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
    }

    #[tokio::test]
    async fn web_fetch_blocks_localhost() {
        let tool = WebFetchTool::new(test_security(), vec![], DEFAULT_TIMEOUT_SECS);
        let result = tool
            .execute(json!({"url": "http://localhost:8080/api"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("local/private"));
    }

    #[tokio::test]
    async fn web_fetch_blocks_private_ip() {
        let tool = WebFetchTool::new(test_security(), vec![], DEFAULT_TIMEOUT_SECS);
        let result = tool
            .execute(json!({"url": "http://192.168.1.1/admin"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("local/private"));
    }

    #[tokio::test]
    async fn web_fetch_blocks_metadata() {
        let tool = WebFetchTool::new(test_security(), vec![], DEFAULT_TIMEOUT_SECS);
        let result = tool
            .execute(json!({"url": "http://metadata.google.internal/computeMetadata"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("local/private"));
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
        let result = tool
            .execute(json!({"url": "https://sub.example.com/page"}))
            .await
            .unwrap();
        // Should not be blocked by domain or SSRF check (will fail at HTTP level)
        assert!(
            !result.success
                && !result
                    .error
                    .as_deref()
                    .unwrap_or("")
                    .contains("Domain not allowed")
        );
    }

    #[test]
    fn strip_script_tags() {
        let html = "<p>Hello</p><script>alert('xss')</script><p>World</p>";
        let result = strip_non_content_tags(html);
        assert_eq!(result, "<p>Hello</p><p>World</p>");
    }

    #[test]
    fn strip_style_tags() {
        let html = "<style>.red{color:red}</style><p>Content</p>";
        let result = strip_non_content_tags(html);
        assert_eq!(result, "<p>Content</p>");
    }

    #[test]
    fn strip_noscript_tags() {
        let html = "<p>Before</p><noscript>Enable JS</noscript><p>After</p>";
        let result = strip_non_content_tags(html);
        assert_eq!(result, "<p>Before</p><p>After</p>");
    }

    #[test]
    fn strip_preserves_normal_html() {
        let html = "<h1>Title</h1><p>Paragraph</p>";
        let result = strip_non_content_tags(html);
        assert_eq!(result, html);
    }
}
