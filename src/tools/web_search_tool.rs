use super::traits::{Tool, ToolResult};
use crate::security::content_wrapper::{self, ContentSource};
use crate::util::cache::TtlCache;
use async_trait::async_trait;
use regex::Regex;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Default cache TTL in minutes.
const DEFAULT_CACHE_TTL_MINUTES: u32 = 15;

/// Maximum cache entries for web search results.
const MAX_CACHE_ENTRIES: usize = 200;

/// Web search tool for searching the internet.
/// Supports multiple providers: DuckDuckGo (free), Brave (requires API key),
/// Perplexity (via OpenRouter or direct API), Grok (xAI).
pub struct WebSearchTool {
    provider: String,
    brave_api_key: Option<String>,
    perplexity_api_key: Option<String>,
    perplexity_base_url: Option<String>,
    perplexity_model: Option<String>,
    grok_api_key: Option<String>,
    grok_model: Option<String>,
    max_results: usize,
    timeout_secs: u64,
    freshness: Option<String>,
    cache: Arc<TtlCache<String>>,
}

impl WebSearchTool {
    pub fn new(
        provider: String,
        brave_api_key: Option<String>,
        max_results: usize,
        timeout_secs: u64,
    ) -> Self {
        Self::with_all_providers(
            provider,
            brave_api_key,
            None,
            None,
            None,
            None,
            None,
            max_results,
            timeout_secs,
            None,
            DEFAULT_CACHE_TTL_MINUTES,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_all_providers(
        provider: String,
        brave_api_key: Option<String>,
        perplexity_api_key: Option<String>,
        perplexity_base_url: Option<String>,
        perplexity_model: Option<String>,
        grok_api_key: Option<String>,
        grok_model: Option<String>,
        max_results: usize,
        timeout_secs: u64,
        freshness: Option<String>,
        cache_ttl_minutes: u32,
    ) -> Self {
        let ttl = Duration::from_secs(u64::from(cache_ttl_minutes) * 60);
        Self {
            provider: provider.trim().to_lowercase(),
            brave_api_key,
            perplexity_api_key,
            perplexity_base_url,
            perplexity_model,
            grok_api_key,
            grok_model,
            max_results: max_results.clamp(1, 10),
            timeout_secs: timeout_secs.max(1),
            freshness,
            cache: Arc::new(TtlCache::new(MAX_CACHE_ENTRIES, ttl)),
        }
    }

    async fn search_duckduckgo(&self, query: &str) -> anyhow::Result<String> {
        // Use DDG Lite endpoint (POST form) — more reliable than html.duckduckgo.com
        // which aggressively blocks non-browser TLS fingerprints (JA3/JA4).
        let form_data = format!("q={}", urlencoding::encode(query));

        let resp = super::curl_client::curl_post_form(
            "https://lite.duckduckgo.com/lite/",
            &form_data,
            &[],
            Duration::from_secs(self.timeout_secs),
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            true,
        )
        .await?;

        if resp.status < 200 || resp.status >= 300 {
            anyhow::bail!("DuckDuckGo search failed with status: {}", resp.status);
        }

        self.parse_duckduckgo_results(&resp.body, query)
    }

    fn parse_duckduckgo_results(&self, html: &str, query: &str) -> anyhow::Result<String> {
        // DDG Lite format uses simple table rows:
        //   <a rel="nofollow" href="URL" class="result-link">Title</a>
        //   <td class="result-snippet">Snippet text</td>
        // Attribute order varies, so we match any <a> with class="result-link" and extract href separately.
        let link_regex =
            Regex::new(r#"<a[^>]*\bclass="result-link"[^>]*>([\s\S]*?)</a>"#)?;
        let href_regex = Regex::new(r#"href="([^"]+)""#)?;

        let snippet_regex = Regex::new(r#"<td[^>]*class="result-snippet"[^>]*>([\s\S]*?)</td>"#)?;

        let link_matches: Vec<_> = link_regex
            .captures_iter(html)
            .take(self.max_results + 2)
            .collect();

        let snippet_matches: Vec<_> = snippet_regex
            .captures_iter(html)
            .take(self.max_results + 2)
            .collect();

        if link_matches.is_empty() {
            return Ok(format!("No results found for: {}", query));
        }

        let mut lines = vec![format!("Search results for: {} (via DuckDuckGo)", query)];

        let count = link_matches.len().min(self.max_results);

        for i in 0..count {
            let caps = &link_matches[i];
            let full_tag = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let url_str = href_regex
                .captures(full_tag)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str())
                .unwrap_or("");
            let title = strip_tags(&caps[1]);

            lines.push(format!("{}. {}", i + 1, title.trim()));
            lines.push(format!("   {}", url_str.trim()));

            if i < snippet_matches.len() {
                let snippet = strip_tags(&snippet_matches[i][1]);
                let snippet = snippet.trim();
                if !snippet.is_empty() {
                    lines.push(format!("   {}", snippet));
                }
            }
        }

        Ok(lines.join("\n"))
    }

    /// Try providers in order, returning the first successful result.
    /// Collects errors and returns a combined message if all fail.
    async fn try_providers(
        &self,
        providers: &[&str],
        query: &str,
        freshness: Option<&str>,
    ) -> Result<String, String> {
        let mut errors = Vec::new();

        for &provider in providers {
            match self.search_single(provider, query, freshness).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    tracing::warn!(provider, error = %e, "Search provider failed, trying next");
                    errors.push(format!("{provider}: {e:#}"));
                }
            }
        }

        Err(errors.join("; "))
    }

    /// Dispatch a search to a single provider by name.
    async fn search_single(
        &self,
        provider: &str,
        query: &str,
        freshness: Option<&str>,
    ) -> anyhow::Result<String> {
        match provider {
            "duckduckgo" | "ddg" => self.search_duckduckgo(query).await,
            "brave" => self.search_brave(query, freshness).await,
            "perplexity" => self.search_perplexity(query, freshness).await,
            "grok" => self.search_grok(query).await,
            other => anyhow::bail!(
                "Unknown search provider: {other}. Supported: auto, duckduckgo, brave, perplexity, grok"
            ),
        }
    }

    async fn search_brave(&self, query: &str, freshness: Option<&str>) -> anyhow::Result<String> {
        let api_key = self
            .brave_api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Brave API key not configured"))?;

        let encoded_query = urlencoding::encode(query);
        let mut search_url = format!(
            "https://api.search.brave.com/res/v1/web/search?q={}&count={}",
            encoded_query, self.max_results
        );

        if let Some(f) = freshness {
            use std::fmt::Write;
            let _ = write!(search_url, "&freshness={f}");
        }

        let resp = super::curl_client::curl_get(
            &search_url,
            &[
                ("Accept", "application/json"),
                ("X-Subscription-Token", api_key),
            ],
            Duration::from_secs(self.timeout_secs),
            None,
            false,
        )
        .await?;

        if resp.status < 200 || resp.status >= 300 {
            anyhow::bail!("Brave search failed with status: {}", resp.status);
        }

        let json: serde_json::Value = serde_json::from_str(&resp.body)?;
        self.parse_brave_results(&json, query)
    }

    fn parse_brave_results(&self, json: &serde_json::Value, query: &str) -> anyhow::Result<String> {
        let results = json
            .get("web")
            .and_then(|w| w.get("results"))
            .and_then(|r| r.as_array())
            .ok_or_else(|| anyhow::anyhow!("Invalid Brave API response"))?;

        if results.is_empty() {
            return Ok(format!("No results found for: {}", query));
        }

        let mut lines = vec![format!("Search results for: {} (via Brave)", query)];

        for (i, result) in results.iter().take(self.max_results).enumerate() {
            let title = result
                .get("title")
                .and_then(|t| t.as_str())
                .unwrap_or("No title");
            let url = result.get("url").and_then(|u| u.as_str()).unwrap_or("");
            let description = result
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");

            lines.push(format!("{}. {}", i + 1, title));
            lines.push(format!("   {}", url));
            if !description.is_empty() {
                lines.push(format!("   {}", description));
            }
        }

        Ok(lines.join("\n"))
    }

    async fn search_perplexity(
        &self,
        query: &str,
        freshness: Option<&str>,
    ) -> anyhow::Result<String> {
        let api_key = self
            .perplexity_api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Perplexity API key not configured"))?;

        // Auto-detect endpoint from key prefix
        let base_url = if let Some(ref url) = self.perplexity_base_url {
            url.clone()
        } else if api_key.starts_with("pplx-") {
            "https://api.perplexity.ai".to_string()
        } else if api_key.starts_with("sk-or-") {
            "https://openrouter.ai/api/v1".to_string()
        } else {
            "https://api.perplexity.ai".to_string()
        };

        let model = self
            .perplexity_model
            .as_deref()
            .unwrap_or("perplexity/sonar-pro");

        // Strip "perplexity/" prefix for direct API
        let effective_model = if base_url.contains("perplexity.ai") {
            model.strip_prefix("perplexity/").unwrap_or(model)
        } else {
            model
        };

        // Build search context
        let mut search_context = json!({});
        if let Some(f) = freshness {
            let recency = match f {
                "pd" => "day",
                "pw" => "week",
                "pm" => "month",
                "py" => "year",
                other => other,
            };
            search_context = json!({"search_recency_filter": recency});
        }

        let body = json!({
            "model": effective_model,
            "messages": [
                {"role": "system", "content": "You are a search assistant. Provide concise search results with sources."},
                {"role": "user", "content": query}
            ],
            "search_context": search_context,
        });

        let post_url = format!("{base_url}/chat/completions");
        let auth_header = format!("Bearer {api_key}");
        let resp = super::curl_client::curl_post_json(
            &post_url,
            &body.to_string(),
            &[("Authorization", &auth_header)],
            Duration::from_secs(self.timeout_secs),
        )
        .await?;

        if resp.status < 200 || resp.status >= 300 {
            anyhow::bail!(
                "Perplexity search failed (HTTP {}): {}",
                resp.status,
                resp.body
            );
        }

        let resp: serde_json::Value = serde_json::from_str(&resp.body)?;
        let content = resp["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("No results");

        // Extract citations if available
        let mut result = format!(
            "Search results for: {} (via Perplexity)\n\n{}",
            query, content
        );

        if let Some(citations) = resp["citations"].as_array() {
            result.push_str("\n\nSources:");
            for (i, citation) in citations.iter().enumerate() {
                if let Some(url) = citation.as_str() {
                    use std::fmt::Write;
                    let _ = write!(result, "\n{}. {}", i + 1, url);
                }
            }
        }

        Ok(result)
    }

    async fn search_grok(&self, query: &str) -> anyhow::Result<String> {
        let api_key = self
            .grok_api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Grok API key not configured"))?;

        let model = self.grok_model.as_deref().unwrap_or("grok-4-1-fast");

        let body = json!({
            "model": model,
            "tools": [{"type": "web_search"}],
            "input": query,
        });

        let auth_header = format!("Bearer {api_key}");
        let resp = super::curl_client::curl_post_json(
            "https://api.x.ai/v1/responses",
            &body.to_string(),
            &[("Authorization", &auth_header)],
            Duration::from_secs(self.timeout_secs),
        )
        .await?;

        if resp.status < 200 || resp.status >= 300 {
            anyhow::bail!("Grok search failed (HTTP {}): {}", resp.status, resp.body);
        }

        let resp: serde_json::Value = serde_json::from_str(&resp.body)?;

        // Parse Grok response format: output[].content[].text + annotations
        let mut result = format!("Search results for: {} (via Grok)\n", query);
        let mut sources = Vec::new();

        if let Some(output) = resp["output"].as_array() {
            for item in output {
                if let Some(content) = item["content"].as_array() {
                    for block in content {
                        if let Some(text) = block["text"].as_str() {
                            result.push('\n');
                            result.push_str(text);
                        }
                        // Collect URL citations from annotations
                        if let Some(annotations) = block["annotations"].as_array() {
                            for ann in annotations {
                                if ann["type"].as_str() == Some("url_citation") {
                                    if let Some(url) = ann["url"].as_str() {
                                        if !sources.contains(&url.to_string()) {
                                            sources.push(url.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // Also check top-level text
                if let Some(text) = item["text"].as_str() {
                    result.push('\n');
                    result.push_str(text);
                }
            }
        }

        if !sources.is_empty() {
            result.push_str("\n\nSources:");
            for (i, url) in sources.iter().enumerate() {
                use std::fmt::Write;
                let _ = write!(result, "\n{}. {}", i + 1, url);
            }
        }

        Ok(result)
    }
}

fn strip_tags(content: &str) -> String {
    let re = Regex::new(r"<[^>]+>").unwrap();
    re.replace_all(content, "").to_string()
}

#[async_trait]
impl Tool for WebSearchTool {
    fn name(&self) -> &str {
        "web_search_tool"
    }

    fn description(&self) -> &str {
        "Search the web for information. Returns relevant search results with titles, URLs, and descriptions. \
        Supports providers: auto, duckduckgo, brave, perplexity, grok."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The search query. Be specific for better results."
                },
                "freshness": {
                    "type": "string",
                    "description": "Time freshness filter: \"pd\" (past day), \"pw\" (past week), \"pm\" (past month), \"py\" (past year). Only supported by Brave and Perplexity.",
                    "enum": ["pd", "pw", "pm", "py"]
                },
                "country": {
                    "type": "string",
                    "description": "Two-letter country code for localized results (e.g., \"us\", \"gb\", \"de\")"
                },
                "search_lang": {
                    "type": "string",
                    "description": "Language code for search results (e.g., \"en\", \"es\", \"fr\")"
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let query = args
            .get("query")
            .and_then(|q| q.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: query"))?;

        if query.trim().is_empty() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Search query cannot be empty".into()),
            });
        }

        // Resolve freshness: parameter override > tool config
        let freshness = args
            .get("freshness")
            .and_then(|f| f.as_str())
            .map(String::from)
            .or_else(|| self.freshness.clone());

        // Check cache
        let cache_key = format!(
            "{}:{}:{}",
            self.provider,
            query,
            freshness.as_deref().unwrap_or("none")
        );
        if let Some(cached) = self.cache.get(&cache_key) {
            tracing::debug!(provider = %self.provider, "web_search cache hit");
            return Ok(ToolResult {
                success: true,
                output: cached,
                error: None,
            });
        }

        tracing::info!(provider = %self.provider, "Searching web for: {}", query);

        // Build provider try-order: explicit provider first, then fallbacks for "auto" mode.
        let providers: Vec<&str> = match self.provider.as_str() {
            "auto" => {
                // Try all configured providers in priority order
                let mut list = Vec::new();
                if self.brave_api_key.is_some() {
                    list.push("brave");
                }
                if self.perplexity_api_key.is_some() {
                    list.push("perplexity");
                }
                if self.grok_api_key.is_some() {
                    list.push("grok");
                }
                list.push("duckduckgo");
                list
            }
            p => vec![p],
        };

        let result = self
            .try_providers(&providers, query, freshness.as_deref())
            .await;

        let result = match result {
            Ok(r) => r,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(e),
                });
            }
        };

        // Wrap with injection defense
        let wrapped = content_wrapper::wrap_web_content(&result, ContentSource::WebSearch);

        // Cache the wrapped result
        self.cache.insert(&cache_key, wrapped.clone());

        Ok(ToolResult {
            success: true,
            output: wrapped,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_name() {
        let tool = WebSearchTool::new("duckduckgo".to_string(), None, 5, 15);
        assert_eq!(tool.name(), "web_search_tool");
    }

    #[test]
    fn test_tool_description() {
        let tool = WebSearchTool::new("duckduckgo".to_string(), None, 5, 15);
        assert!(tool.description().contains("Search the web"));
    }

    #[test]
    fn test_parameters_schema() {
        let tool = WebSearchTool::new("duckduckgo".to_string(), None, 5, 15);
        let schema = tool.parameters_schema();
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["query"].is_object());
        assert!(schema["properties"]["freshness"].is_object());
    }

    #[test]
    fn test_strip_tags() {
        let html = "<b>Hello</b> <i>World</i>";
        assert_eq!(strip_tags(html), "Hello World");
    }

    #[test]
    fn test_parse_duckduckgo_results_empty() {
        let tool = WebSearchTool::new("duckduckgo".to_string(), None, 5, 15);
        let result = tool
            .parse_duckduckgo_results("<html>No results here</html>", "test")
            .unwrap();
        assert!(result.contains("No results found"));
    }

    #[test]
    fn test_parse_duckduckgo_results_with_data() {
        let tool = WebSearchTool::new("duckduckgo".to_string(), None, 5, 15);
        let html = r#"
            <a rel="nofollow" href="https://example.com" class="result-link">Example Title</a>
            <td class="result-snippet">This is a description</td>
        "#;
        let result = tool.parse_duckduckgo_results(html, "test").unwrap();
        assert!(result.contains("Example Title"));
        assert!(result.contains("https://example.com"));
    }

    #[test]
    fn test_parse_duckduckgo_results_direct_urls() {
        let tool = WebSearchTool::new("duckduckgo".to_string(), None, 5, 15);
        let html = r#"
            <a rel="nofollow" href="https://example.com/path?a=1" class="result-link">Example Title</a>
            <td class="result-snippet">This is a description</td>
        "#;
        let result = tool.parse_duckduckgo_results(html, "test").unwrap();
        assert!(result.contains("https://example.com/path?a=1"));
    }

    #[test]
    fn test_constructor_clamps_web_search_limits() {
        let tool = WebSearchTool::new("duckduckgo".to_string(), None, 0, 0);
        let html = r#"
            <a rel="nofollow" href="https://example.com" class="result-link">Example Title</a>
            <td class="result-snippet">This is a description</td>
        "#;
        let result = tool.parse_duckduckgo_results(html, "test").unwrap();
        assert!(result.contains("Example Title"));
    }

    #[tokio::test]
    async fn test_execute_missing_query() {
        let tool = WebSearchTool::new("duckduckgo".to_string(), None, 5, 15);
        let result = tool.execute(json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_empty_query() {
        let tool = WebSearchTool::new("duckduckgo".to_string(), None, 5, 15);
        let result = tool.execute(json!({"query": ""})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("empty"));
    }

    #[tokio::test]
    async fn test_execute_brave_without_api_key() {
        let tool = WebSearchTool::new("brave".to_string(), None, 5, 15);
        let result = tool.execute(json!({"query": "test"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap_or("").contains("API key"));
    }

    #[tokio::test]
    async fn test_execute_perplexity_without_api_key() {
        let tool = WebSearchTool::with_all_providers(
            "perplexity".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            5,
            15,
            None,
            15,
        );
        let result = tool.execute(json!({"query": "test"})).await.unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Perplexity API key"));
    }

    #[tokio::test]
    async fn test_execute_grok_without_api_key() {
        let tool = WebSearchTool::with_all_providers(
            "grok".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            5,
            15,
            None,
            15,
        );
        let result = tool.execute(json!({"query": "test"})).await.unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Grok API key"));
    }

    #[tokio::test]
    async fn test_execute_unknown_provider() {
        let tool = WebSearchTool::new("unknown_engine".to_string(), None, 5, 15);
        let result = tool.execute(json!({"query": "test"})).await.unwrap();
        assert!(!result.success);
        assert!(result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Unknown search provider"));
    }
}
