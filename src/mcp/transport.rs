//! MCP transport implementations — stdio, HTTP, SSE.

use crate::mcp::types::{JsonRpcRequest, JsonRpcResponse};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, Mutex};

/// Transport trait for MCP server communication.
#[async_trait]
pub trait McpTransport: Send + Sync {
    /// Send a JSON-RPC request and wait for the matching response.
    async fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse>;

    /// Send a JSON-RPC notification (no response expected).
    async fn send_notification(&self, method: &str, params: Option<Value>) -> Result<()>;

    /// Check if the transport is still alive.
    fn is_alive(&self) -> bool;

    /// Close the transport.
    async fn close(&self) -> Result<()>;
}

// ── Stdio Transport ─────────────────────────────────────────────

type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<JsonRpcResponse>>>>;

/// Transport that communicates with an MCP server via stdin/stdout of a child process.
pub struct StdioTransport {
    stdin: Mutex<tokio::process::ChildStdin>,
    pending: PendingMap,
    alive: Arc<AtomicBool>,
    child: Mutex<Child>,
}

impl StdioTransport {
    /// Spawn a child process and set up stdin/stdout communication.
    pub fn spawn(command: &str, args: &[String], env: &HashMap<String, String>) -> Result<Self> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .env_clear();

        // Inject only configured env vars + minimal PATH
        for (k, v) in env {
            cmd.env(k, v);
        }
        if !env.contains_key("PATH") {
            if let Ok(path) = std::env::var("PATH") {
                cmd.env("PATH", path);
            }
        }
        // Some tools need HOME
        if !env.contains_key("HOME") {
            if let Ok(home) = std::env::var("HOME") {
                cmd.env("HOME", home);
            }
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn MCP server: {command} {}", args.join(" ")))?;

        let stdin = child
            .stdin
            .take()
            .context("Failed to capture child stdin")?;
        let stdout = child
            .stdout
            .take()
            .context("Failed to capture child stdout")?;
        let stderr = child
            .stderr
            .take()
            .context("Failed to capture child stderr")?;

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));

        // Background task: read stdout lines and dispatch responses
        let pending_clone = pending.clone();
        let alive_clone = alive.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => {
                        alive_clone.store(false, Ordering::SeqCst);
                        break;
                    }
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(trimmed) {
                            if let Some(id) = resp.id {
                                let mut map = pending_clone.lock().await;
                                if let Some(tx) = map.remove(&id) {
                                    let _ = tx.send(resp);
                                }
                            }
                            // Notifications (no id) are currently ignored
                        }
                    }
                    Err(e) => {
                        tracing::warn!("MCP stdio read error: {e}");
                        alive_clone.store(false, Ordering::SeqCst);
                        break;
                    }
                }
            }
        });

        // Background task: drain stderr and log warnings
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            tracing::debug!(target: "mcp_stderr", "{trimmed}");
                        }
                    }
                }
            }
        });

        Ok(Self {
            stdin: Mutex::new(stdin),
            pending,
            alive,
            child: Mutex::new(child),
        })
    }
}

#[async_trait]
impl McpTransport for StdioTransport {
    async fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        if !self.alive.load(Ordering::SeqCst) {
            bail!("MCP stdio transport is dead");
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().await;
            map.insert(request.id, tx);
        }

        let mut json = serde_json::to_string(request)?;
        json.push('\n');

        {
            let mut stdin = self.stdin.lock().await;
            stdin
                .write_all(json.as_bytes())
                .await
                .context("Failed to write to MCP stdin")?;
            stdin.flush().await?;
        }

        let resp = tokio::time::timeout(std::time::Duration::from_secs(120), rx)
            .await
            .context("MCP request timed out")?
            .context("MCP response channel closed")?;

        Ok(resp)
    }

    async fn send_notification(&self, method: &str, params: Option<Value>) -> Result<()> {
        if !self.alive.load(Ordering::SeqCst) {
            bail!("MCP stdio transport is dead");
        }

        // Notifications use JSON-RPC without id
        let notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params.unwrap_or(Value::Object(serde_json::Map::new())),
        });

        let mut json = serde_json::to_string(&notif)?;
        json.push('\n');

        let mut stdin = self.stdin.lock().await;
        stdin.write_all(json.as_bytes()).await?;
        stdin.flush().await?;
        Ok(())
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    async fn close(&self) -> Result<()> {
        self.alive.store(false, Ordering::SeqCst);
        let mut child = self.child.lock().await;
        let _ = child.kill().await;
        Ok(())
    }
}

// ── HTTP Transport ──────────────────────────────────────────────

/// Transport that communicates with an MCP server via HTTP POST.
pub struct HttpTransport {
    client: reqwest::Client,
    url: String,
    headers: HashMap<String, String>,
    session_id: Mutex<Option<String>>,
}

impl HttpTransport {
    pub fn new(url: &str, headers: &HashMap<String, String>, timeout_secs: u64) -> Self {
        let client =
            crate::config::build_runtime_proxy_client_with_timeouts("tool.mcp", timeout_secs, 10);
        Self {
            client,
            url: url.to_string(),
            headers: headers.clone(),
            session_id: Mutex::new(None),
        }
    }
}

#[async_trait]
impl McpTransport for HttpTransport {
    async fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        let mut req = self.client.post(&self.url);
        req = req.header("Content-Type", "application/json");

        for (k, v) in &self.headers {
            req = req.header(k, v);
        }

        // Include session id if we have one
        {
            let session = self.session_id.lock().await;
            if let Some(ref id) = *session {
                req = req.header("Mcp-Session-Id", id);
            }
        }

        let resp = req.json(request).send().await?;

        // Capture session id from response
        if let Some(session_id) = resp.headers().get("mcp-session-id") {
            if let Ok(id) = session_id.to_str() {
                let mut session = self.session_id.lock().await;
                *session = Some(id.to_string());
            }
        }

        let body = resp.text().await?;
        let rpc_resp: JsonRpcResponse =
            serde_json::from_str(&body).context("Failed to parse MCP HTTP response")?;
        Ok(rpc_resp)
    }

    async fn send_notification(&self, method: &str, params: Option<Value>) -> Result<()> {
        let notif = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params.unwrap_or(Value::Object(serde_json::Map::new())),
        });

        let mut req = self.client.post(&self.url);
        req = req.header("Content-Type", "application/json");

        for (k, v) in &self.headers {
            req = req.header(k, v);
        }

        {
            let session = self.session_id.lock().await;
            if let Some(ref id) = *session {
                req = req.header("Mcp-Session-Id", id);
            }
        }

        req.json(&notif).send().await?;
        Ok(())
    }

    fn is_alive(&self) -> bool {
        true // HTTP is stateless; liveness is per-request
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

// ── SSE Transport ───────────────────────────────────────────────

/// Legacy SSE transport — sends requests via HTTP POST, receives via SSE stream.
/// This is a thin wrapper that behaves like HTTP for requests.
pub struct SseTransport {
    inner: HttpTransport,
}

impl SseTransport {
    pub fn new(url: &str, headers: &HashMap<String, String>, timeout_secs: u64) -> Self {
        Self {
            inner: HttpTransport::new(url, headers, timeout_secs),
        }
    }
}

#[async_trait]
impl McpTransport for SseTransport {
    async fn send_request(&self, request: &JsonRpcRequest) -> Result<JsonRpcResponse> {
        self.inner.send_request(request).await
    }

    async fn send_notification(&self, method: &str, params: Option<Value>) -> Result<()> {
        self.inner.send_notification(method, params).await
    }

    fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }
}

/// Create a transport from config.
#[allow(clippy::implicit_hasher)]
pub fn create_transport(
    transport_type: &crate::config::McpTransportType,
    command: Option<&str>,
    args: &[String],
    env: &HashMap<String, String>,
    url: Option<&str>,
    headers: &HashMap<String, String>,
    timeout_secs: u64,
) -> Result<Box<dyn McpTransport>> {
    match transport_type {
        crate::config::McpTransportType::Stdio => {
            let cmd = command.context("stdio transport requires 'command'")?;
            let transport = StdioTransport::spawn(cmd, args, env)?;
            Ok(Box::new(transport))
        }
        crate::config::McpTransportType::Http => {
            let server_url = url.context("http transport requires 'url'")?;
            Ok(Box::new(HttpTransport::new(
                server_url,
                headers,
                timeout_secs,
            )))
        }
        crate::config::McpTransportType::Sse => {
            let server_url = url.context("sse transport requires 'url'")?;
            Ok(Box::new(SseTransport::new(
                server_url,
                headers,
                timeout_secs,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_transport_creation() {
        let headers = HashMap::new();
        let transport = HttpTransport::new("https://example.com/mcp", &headers, 30);
        assert!(transport.is_alive());
    }

    #[test]
    fn sse_transport_creation() {
        let headers = HashMap::new();
        let transport = SseTransport::new("https://example.com/mcp", &headers, 30);
        assert!(transport.is_alive());
    }
}
