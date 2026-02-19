//! MCP client session — manages protocol lifecycle for a single server.

use crate::mcp::transport::McpTransport;
use crate::mcp::types::{
    ClientCapabilities, ClientInfo, InitializeParams, InitializeResult, JsonRpcRequest,
    McpCallToolResult, McpPromptDefinition, McpResourceDefinition, McpServerStatus,
    McpToolDefinition, PromptsListResult, ResourcesListResult, ServerCapabilities, ToolsListResult,
    MCP_CLIENT_NAME, MCP_CLIENT_VERSION, MCP_PROTOCOL_VERSION,
};
use anyhow::{bail, Context, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

/// MCP client for a single server connection.
pub struct McpClient {
    name: String,
    transport: Box<dyn McpTransport>,
    request_counter: AtomicU64,
    server_capabilities: Mutex<Option<ServerCapabilities>>,
    tools: Mutex<Vec<McpToolDefinition>>,
    status: Mutex<McpServerStatus>,
}

impl McpClient {
    /// Create a new uninitialized client.
    pub fn new(name: String, transport: Box<dyn McpTransport>) -> Self {
        Self {
            name,
            transport,
            request_counter: AtomicU64::new(1),
            server_capabilities: Mutex::new(None),
            tools: Mutex::new(Vec::new()),
            status: Mutex::new(McpServerStatus::Disconnected),
        }
    }

    fn next_id(&self) -> u64 {
        self.request_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Perform MCP handshake: send `initialize`, receive capabilities, send `initialized`.
    pub async fn initialize(&self) -> Result<()> {
        {
            let mut status = self.status.lock().await;
            *status = McpServerStatus::Connecting;
        }

        let params = InitializeParams {
            protocol_version: MCP_PROTOCOL_VERSION.to_string(),
            capabilities: ClientCapabilities {},
            client_info: ClientInfo {
                name: MCP_CLIENT_NAME.to_string(),
                version: MCP_CLIENT_VERSION.to_string(),
            },
        };

        let req = JsonRpcRequest::new(
            self.next_id(),
            "initialize",
            Some(serde_json::to_value(&params)?),
        );

        let resp = self
            .transport
            .send_request(&req)
            .await
            .context("MCP initialize request failed")?;

        if let Some(err) = resp.error {
            let mut status = self.status.lock().await;
            *status = McpServerStatus::Error(err.message.clone());
            bail!("MCP initialize error: {err}");
        }

        let result_value = resp.result.context("MCP initialize returned no result")?;
        let init_result: InitializeResult = serde_json::from_value(result_value)
            .context("Failed to parse MCP initialize result")?;

        {
            let mut caps = self.server_capabilities.lock().await;
            *caps = Some(init_result.capabilities);
        }

        // Send initialized notification
        self.transport
            .send_notification("notifications/initialized", None)
            .await
            .context("Failed to send initialized notification")?;

        {
            let mut status = self.status.lock().await;
            *status = McpServerStatus::Connected;
        }

        if let Some(info) = init_result.server_info {
            tracing::info!(
                server = %self.name,
                server_name = %info.name,
                server_version = info.version.as_deref().unwrap_or("unknown"),
                "MCP server initialized"
            );
        }

        Ok(())
    }

    /// Call `tools/list` and cache results.
    pub async fn list_tools(&self) -> Result<Vec<McpToolDefinition>> {
        let req = JsonRpcRequest::new(self.next_id(), "tools/list", None);
        let resp = self
            .transport
            .send_request(&req)
            .await
            .context("MCP tools/list request failed")?;

        if let Some(err) = resp.error {
            bail!("MCP tools/list error: {err}");
        }

        let result_value = resp.result.context("MCP tools/list returned no result")?;
        let list_result: ToolsListResult =
            serde_json::from_value(result_value).context("Failed to parse tools/list result")?;

        let tools = list_result.tools;
        {
            let mut cached = self.tools.lock().await;
            *cached = tools.clone();
        }

        Ok(tools)
    }

    /// Call a tool on the server.
    pub async fn call_tool(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<McpCallToolResult> {
        let params = serde_json::json!({
            "name": name,
            "arguments": args,
        });

        let req = JsonRpcRequest::new(self.next_id(), "tools/call", Some(params));
        let resp = self
            .transport
            .send_request(&req)
            .await
            .with_context(|| format!("MCP tools/call failed for {name}"))?;

        if let Some(err) = resp.error {
            bail!("MCP tools/call error for {name}: {err}");
        }

        let result_value = resp.result.context("MCP tools/call returned no result")?;
        let call_result: McpCallToolResult =
            serde_json::from_value(result_value).context("Failed to parse tools/call result")?;

        Ok(call_result)
    }

    /// Call `resources/list` to discover available resources.
    pub async fn list_resources(&self) -> Result<Vec<McpResourceDefinition>> {
        let req = JsonRpcRequest::new(self.next_id(), "resources/list", None);
        let resp = self
            .transport
            .send_request(&req)
            .await
            .context("MCP resources/list request failed")?;

        if let Some(err) = resp.error {
            bail!("MCP resources/list error: {err}");
        }

        let result_value = resp
            .result
            .context("MCP resources/list returned no result")?;
        let list_result: ResourcesListResult = serde_json::from_value(result_value)
            .context("Failed to parse resources/list result")?;

        Ok(list_result.resources)
    }

    /// Call `prompts/list` to discover available prompts.
    pub async fn list_prompts(&self) -> Result<Vec<McpPromptDefinition>> {
        let req = JsonRpcRequest::new(self.next_id(), "prompts/list", None);
        let resp = self
            .transport
            .send_request(&req)
            .await
            .context("MCP prompts/list request failed")?;

        if let Some(err) = resp.error {
            bail!("MCP prompts/list error: {err}");
        }

        let result_value = resp.result.context("MCP prompts/list returned no result")?;
        let list_result: PromptsListResult =
            serde_json::from_value(result_value).context("Failed to parse prompts/list result")?;

        Ok(list_result.prompts)
    }

    /// Get server capabilities (from last `initialize()` call).
    pub async fn server_capabilities(&self) -> Option<ServerCapabilities> {
        self.server_capabilities.lock().await.clone()
    }

    /// Get current connection status.
    pub async fn status(&self) -> McpServerStatus {
        self.status.lock().await.clone()
    }

    /// Get cached tool list (from last `list_tools()` call).
    pub async fn cached_tools(&self) -> Vec<McpToolDefinition> {
        self.tools.lock().await.clone()
    }

    /// Close the transport.
    pub async fn close(&self) -> Result<()> {
        let mut status = self.status.lock().await;
        *status = McpServerStatus::Disconnected;
        self.transport.close().await
    }

    /// Get server name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if transport is alive.
    pub fn is_alive(&self) -> bool {
        self.transport.is_alive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::transport::McpTransport;
    use crate::mcp::types::JsonRpcResponse;

    /// Mock transport for testing.
    struct MockTransport {
        responses: Mutex<Vec<JsonRpcResponse>>,
    }

    impl MockTransport {
        fn new(responses: Vec<JsonRpcResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }

    #[async_trait::async_trait]
    impl McpTransport for MockTransport {
        async fn send_request(&self, _request: &JsonRpcRequest) -> Result<JsonRpcResponse> {
            let mut responses = self.responses.lock().await;
            if responses.is_empty() {
                bail!("No more mock responses");
            }
            Ok(responses.remove(0))
        }

        async fn send_notification(
            &self,
            _method: &str,
            _params: Option<serde_json::Value>,
        ) -> Result<()> {
            Ok(())
        }

        fn is_alive(&self) -> bool {
            true
        }

        async fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn client_initialize_and_list_tools() {
        let init_response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            result: Some(serde_json::json!({
                "protocolVersion": "2025-03-26",
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "test-server", "version": "1.0" }
            })),
            error: None,
        };

        let tools_response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(2),
            result: Some(serde_json::json!({
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file",
                        "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } } }
                    }
                ]
            })),
            error: None,
        };

        let transport = MockTransport::new(vec![init_response, tools_response]);
        let client = McpClient::new("test".to_string(), Box::new(transport));

        client.initialize().await.unwrap();
        let status = client.status().await;
        assert_eq!(status, McpServerStatus::Connected);

        let tools = client.list_tools().await.unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "read_file");
    }

    #[tokio::test]
    async fn client_call_tool() {
        let call_response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            result: Some(serde_json::json!({
                "content": [{ "type": "text", "text": "file contents here" }],
                "isError": false
            })),
            error: None,
        };

        let transport = MockTransport::new(vec![call_response]);
        let client = McpClient::new("test".to_string(), Box::new(transport));

        let result = client
            .call_tool("read_file", serde_json::json!({"path": "/tmp/test"}))
            .await
            .unwrap();
        assert!(!result.is_error);
        assert_eq!(result.content.len(), 1);
    }

    #[tokio::test]
    async fn client_initialize_error() {
        let error_response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            result: None,
            error: Some(crate::mcp::types::JsonRpcError {
                code: -32600,
                message: "Invalid request".to_string(),
                data: None,
            }),
        };

        let transport = MockTransport::new(vec![error_response]);
        let client = McpClient::new("test".to_string(), Box::new(transport));

        let result = client.initialize().await;
        assert!(result.is_err());

        let status = client.status().await;
        assert!(matches!(status, McpServerStatus::Error(_)));
    }
}
