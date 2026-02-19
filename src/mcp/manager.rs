//! MCP server lifecycle manager — manages multiple server connections.

use crate::config::McpConfig;
use crate::mcp::client::McpClient;
use crate::mcp::transport;
use crate::mcp::types::{McpServerStatus, McpToolDefinition};
use crate::tools::Tool;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Manages connections to multiple MCP servers.
pub struct McpManager {
    clients: Mutex<HashMap<String, Arc<McpClient>>>,
    config: McpConfig,
}

impl McpManager {
    /// Create a new manager (no connections yet).
    pub fn new(config: McpConfig) -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Connect to all configured servers. Failures are logged as warnings, non-fatal.
    pub async fn connect_all(&self) -> Result<()> {
        let mut errors = Vec::new();

        for (name, server_config) in &self.config.servers {
            match self.connect_server_inner(name, server_config).await {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(server = %name, error = %e, "Failed to connect MCP server");
                    errors.push(format!("{name}: {e}"));
                }
            }
        }

        if !errors.is_empty() {
            bail!("{}", errors.join("; "));
        }

        Ok(())
    }

    async fn connect_server_inner(
        &self,
        name: &str,
        server_config: &crate::config::McpServerConfig,
    ) -> Result<()> {
        let timeout = server_config
            .timeout_secs
            .unwrap_or(self.config.default_timeout_secs);

        let transport = transport::create_transport(
            &server_config.transport,
            server_config.command.as_deref(),
            &server_config.args,
            &server_config.env,
            server_config.url.as_deref(),
            &server_config.headers,
            timeout,
        )?;

        let client = McpClient::new(name.to_string(), transport);
        client.initialize().await?;
        client.list_tools().await?;

        let tools = client.cached_tools().await;
        tracing::info!(
            server = %name,
            tools = tools.len(),
            "MCP server connected"
        );

        let mut clients = self.clients.lock().await;
        clients.insert(name.to_string(), Arc::new(client));
        Ok(())
    }

    /// Connect a single server by name (from config).
    pub async fn connect_server(&self, name: &str) -> Result<()> {
        let server_config = self
            .config
            .servers
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("MCP server '{name}' not found in config"))?
            .clone();
        self.connect_server_inner(name, &server_config).await
    }

    /// Disconnect a single server.
    pub async fn disconnect_server(&self, name: &str) -> Result<()> {
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.remove(name) {
            client.close().await?;
        }
        Ok(())
    }

    /// Get status of all configured servers.
    pub async fn server_statuses(&self) -> HashMap<String, McpServerStatus> {
        let clients = self.clients.lock().await;
        let mut statuses = HashMap::new();

        // Include connected servers
        for (name, client) in clients.iter() {
            statuses.insert(name.clone(), client.status().await);
        }

        // Include configured-but-not-connected servers
        for name in self.config.servers.keys() {
            statuses
                .entry(name.clone())
                .or_insert(McpServerStatus::Disconnected);
        }

        statuses
    }

    /// Get all tools from all connected servers.
    pub async fn all_tools(&self) -> Vec<(String, McpToolDefinition)> {
        let clients = self.clients.lock().await;
        let mut result = Vec::new();
        for (name, client) in clients.iter() {
            for tool in client.cached_tools().await {
                result.push((name.clone(), tool));
            }
        }
        result
    }

    /// Get tools from a specific server.
    pub async fn server_tools(&self, name: &str) -> Option<Vec<McpToolDefinition>> {
        let clients = self.clients.lock().await;
        let client = clients.get(name)?;
        Some(client.cached_tools().await)
    }

    /// Call a tool on a specific server.
    pub async fn call_tool(
        &self,
        server: &str,
        tool: &str,
        args: serde_json::Value,
    ) -> Result<crate::mcp::types::McpCallToolResult> {
        let clients = self.clients.lock().await;
        let client = clients
            .get(server)
            .ok_or_else(|| anyhow::anyhow!("MCP server '{server}' not connected"))?
            .clone();
        drop(clients); // Release lock before potentially slow call

        // Check if transport is alive; if not and auto_restart, try reconnect
        if !client.is_alive() {
            if let Some(cfg) = self.config.servers.get(server) {
                if cfg.auto_restart {
                    tracing::info!(server = %server, "MCP server process died, attempting reconnect");
                    drop(client);
                    self.connect_server(server).await?;
                    let clients = self.clients.lock().await;
                    let client = clients
                        .get(server)
                        .ok_or_else(|| anyhow::anyhow!("MCP reconnect failed for '{server}'"))?
                        .clone();
                    drop(clients);
                    return client.call_tool(tool, args).await;
                }
            }
            bail!("MCP server '{server}' transport is dead");
        }

        client.call_tool(tool, args).await
    }

    /// Create proxy tools wrapping all MCP server tools as native ZeroClaw tools.
    pub fn create_proxy_tools(self: &Arc<Self>, manager: Arc<McpManager>) -> Vec<Box<dyn Tool>> {
        // We need to block on the async lock briefly to get tool list.
        // This is called during setup, not in hot path.
        let tools = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.all_tools())
        });

        tools
            .into_iter()
            .map(|(server, tool_def)| {
                let proxy: Box<dyn Tool> = Box::new(crate::tools::McpProxyTool::new(
                    server,
                    tool_def,
                    manager.clone(),
                ));
                proxy
            })
            .collect()
    }

    /// Shutdown all connected servers.
    pub async fn shutdown(&self) -> Result<()> {
        let mut clients = self.clients.lock().await;
        for (name, client) in clients.drain() {
            if let Err(e) = client.close().await {
                tracing::warn!(server = %name, error = %e, "Error closing MCP server");
            }
        }
        Ok(())
    }

    /// Get reference to the config.
    pub fn config(&self) -> &McpConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpConfig;

    #[tokio::test]
    async fn manager_empty_config() {
        let config = McpConfig::default();
        let manager = McpManager::new(config);

        let statuses = manager.server_statuses().await;
        assert!(statuses.is_empty());

        let tools = manager.all_tools().await;
        assert!(tools.is_empty());
    }

    #[tokio::test]
    async fn manager_disconnect_nonexistent() {
        let config = McpConfig::default();
        let manager = McpManager::new(config);

        // Should not error
        manager.disconnect_server("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn manager_call_tool_not_connected() {
        let config = McpConfig::default();
        let manager = McpManager::new(config);

        let result = manager
            .call_tool("nonexistent", "test", serde_json::json!({}))
            .await;
        assert!(result.is_err());
    }
}
