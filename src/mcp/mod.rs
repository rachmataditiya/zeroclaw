//! MCP (Model Context Protocol) client support.
//!
//! Enables ZeroClaw agents to connect to MCP-compatible tool servers,
//! discovering and invoking external tools via JSON-RPC 2.0.

pub mod client;
pub mod manager;
pub mod transport;
pub mod types;

pub use manager::McpManager;
#[allow(unused_imports)]
pub use types::{McpServerStatus, McpToolDefinition};

use crate::config::Config;
use anyhow::Result;

/// Handle `zeroclaw mcp` subcommands.
pub fn handle_command(cmd: crate::McpCommands, config: &Config) -> Result<()> {
    match cmd {
        crate::McpCommands::List => {
            if config.mcp.servers.is_empty() {
                println!("No MCP servers configured.");
                println!();
                println!("Add one with: zeroclaw mcp add <name> --command <cmd>");
                println!("  Example: zeroclaw mcp add filesystem --command npx -- -y @modelcontextprotocol/server-filesystem /tmp");
                println!();
                println!("Or add to config.toml:");
                println!("  [mcp]");
                println!("  enabled = true");
                println!();
                println!("  [mcp.servers.filesystem]");
                println!("  transport = \"stdio\"");
                println!("  command = \"npx\"");
                println!(
                    "  args = [\"-y\", \"@modelcontextprotocol/server-filesystem\", \"/tmp\"]"
                );
            } else {
                println!("Configured MCP servers:");
                for (name, server) in &config.mcp.servers {
                    let detail = match &server.transport {
                        crate::config::McpTransportType::Stdio => {
                            format!(
                                "{} {}",
                                server.command.as_deref().unwrap_or("(no command)"),
                                server.args.join(" ")
                            )
                        }
                        crate::config::McpTransportType::Http
                        | crate::config::McpTransportType::Sse => {
                            server.url.as_deref().unwrap_or("(no url)").to_string()
                        }
                    };
                    println!("  {}  {}  {}", name, server.transport, detail);
                }
                if !config.mcp.enabled {
                    println!();
                    println!("Note: MCP is not enabled. Set mcp.enabled = true in config.toml");
                }
            }
        }
        crate::McpCommands::Add {
            name,
            transport,
            command,
            url,
            args,
        } => {
            let mut cfg = Config::load_or_init()?;

            if cfg.mcp.servers.contains_key(&name) {
                println!("MCP server '{name}' already configured.");
                return Ok(());
            }

            let transport_type = match transport.as_str() {
                "stdio" => crate::config::McpTransportType::Stdio,
                "http" => crate::config::McpTransportType::Http,
                "sse" => crate::config::McpTransportType::Sse,
                other => {
                    anyhow::bail!("Unknown transport type: {other}. Use stdio, http, or sse.");
                }
            };

            let server_config = crate::config::McpServerConfig {
                transport: transport_type,
                command,
                args,
                env: std::collections::HashMap::new(),
                url,
                headers: std::collections::HashMap::new(),
                timeout_secs: None,
                auto_restart: false,
            };

            cfg.mcp.enabled = true;
            cfg.mcp.servers.insert(name.clone(), server_config);
            cfg.save()?;
            println!("Added MCP server '{name}'. Restart agent to apply.");
        }
        crate::McpCommands::Remove { name } => {
            let mut cfg = Config::load_or_init()?;

            if cfg.mcp.servers.remove(&name).is_none() {
                println!("MCP server '{name}' not found.");
                return Ok(());
            }

            cfg.save()?;
            println!("Removed MCP server '{name}'. Restart agent to apply.");
        }
    }
    Ok(())
}
