use crate::config::Config;
use anyhow::Result;
use chrono::Utc;
use std::future::Future;
use std::path::PathBuf;
use tokio::task::JoinHandle;
use tokio::time::Duration;

const STATUS_FLUSH_SECONDS: u64 = 5;

pub async fn run(config: Config, host: String, port: u16) -> Result<()> {
    let initial_backoff = config.reliability.channel_initial_backoff_secs.max(1);
    let max_backoff = config
        .reliability
        .channel_max_backoff_secs
        .max(initial_backoff);

    crate::health::mark_component_ok("daemon");

    if config.heartbeat.enabled {
        let _ =
            crate::heartbeat::engine::HeartbeatEngine::ensure_heartbeat_file(&config.workspace_dir)
                .await;
    }

    let mut handles: Vec<JoinHandle<()>> = vec![spawn_state_writer(config.clone())];

    {
        let gateway_cfg = config.clone();
        let gateway_host = host.clone();
        handles.push(spawn_component_supervisor(
            "gateway",
            initial_backoff,
            max_backoff,
            move || {
                let cfg = gateway_cfg.clone();
                let host = gateway_host.clone();
                async move { crate::gateway::run_gateway(&host, port, cfg).await }
            },
        ));
    }

    {
        if has_supervised_channels(&config) {
            let channels_cfg = config.clone();
            handles.push(spawn_component_supervisor(
                "channels",
                initial_backoff,
                max_backoff,
                move || {
                    let cfg = channels_cfg.clone();
                    async move { crate::channels::start_channels(cfg).await }
                },
            ));
        } else {
            crate::health::mark_component_ok("channels");
            tracing::info!("No real-time channels configured; channel supervisor disabled");
        }
    }

    if config.heartbeat.enabled {
        let heartbeat_cfg = config.clone();
        handles.push(spawn_component_supervisor(
            "heartbeat",
            initial_backoff,
            max_backoff,
            move || {
                let cfg = heartbeat_cfg.clone();
                async move { Box::pin(run_heartbeat_worker(cfg)).await }
            },
        ));
    }

    if config.cron.enabled {
        let scheduler_cfg = config.clone();
        handles.push(spawn_component_supervisor(
            "scheduler",
            initial_backoff,
            max_backoff,
            move || {
                let cfg = scheduler_cfg.clone();
                async move { crate::cron::scheduler::run(cfg).await }
            },
        ));
    } else {
        crate::health::mark_component_ok("scheduler");
        tracing::info!("Cron disabled; scheduler supervisor not started");
    }

    // ── Event processor (external event sources → agent loop) ──
    if config.events.sources.is_empty() {
        crate::health::mark_component_ok("event_processor");
        tracing::info!("No event sources configured; event processor not started");
    } else {
        let events_cfg = config.clone();
        handles.push(spawn_component_supervisor(
            "event_processor",
            initial_backoff,
            max_backoff,
            move || {
                let cfg = events_cfg.clone();
                async move { run_event_processor(cfg).await }
            },
        ));
    }

    tracing::info!(backend = %config.observability.backend, "Observability observer active");

    println!("🧠 ZeroClaw daemon started");
    println!("   Gateway:  http://{host}:{port}");
    println!("   Components: gateway, channels, heartbeat, scheduler");
    println!("   Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;
    crate::health::mark_component_error("daemon", "shutdown requested");

    for handle in &handles {
        handle.abort();
    }
    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

pub fn state_file_path(config: &Config) -> PathBuf {
    config
        .config_path
        .parent()
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
        .join("daemon_state.json")
}

fn spawn_state_writer(config: Config) -> JoinHandle<()> {
    tokio::spawn(async move {
        let path = state_file_path(&config);
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        let mut interval = tokio::time::interval(Duration::from_secs(STATUS_FLUSH_SECONDS));
        loop {
            interval.tick().await;
            let mut json = crate::health::snapshot_json();
            if let Some(obj) = json.as_object_mut() {
                obj.insert(
                    "written_at".into(),
                    serde_json::json!(Utc::now().to_rfc3339()),
                );
            }
            let data = serde_json::to_vec_pretty(&json).unwrap_or_else(|_| b"{}".to_vec());
            let _ = tokio::fs::write(&path, data).await;
        }
    })
}

fn spawn_component_supervisor<F, Fut>(
    name: &'static str,
    initial_backoff_secs: u64,
    max_backoff_secs: u64,
    mut run_component: F,
) -> JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        let mut backoff = initial_backoff_secs.max(1);
        let max_backoff = max_backoff_secs.max(backoff);

        loop {
            crate::health::mark_component_ok(name);
            match run_component().await {
                Ok(()) => {
                    crate::health::mark_component_error(name, "component exited unexpectedly");
                    tracing::warn!("Daemon component '{name}' exited unexpectedly");
                    // Clean exit — reset backoff since the component ran successfully
                    backoff = initial_backoff_secs.max(1);
                }
                Err(e) => {
                    crate::health::mark_component_error(name, e.to_string());
                    tracing::error!("Daemon component '{name}' failed: {e}");
                }
            }

            crate::health::bump_component_restart(name);
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            // Double backoff AFTER sleeping so first error uses initial_backoff
            backoff = backoff.saturating_mul(2).min(max_backoff);
        }
    })
}

async fn run_heartbeat_worker(config: Config) -> Result<()> {
    let observer: std::sync::Arc<dyn crate::observability::Observer> =
        std::sync::Arc::from(crate::observability::create_observer(&config.observability));
    let engine = crate::heartbeat::engine::HeartbeatEngine::new(
        config.heartbeat.clone(),
        config.workspace_dir.clone(),
        observer,
    );

    let interval_mins = config.heartbeat.interval_minutes.max(5);
    let mut interval = tokio::time::interval(Duration::from_secs(u64::from(interval_mins) * 60));

    loop {
        interval.tick().await;

        let tasks = engine.collect_tasks().await?;
        if tasks.is_empty() {
            continue;
        }

        for task in tasks {
            let prompt = format!("[Heartbeat Task] {task}");
            let temp = config.default_temperature;
            if let Err(e) =
                crate::agent::run(config.clone(), Some(prompt), None, None, temp, vec![]).await
            {
                crate::health::mark_component_error("heartbeat", e.to_string());
                tracing::warn!("Heartbeat task failed: {e}");
            } else {
                crate::health::mark_component_ok("heartbeat");
            }
        }
    }
}

async fn run_event_processor(config: Config) -> Result<()> {
    let observer: std::sync::Arc<dyn crate::observability::Observer> =
        std::sync::Arc::from(crate::observability::create_observer(&config.observability));

    // Build provider, memory, tools — same as gateway/channels
    let provider: std::sync::Arc<dyn crate::providers::Provider> =
        std::sync::Arc::from(crate::providers::create_resilient_provider_with_options(
            config.default_provider.as_deref().unwrap_or("openrouter"),
            config.api_key.as_deref(),
            config.api_url.as_deref(),
            &config.reliability,
            &crate::providers::ProviderRuntimeOptions {
                auth_profile_override: None,
                zeroclaw_dir: config.config_path.parent().map(std::path::PathBuf::from),
                secrets_encrypt: config.secrets.encrypt,
            },
        )?);

    let mem: std::sync::Arc<dyn crate::memory::Memory> =
        std::sync::Arc::from(crate::memory::create_memory_with_storage(
            &config.memory,
            Some(&config.storage.provider.config),
            &config.workspace_dir,
            config.api_key.as_deref(),
        )?);

    let runtime: std::sync::Arc<dyn crate::runtime::RuntimeAdapter> =
        std::sync::Arc::from(crate::runtime::create_runtime(&config.runtime)?);
    let security = std::sync::Arc::new(crate::security::SecurityPolicy::from_config(
        &config.autonomy,
        &config.workspace_dir,
    ));

    let (composio_key, composio_entity_id) = if config.composio.enabled {
        (
            config.composio.api_key.as_deref(),
            Some(config.composio.entity_id.as_str()),
        )
    } else {
        (None, None)
    };

    let tools_registry = std::sync::Arc::new(crate::tools::all_tools_with_runtime(
        std::sync::Arc::new(config.clone()),
        &security,
        runtime,
        std::sync::Arc::clone(&mem),
        composio_key,
        composio_entity_id,
        &config.browser,
        &config.http_request,
        &config.workspace_dir,
        &config.agents,
        config.api_key.as_deref(),
        &config,
    ));

    let model = config
        .default_model
        .clone()
        .unwrap_or_else(|| "anthropic/claude-sonnet-4".into());

    let skills = crate::skills::load_skills(&config.workspace_dir);
    let tool_descs: Vec<(&str, &str)> = tools_registry
        .iter()
        .map(|t| (t.name(), t.description()))
        .collect();
    let native_tools = provider.supports_native_tools() && !tool_descs.is_empty();
    let bootstrap_max_chars = if config.agent.compact_context {
        Some(6000)
    } else {
        None
    };
    let mut system_prompt = crate::channels::build_system_prompt(
        &config.workspace_dir,
        &model,
        &tool_descs,
        &skills,
        Some(&config.identity),
        bootstrap_max_chars,
        native_tools,
    );
    if !native_tools {
        system_prompt.push_str(&crate::agent::loop_::build_tool_instructions(
            tools_registry.as_ref(),
            false,
        ));
    }

    let agent_context = std::sync::Arc::new(crate::gateway::WebhookAgentContext {
        provider,
        provider_name: config
            .default_provider
            .clone()
            .unwrap_or_else(|| "openrouter".to_string()),
        model,
        temperature: config.default_temperature,
        tools_registry,
        memory: mem,
        system_prompt,
        observer: observer.clone(),
        max_tool_iterations: if config.agent.max_tool_iterations > 0 {
            config.agent.max_tool_iterations
        } else {
            10
        },
        min_relevance_score: config.memory.min_relevance_score,
        auto_save: config.memory.auto_save,
    });

    // Build event sources from config
    let sources = build_event_sources(&config.events);
    let routes: Vec<crate::events::EventRoute> = config
        .events
        .routes
        .iter()
        .map(|r| crate::events::EventRoute {
            source: r.source.clone(),
            pattern: r.pattern.clone(),
            skill: r.skill.clone(),
            prompt_template: r.prompt_template.clone(),
        })
        .collect();

    let mut processor =
        crate::events::EventProcessor::new(sources, agent_context, routes, observer);

    processor.run().await
}

fn build_event_sources(
    config: &crate::config::EventsConfig,
) -> Vec<Box<dyn crate::events::EventSource>> {
    config
        .sources
        .iter()
        .filter_map(|src| match src.source_type.as_str() {
            #[cfg(feature = "amqp")]
            "amqp" => Some(
                Box::new(crate::events::amqp::AmqpEventSource::from_config(src))
                    as Box<dyn crate::events::EventSource>,
            ),
            other => {
                tracing::warn!("Unknown event source type: {other} (source: {})", src.name);
                None
            }
        })
        .collect()
}

fn has_supervised_channels(config: &Config) -> bool {
    config.channels_config.telegram.is_some()
        || config.channels_config.discord.is_some()
        || config.channels_config.slack.is_some()
        || config.channels_config.imessage.is_some()
        || config.channels_config.matrix.is_some()
        || config.channels_config.signal.is_some()
        || config.channels_config.whatsapp.is_some()
        || config.channels_config.email.is_some()
        || config.channels_config.irc.is_some()
        || config.channels_config.lark.is_some()
        || config.channels_config.dingtalk.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config(tmp: &TempDir) -> Config {
        let config = Config {
            workspace_dir: tmp.path().join("workspace"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        std::fs::create_dir_all(&config.workspace_dir).unwrap();
        config
    }

    #[test]
    fn state_file_path_uses_config_directory() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(&tmp);

        let path = state_file_path(&config);
        assert_eq!(path, tmp.path().join("daemon_state.json"));
    }

    #[tokio::test]
    async fn supervisor_marks_error_and_restart_on_failure() {
        let handle = spawn_component_supervisor("daemon-test-fail", 1, 1, || async {
            anyhow::bail!("boom")
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.abort();
        let _ = handle.await;

        let snapshot = crate::health::snapshot_json();
        let component = &snapshot["components"]["daemon-test-fail"];
        assert_eq!(component["status"], "error");
        assert!(component["restart_count"].as_u64().unwrap_or(0) >= 1);
        assert!(component["last_error"]
            .as_str()
            .unwrap_or("")
            .contains("boom"));
    }

    #[tokio::test]
    async fn supervisor_marks_unexpected_exit_as_error() {
        let handle = spawn_component_supervisor("daemon-test-exit", 1, 1, || async { Ok(()) });

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.abort();
        let _ = handle.await;

        let snapshot = crate::health::snapshot_json();
        let component = &snapshot["components"]["daemon-test-exit"];
        assert_eq!(component["status"], "error");
        assert!(component["restart_count"].as_u64().unwrap_or(0) >= 1);
        assert!(component["last_error"]
            .as_str()
            .unwrap_or("")
            .contains("component exited unexpectedly"));
    }

    #[test]
    fn detects_no_supervised_channels() {
        let config = Config::default();
        assert!(!has_supervised_channels(&config));
    }

    #[test]
    fn detects_supervised_channels_present() {
        let mut config = Config::default();
        config.channels_config.telegram = Some(crate::config::TelegramConfig {
            bot_token: "token".into(),
            allowed_users: vec![],
            stream_mode: crate::config::StreamMode::default(),
            draft_update_interval_ms: 1000,
            mention_only: false,
        });
        assert!(has_supervised_channels(&config));
    }

    #[test]
    fn detects_dingtalk_as_supervised_channel() {
        let mut config = Config::default();
        config.channels_config.dingtalk = Some(crate::config::schema::DingTalkConfig {
            client_id: "client_id".into(),
            client_secret: "client_secret".into(),
            allowed_users: vec!["*".into()],
        });
        assert!(has_supervised_channels(&config));
    }
}
