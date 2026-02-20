use crate::auth::openai_oauth::extract_account_id_from_jwt;
use crate::auth::AuthService;
use crate::providers::traits::{
    ChatMessage, ChatRequest as ProviderChatRequest, ChatResponse as ProviderChatResponse,
    Provider, ProviderCapabilities, ToolCall as ProviderToolCall,
};
use crate::providers::ProviderRuntimeOptions;
use crate::tools::ToolSpec;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

const CODEX_RESPONSES_URL: &str = "https://chatgpt.com/backend-api/codex/responses";
const DEFAULT_CODEX_INSTRUCTIONS: &str =
    "You are ZeroClaw, a concise and helpful coding assistant.";

pub struct OpenAiCodexProvider {
    auth: AuthService,
    auth_profile_override: Option<String>,
    client: Client,
}

#[derive(Debug, Serialize)]
struct ResponsesRequest {
    model: String,
    input: Vec<ResponsesInputItem>,
    instructions: String,
    store: bool,
    stream: bool,
    text: ResponsesTextOptions,
    reasoning: ResponsesReasoningOptions,
    include: Vec<String>,
    tool_choice: String,
    parallel_tool_calls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<ResponsesToolSpec>>,
}

#[derive(Debug, Serialize)]
struct ResponsesInput {
    role: String,
    content: Vec<ResponsesInputContent>,
}

#[derive(Debug, Serialize)]
struct ResponsesInputContent {
    #[serde(rename = "type")]
    kind: String,
    text: String,
}

#[derive(Debug, Serialize)]
struct ResponsesTextOptions {
    verbosity: String,
}

#[derive(Debug, Serialize)]
struct ResponsesReasoningOptions {
    effort: String,
    summary: String,
}

#[derive(Debug, Serialize)]
struct ResponsesToolSpec {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ResponsesFunctionCallInput {
    #[serde(rename = "type")]
    kind: String,
    call_id: String,
    name: String,
    arguments: String,
}

#[derive(Debug, Serialize)]
struct ResponsesFunctionCallOutput {
    #[serde(rename = "type")]
    kind: String,
    call_id: String,
    output: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ResponsesInputItem {
    Message(ResponsesInput),
    FunctionCall(ResponsesFunctionCallInput),
    FunctionCallOutput(ResponsesFunctionCallOutput),
}

#[derive(Debug, Deserialize)]
struct ResponsesResponse {
    #[serde(default)]
    output: Vec<ResponsesOutput>,
    #[serde(default)]
    output_text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResponsesOutput {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    content: Vec<ResponsesContent>,
    #[serde(default)]
    call_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResponsesContent {
    #[serde(rename = "type")]
    kind: Option<String>,
    text: Option<String>,
}

impl OpenAiCodexProvider {
    pub fn new(options: &ProviderRuntimeOptions) -> Self {
        let state_dir = options
            .zeroclaw_dir
            .clone()
            .unwrap_or_else(default_zeroclaw_dir);
        let auth = AuthService::new(&state_dir, options.secrets_encrypt);

        Self {
            auth,
            auth_profile_override: options.auth_profile_override.clone(),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }
}

fn default_zeroclaw_dir() -> PathBuf {
    directories::UserDirs::new().map_or_else(
        || PathBuf::from(".zeroclaw"),
        |dirs| dirs.home_dir().join(".zeroclaw"),
    )
}

fn first_nonempty(text: Option<&str>) -> Option<String> {
    text.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn resolve_instructions(system_prompt: Option<&str>) -> String {
    first_nonempty(system_prompt).unwrap_or_else(|| DEFAULT_CODEX_INSTRUCTIONS.to_string())
}

fn normalize_model_id(model: &str) -> &str {
    model.rsplit('/').next().unwrap_or(model)
}

fn clamp_reasoning_effort(model: &str, effort: &str) -> String {
    let id = normalize_model_id(model);
    if (id.starts_with("gpt-5.2") || id.starts_with("gpt-5.3")) && effort == "minimal" {
        return "low".to_string();
    }
    if id == "gpt-5.1" && effort == "xhigh" {
        return "high".to_string();
    }
    if id == "gpt-5.1-codex-mini" {
        return if effort == "high" || effort == "xhigh" {
            "high".to_string()
        } else {
            "medium".to_string()
        };
    }
    effort.to_string()
}

fn resolve_reasoning_effort(model_id: &str) -> String {
    let raw = std::env::var("ZEROCLAW_CODEX_REASONING_EFFORT")
        .ok()
        .and_then(|value| first_nonempty(Some(&value)))
        .unwrap_or_else(|| "xhigh".to_string())
        .to_ascii_lowercase();
    clamp_reasoning_effort(model_id, &raw)
}

fn nonempty_preserve(text: Option<&str>) -> Option<String> {
    text.and_then(|value| {
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn extract_responses_text(response: &ResponsesResponse) -> Option<String> {
    if let Some(text) = first_nonempty(response.output_text.as_deref()) {
        return Some(text);
    }

    for item in &response.output {
        for content in &item.content {
            if content.kind.as_deref() == Some("output_text") {
                if let Some(text) = first_nonempty(content.text.as_deref()) {
                    return Some(text);
                }
            }
        }
    }

    for item in &response.output {
        for content in &item.content {
            if let Some(text) = first_nonempty(content.text.as_deref()) {
                return Some(text);
            }
        }
    }

    None
}

fn extract_stream_event_text(event: &Value, saw_delta: bool) -> Option<String> {
    let event_type = event.get("type").and_then(Value::as_str);
    match event_type {
        Some("response.output_text.delta") => {
            nonempty_preserve(event.get("delta").and_then(Value::as_str))
        }
        Some("response.output_text.done") if !saw_delta => {
            nonempty_preserve(event.get("text").and_then(Value::as_str))
        }
        Some("response.completed" | "response.done") => event
            .get("response")
            .and_then(|value| serde_json::from_value::<ResponsesResponse>(value.clone()).ok())
            .and_then(|response| extract_responses_text(&response)),
        _ => None,
    }
}

fn parse_sse_text(body: &str) -> anyhow::Result<Option<String>> {
    let mut saw_delta = false;
    let mut delta_accumulator = String::new();
    let mut fallback_text = None;
    let mut buffer = body.to_string();

    let mut process_event = |event: Value| -> anyhow::Result<()> {
        if let Some(message) = extract_stream_error_message(&event) {
            return Err(anyhow::anyhow!("OpenAI Codex stream error: {message}"));
        }
        if let Some(text) = extract_stream_event_text(&event, saw_delta) {
            let event_type = event.get("type").and_then(Value::as_str);
            if event_type == Some("response.output_text.delta") {
                saw_delta = true;
                delta_accumulator.push_str(&text);
            } else if fallback_text.is_none() {
                fallback_text = Some(text);
            }
        }
        Ok(())
    };

    let mut process_chunk = |chunk: &str| -> anyhow::Result<()> {
        let data_lines: Vec<String> = chunk
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|line| line.trim().to_string())
            .collect();
        if data_lines.is_empty() {
            return Ok(());
        }

        let joined = data_lines.join("\n");
        let trimmed = joined.trim();
        if trimmed.is_empty() || trimmed == "[DONE]" {
            return Ok(());
        }

        if let Ok(event) = serde_json::from_str::<Value>(trimmed) {
            return process_event(event);
        }

        for line in data_lines {
            let line = line.trim();
            if line.is_empty() || line == "[DONE]" {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<Value>(line) {
                process_event(event)?;
            }
        }

        Ok(())
    };

    loop {
        let Some(idx) = buffer.find("\n\n") else {
            break;
        };

        let chunk = buffer[..idx].to_string();
        buffer = buffer[idx + 2..].to_string();
        process_chunk(&chunk)?;
    }

    if !buffer.trim().is_empty() {
        process_chunk(&buffer)?;
    }

    if saw_delta {
        return Ok(nonempty_preserve(Some(&delta_accumulator)));
    }

    Ok(fallback_text)
}

fn extract_stream_error_message(event: &Value) -> Option<String> {
    let event_type = event.get("type").and_then(Value::as_str);

    if event_type == Some("error") {
        return first_nonempty(
            event
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| event.get("code").and_then(Value::as_str))
                .or_else(|| {
                    event
                        .get("error")
                        .and_then(|error| error.get("message"))
                        .and_then(Value::as_str)
                }),
        );
    }

    if event_type == Some("response.failed") {
        return first_nonempty(
            event
                .get("response")
                .and_then(|response| response.get("error"))
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str),
        );
    }

    None
}

fn convert_tools_to_responses(tools: Option<&[ToolSpec]>) -> Option<Vec<ResponsesToolSpec>> {
    tools.map(|items| {
        items
            .iter()
            .map(|tool| ResponsesToolSpec {
                kind: "function".to_string(),
                name: tool.name.clone(),
                description: tool.description.clone(),
                parameters: tool.parameters.clone(),
            })
            .collect()
    })
}

fn convert_messages_to_responses(messages: &[ChatMessage]) -> Vec<ResponsesInputItem> {
    let mut items = Vec::new();

    for msg in messages {
        match msg.role.as_str() {
            "system" => {
                // System messages go to `instructions` field, skip from input.
            }
            "user" => {
                items.push(ResponsesInputItem::Message(ResponsesInput {
                    role: "user".to_string(),
                    content: vec![ResponsesInputContent {
                        kind: "input_text".to_string(),
                        text: msg.content.clone(),
                    }],
                }));
            }
            "assistant" => {
                // The agent loop stores assistant messages with tool calls as JSON:
                // {"content": "text or null", "tool_calls": [{"id": "...", "name": "...", "arguments": "..."}]}
                if let Ok(value) = serde_json::from_str::<Value>(&msg.content) {
                    if let Some(tool_calls_value) = value.get("tool_calls") {
                        if let Ok(parsed_calls) = serde_json::from_value::<Vec<ProviderToolCall>>(
                            tool_calls_value.clone(),
                        ) {
                            // Emit assistant text as a message if present.
                            if let Some(text) = value
                                .get("content")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                            {
                                items.push(ResponsesInputItem::Message(ResponsesInput {
                                    role: "assistant".to_string(),
                                    content: vec![ResponsesInputContent {
                                        kind: "output_text".to_string(),
                                        text: text.to_string(),
                                    }],
                                }));
                            }
                            // Emit each tool call as a function_call input item.
                            for tc in parsed_calls {
                                items.push(ResponsesInputItem::FunctionCall(
                                    ResponsesFunctionCallInput {
                                        kind: "function_call".to_string(),
                                        call_id: tc.id,
                                        name: tc.name,
                                        arguments: tc.arguments,
                                    },
                                ));
                            }
                            continue;
                        }
                    }
                }
                // Plain assistant message (no tool calls).
                items.push(ResponsesInputItem::Message(ResponsesInput {
                    role: "assistant".to_string(),
                    content: vec![ResponsesInputContent {
                        kind: "output_text".to_string(),
                        text: msg.content.clone(),
                    }],
                }));
            }
            "tool" => {
                // Tool result messages from the agent loop:
                // {"tool_call_id": "call_123", "content": "result text"}
                if let Ok(value) = serde_json::from_str::<Value>(&msg.content) {
                    let call_id = value
                        .get("tool_call_id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let output = value
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    items.push(ResponsesInputItem::FunctionCallOutput(
                        ResponsesFunctionCallOutput {
                            kind: "function_call_output".to_string(),
                            call_id,
                            output,
                        },
                    ));
                }
            }
            _ => {
                // Unknown role — pass as user message to avoid dropping content.
                items.push(ResponsesInputItem::Message(ResponsesInput {
                    role: "user".to_string(),
                    content: vec![ResponsesInputContent {
                        kind: "input_text".to_string(),
                        text: msg.content.clone(),
                    }],
                }));
            }
        }
    }

    items
}

fn extract_responses_tool_calls(response: &ResponsesResponse) -> Vec<ProviderToolCall> {
    response
        .output
        .iter()
        .filter(|item| item.kind.as_deref() == Some("function_call"))
        .filter_map(|item| {
            let call_id = item.call_id.as_ref()?;
            let name = item.name.as_ref()?;
            let arguments = item.arguments.as_ref()?;
            Some(ProviderToolCall {
                id: call_id.clone(),
                name: name.clone(),
                arguments: arguments.clone(),
            })
        })
        .collect()
}

/// Outcome of processing a single SSE event in the full (text + tool calls) path.
enum StreamEventAction {
    /// A text delta to accumulate.
    TextDelta(String),
    /// A complete text snapshot (from `response.output_text.done` or `response.completed`).
    TextDone(String),
    /// A new function call was announced — create a partial entry.
    FunctionCallAdded { call_id: String, name: String },
    /// An arguments delta for a function call.
    FunctionCallArgsDelta { call_id: String, delta: String },
    /// Arguments for a function call are complete.
    FunctionCallArgsDone { call_id: String, arguments: String },
    /// The authoritative completed response with tool calls.
    Completed {
        text: Option<String>,
        tool_calls: Vec<ProviderToolCall>,
    },
    /// Nothing actionable.
    None,
}

fn classify_stream_event(event: &Value, saw_delta: bool) -> StreamEventAction {
    let event_type = event.get("type").and_then(Value::as_str);
    match event_type {
        Some("response.output_text.delta") => {
            if let Some(text) = nonempty_preserve(event.get("delta").and_then(Value::as_str)) {
                StreamEventAction::TextDelta(text)
            } else {
                StreamEventAction::None
            }
        }
        Some("response.output_text.done") if !saw_delta => {
            if let Some(text) = nonempty_preserve(event.get("text").and_then(Value::as_str)) {
                StreamEventAction::TextDone(text)
            } else {
                StreamEventAction::None
            }
        }
        // Incremental tool call events from the Codex Responses API.
        Some("response.output_item.added") => {
            let item = event.get("item").unwrap_or(event);
            if item.get("type").and_then(Value::as_str) == Some("function_call") {
                let call_id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if call_id.is_empty() {
                    StreamEventAction::None
                } else {
                    StreamEventAction::FunctionCallAdded { call_id, name }
                }
            } else {
                StreamEventAction::None
            }
        }
        Some("response.function_call_arguments.delta") => {
            let call_id = event
                .get("call_id")
                .or_else(|| event.get("item_id"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let delta = event
                .get("delta")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if call_id.is_empty() {
                StreamEventAction::None
            } else {
                StreamEventAction::FunctionCallArgsDelta { call_id, delta }
            }
        }
        Some("response.function_call_arguments.done") => {
            let call_id = event
                .get("call_id")
                .or_else(|| event.get("item_id"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let arguments = event
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if call_id.is_empty() {
                StreamEventAction::None
            } else {
                StreamEventAction::FunctionCallArgsDone { call_id, arguments }
            }
        }
        Some("response.completed" | "response.done") => {
            if let Some(resp) = event
                .get("response")
                .and_then(|v| serde_json::from_value::<ResponsesResponse>(v.clone()).ok())
            {
                let text = extract_responses_text(&resp);
                let tool_calls = extract_responses_tool_calls(&resp);
                StreamEventAction::Completed { text, tool_calls }
            } else {
                StreamEventAction::None
            }
        }
        _ => StreamEventAction::None,
    }
}

/// Partial tool call being accumulated from incremental SSE events.
#[derive(Debug, Clone)]
struct PartialToolCall {
    call_id: String,
    name: String,
    arguments: String,
    /// Insertion order so we can emit calls in the order the API announced them.
    order: usize,
}

fn parse_sse_full(body: &str) -> anyhow::Result<(Option<String>, Vec<ProviderToolCall>)> {
    let mut saw_delta = false;
    let mut delta_accumulator = String::new();
    let mut fallback_text = None;
    // Authoritative tool calls from response.completed (if present).
    let mut completed_tool_calls: Option<Vec<ProviderToolCall>> = None;
    // Incremental tool call accumulator keyed by call_id.
    let mut partial_calls: HashMap<String, PartialToolCall> = HashMap::new();
    let mut partial_order: usize = 0;
    let mut event_types_seen: Vec<String> = Vec::new();
    let mut buffer = body.to_string();

    let mut process_event = |event: Value| -> anyhow::Result<()> {
        if let Some(message) = extract_stream_error_message(&event) {
            return Err(anyhow::anyhow!("OpenAI Codex stream error: {message}"));
        }
        if let Some(et) = event.get("type").and_then(Value::as_str) {
            event_types_seen.push(et.to_string());
        }
        match classify_stream_event(&event, saw_delta) {
            StreamEventAction::TextDelta(text) => {
                saw_delta = true;
                delta_accumulator.push_str(&text);
            }
            StreamEventAction::TextDone(text) => {
                if fallback_text.is_none() {
                    fallback_text = Some(text);
                }
            }
            StreamEventAction::FunctionCallAdded { call_id, name } => {
                partial_calls.entry(call_id.clone()).or_insert_with(|| {
                    let order = partial_order;
                    partial_order += 1;
                    PartialToolCall {
                        call_id,
                        name,
                        arguments: String::new(),
                        order,
                    }
                });
            }
            StreamEventAction::FunctionCallArgsDelta { call_id, delta } => {
                if let Some(entry) = partial_calls.get_mut(&call_id) {
                    entry.arguments.push_str(&delta);
                }
            }
            StreamEventAction::FunctionCallArgsDone { call_id, arguments } => {
                if let Some(entry) = partial_calls.get_mut(&call_id) {
                    // Use the final arguments from the done event (authoritative).
                    if !arguments.is_empty() {
                        entry.arguments = arguments;
                    }
                }
            }
            StreamEventAction::Completed { text, tool_calls } => {
                if !tool_calls.is_empty() {
                    completed_tool_calls = Some(tool_calls);
                }
                if let Some(text) = text {
                    if fallback_text.is_none() {
                        fallback_text = Some(text);
                    }
                }
            }
            StreamEventAction::None => {}
        }
        Ok(())
    };

    let mut process_chunk = |chunk: &str| -> anyhow::Result<()> {
        let data_lines: Vec<String> = chunk
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|line| line.trim().to_string())
            .collect();
        if data_lines.is_empty() {
            return Ok(());
        }

        let joined = data_lines.join("\n");
        let trimmed = joined.trim();
        if trimmed.is_empty() || trimmed == "[DONE]" {
            return Ok(());
        }

        if let Ok(event) = serde_json::from_str::<Value>(trimmed) {
            return process_event(event);
        }

        for line in data_lines {
            let line = line.trim();
            if line.is_empty() || line == "[DONE]" {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<Value>(line) {
                process_event(event)?;
            }
        }

        Ok(())
    };

    loop {
        let Some(idx) = buffer.find("\n\n") else {
            break;
        };
        let chunk = buffer[..idx].to_string();
        buffer = buffer[idx + 2..].to_string();
        process_chunk(&chunk)?;
    }

    if !buffer.trim().is_empty() {
        process_chunk(&buffer)?;
    }

    let text = if saw_delta {
        nonempty_preserve(Some(&delta_accumulator))
    } else {
        fallback_text
    };

    // Prefer authoritative completed tool calls; fall back to incrementally accumulated ones.
    let tool_calls = if let Some(calls) = completed_tool_calls {
        calls
    } else if !partial_calls.is_empty() {
        let mut calls: Vec<PartialToolCall> = partial_calls.into_values().collect();
        calls.sort_by_key(|c| c.order);
        calls
            .into_iter()
            .filter(|c| !c.name.is_empty())
            .map(|c| ProviderToolCall {
                id: c.call_id,
                name: c.name,
                arguments: c.arguments,
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok((text, tool_calls))
}

async fn decode_responses_body_full(
    response: reqwest::Response,
) -> anyhow::Result<(Option<String>, Vec<ProviderToolCall>)> {
    let body = response.text().await?;

    let (text, tool_calls) = parse_sse_full(&body)?;
    if text.is_some() || !tool_calls.is_empty() {
        return Ok((text, tool_calls));
    }

    let body_trimmed = body.trim_start();
    let looks_like_sse = body_trimmed.starts_with("event:") || body_trimmed.starts_with("data:");
    if looks_like_sse {
        // Collect event types for diagnostics.
        let event_types: Vec<String> = body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
            .filter_map(|v| v.get("type").and_then(Value::as_str).map(str::to_string))
            .collect();
        return Err(anyhow::anyhow!(
            "No response from OpenAI Codex stream (body_len={}, event_types={:?}): {}",
            body.len(),
            event_types,
            super::sanitize_api_error(&body)
        ));
    }

    let parsed: ResponsesResponse = serde_json::from_str(&body).map_err(|err| {
        anyhow::anyhow!(
            "OpenAI Codex JSON parse failed: {err}. Payload: {}",
            super::sanitize_api_error(&body)
        )
    })?;
    let text = extract_responses_text(&parsed);
    let tool_calls = extract_responses_tool_calls(&parsed);
    if text.is_some() || !tool_calls.is_empty() {
        return Ok((text, tool_calls));
    }
    Err(anyhow::anyhow!("No response from OpenAI Codex"))
}

async fn decode_responses_body(response: reqwest::Response) -> anyhow::Result<String> {
    let body = response.text().await?;

    if let Some(text) = parse_sse_text(&body)? {
        return Ok(text);
    }

    let body_trimmed = body.trim_start();
    let looks_like_sse = body_trimmed.starts_with("event:") || body_trimmed.starts_with("data:");
    if looks_like_sse {
        return Err(anyhow::anyhow!(
            "No response from OpenAI Codex stream payload: {}",
            super::sanitize_api_error(&body)
        ));
    }

    let parsed: ResponsesResponse = serde_json::from_str(&body).map_err(|err| {
        anyhow::anyhow!(
            "OpenAI Codex JSON parse failed: {err}. Payload: {}",
            super::sanitize_api_error(&body)
        )
    })?;
    extract_responses_text(&parsed).ok_or_else(|| anyhow::anyhow!("No response from OpenAI Codex"))
}

#[async_trait]
impl Provider for OpenAiCodexProvider {
    async fn chat_with_system(
        &self,
        system_prompt: Option<&str>,
        message: &str,
        model: &str,
        _temperature: f64,
    ) -> anyhow::Result<String> {
        let profile = self
            .auth
            .get_profile("openai-codex", self.auth_profile_override.as_deref())?;
        let access_token = self
            .auth
            .get_valid_openai_access_token(self.auth_profile_override.as_deref())
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "OpenAI Codex auth profile not found. Run `zeroclaw auth login --provider openai-codex`."
                )
            })?;
        let account_id = profile
            .and_then(|profile| profile.account_id)
            .or_else(|| extract_account_id_from_jwt(&access_token))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "OpenAI Codex account id not found in auth profile/token. Run `zeroclaw auth login --provider openai-codex` again."
                )
            })?;
        let normalized_model = normalize_model_id(model);

        let request = ResponsesRequest {
            model: normalized_model.to_string(),
            input: vec![ResponsesInputItem::Message(ResponsesInput {
                role: "user".to_string(),
                content: vec![ResponsesInputContent {
                    kind: "input_text".to_string(),
                    text: message.to_string(),
                }],
            })],
            instructions: resolve_instructions(system_prompt),
            store: false,
            stream: true,
            text: ResponsesTextOptions {
                verbosity: "medium".to_string(),
            },
            reasoning: ResponsesReasoningOptions {
                effort: resolve_reasoning_effort(normalized_model),
                summary: "auto".to_string(),
            },
            include: vec!["reasoning.encrypted_content".to_string()],
            tool_choice: "auto".to_string(),
            parallel_tool_calls: true,
            tools: None,
        };

        let response = self
            .client
            .post(CODEX_RESPONSES_URL)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("chatgpt-account-id", account_id)
            .header("OpenAI-Beta", "responses=experimental")
            .header("originator", "pi")
            .header("accept", "text/event-stream")
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(super::api_error("OpenAI Codex", response).await);
        }

        decode_responses_body(response).await
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            native_tool_calling: true,
        }
    }

    async fn chat(
        &self,
        request: ProviderChatRequest<'_>,
        model: &str,
        _temperature: f64,
    ) -> anyhow::Result<ProviderChatResponse> {
        let profile = self
            .auth
            .get_profile("openai-codex", self.auth_profile_override.as_deref())?;
        let access_token = self
            .auth
            .get_valid_openai_access_token(self.auth_profile_override.as_deref())
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "OpenAI Codex auth profile not found. Run `zeroclaw auth login --provider openai-codex`."
                )
            })?;
        let account_id = profile
            .and_then(|p| p.account_id)
            .or_else(|| extract_account_id_from_jwt(&access_token))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "OpenAI Codex account id not found in auth profile/token. Run `zeroclaw auth login --provider openai-codex` again."
                )
            })?;
        let normalized_model = normalize_model_id(model);

        // Extract system prompt from messages for the `instructions` field.
        let system_prompt = request
            .messages
            .iter()
            .find(|m| m.role == "system")
            .map(|m| m.content.as_str());

        let input = convert_messages_to_responses(request.messages);
        let tools = convert_tools_to_responses(request.tools);

        let api_request = ResponsesRequest {
            model: normalized_model.to_string(),
            input,
            instructions: resolve_instructions(system_prompt),
            store: false,
            stream: true,
            text: ResponsesTextOptions {
                verbosity: "medium".to_string(),
            },
            reasoning: ResponsesReasoningOptions {
                effort: resolve_reasoning_effort(normalized_model),
                summary: "auto".to_string(),
            },
            include: vec!["reasoning.encrypted_content".to_string()],
            tool_choice: "auto".to_string(),
            parallel_tool_calls: true,
            tools,
        };

        let response = self
            .client
            .post(CODEX_RESPONSES_URL)
            .header("Authorization", format!("Bearer {access_token}"))
            .header("chatgpt-account-id", &account_id)
            .header("OpenAI-Beta", "responses=experimental")
            .header("originator", "pi")
            .header("accept", "text/event-stream")
            .header("Content-Type", "application/json")
            .json(&api_request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(super::api_error("OpenAI Codex", response).await);
        }

        let (text, tool_calls) = decode_responses_body_full(response).await?;
        Ok(ProviderChatResponse {
            text,
            tool_calls,
            reasoning_content: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_output_text_first() {
        let response = ResponsesResponse {
            output: vec![],
            output_text: Some("hello".into()),
        };
        assert_eq!(extract_responses_text(&response).as_deref(), Some("hello"));
    }

    #[test]
    fn extracts_nested_output_text() {
        let response = ResponsesResponse {
            output: vec![ResponsesOutput {
                kind: Some("message".into()),
                content: vec![ResponsesContent {
                    kind: Some("output_text".into()),
                    text: Some("nested".into()),
                }],
                call_id: None,
                name: None,
                arguments: None,
            }],
            output_text: None,
        };
        assert_eq!(extract_responses_text(&response).as_deref(), Some("nested"));
    }

    #[test]
    fn default_state_dir_is_non_empty() {
        let path = default_zeroclaw_dir();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn resolve_instructions_uses_default_when_missing() {
        assert_eq!(
            resolve_instructions(None),
            DEFAULT_CODEX_INSTRUCTIONS.to_string()
        );
    }

    #[test]
    fn resolve_instructions_uses_default_when_blank() {
        assert_eq!(
            resolve_instructions(Some("   ")),
            DEFAULT_CODEX_INSTRUCTIONS.to_string()
        );
    }

    #[test]
    fn resolve_instructions_uses_system_prompt_when_present() {
        assert_eq!(
            resolve_instructions(Some("Be strict")),
            "Be strict".to_string()
        );
    }

    #[test]
    fn clamp_reasoning_effort_adjusts_known_models() {
        assert_eq!(
            clamp_reasoning_effort("gpt-5.3-codex", "minimal"),
            "low".to_string()
        );
        assert_eq!(
            clamp_reasoning_effort("gpt-5.1", "xhigh"),
            "high".to_string()
        );
        assert_eq!(
            clamp_reasoning_effort("gpt-5.1-codex-mini", "low"),
            "medium".to_string()
        );
        assert_eq!(
            clamp_reasoning_effort("gpt-5.1-codex-mini", "xhigh"),
            "high".to_string()
        );
        assert_eq!(
            clamp_reasoning_effort("gpt-5.3-codex", "xhigh"),
            "xhigh".to_string()
        );
    }

    #[test]
    fn parse_sse_text_reads_output_text_delta() {
        let payload = r#"data: {"type":"response.created","response":{"id":"resp_123"}}

data: {"type":"response.output_text.delta","delta":"Hello"}
data: {"type":"response.output_text.delta","delta":" world"}
data: {"type":"response.completed","response":{"output_text":"Hello world"}}
data: [DONE]
"#;

        assert_eq!(
            parse_sse_text(payload).unwrap().as_deref(),
            Some("Hello world")
        );
    }

    #[test]
    fn parse_sse_text_falls_back_to_completed_response() {
        let payload = r#"data: {"type":"response.completed","response":{"output_text":"Done"}}
data: [DONE]
"#;

        assert_eq!(parse_sse_text(payload).unwrap().as_deref(), Some("Done"));
    }

    #[test]
    fn convert_tools_to_responses_maps_fields() {
        let tools = vec![ToolSpec {
            name: "shell".to_string(),
            description: "Execute commands".to_string(),
            parameters: serde_json::json!({"type": "object", "properties": {"cmd": {"type": "string"}}}),
        }];
        let result = convert_tools_to_responses(Some(&tools)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, "function");
        assert_eq!(result[0].name, "shell");
        assert_eq!(result[0].description, "Execute commands");
        assert!(result[0].parameters.get("properties").is_some());
    }

    #[test]
    fn convert_tools_to_responses_none_for_none() {
        assert!(convert_tools_to_responses(None).is_none());
    }

    #[test]
    fn convert_messages_skips_system() {
        let messages = vec![
            ChatMessage::system("You are helpful"),
            ChatMessage::user("Hello"),
        ];
        let items = convert_messages_to_responses(&messages);
        assert_eq!(items.len(), 1);
        // Should be the user message, not system.
        let json = serde_json::to_value(&items[0]).unwrap();
        assert_eq!(json["role"], "user");
    }

    #[test]
    fn convert_messages_handles_user() {
        let messages = vec![ChatMessage::user("What is Rust?")];
        let items = convert_messages_to_responses(&messages);
        assert_eq!(items.len(), 1);
        let json = serde_json::to_value(&items[0]).unwrap();
        assert_eq!(json["role"], "user");
        assert_eq!(json["content"][0]["type"], "input_text");
        assert_eq!(json["content"][0]["text"], "What is Rust?");
    }

    #[test]
    fn convert_messages_handles_assistant_with_tool_calls() {
        let assistant_content = serde_json::json!({
            "content": "Let me check",
            "tool_calls": [
                {"id": "call_abc", "name": "shell", "arguments": "{\"cmd\":\"ls\"}"}
            ]
        })
        .to_string();
        let messages = vec![ChatMessage::assistant(assistant_content)];
        let items = convert_messages_to_responses(&messages);

        // Should produce: 1 assistant text message + 1 function call item.
        assert_eq!(items.len(), 2);

        let text_json = serde_json::to_value(&items[0]).unwrap();
        assert_eq!(text_json["role"], "assistant");
        assert_eq!(text_json["content"][0]["text"], "Let me check");

        let call_json = serde_json::to_value(&items[1]).unwrap();
        assert_eq!(call_json["type"], "function_call");
        assert_eq!(call_json["call_id"], "call_abc");
        assert_eq!(call_json["name"], "shell");
    }

    #[test]
    fn convert_messages_handles_assistant_with_null_content() {
        let assistant_content = serde_json::json!({
            "content": null,
            "tool_calls": [
                {"id": "call_1", "name": "file_read", "arguments": "{}"}
            ]
        })
        .to_string();
        let messages = vec![ChatMessage::assistant(assistant_content)];
        let items = convert_messages_to_responses(&messages);

        // Only the function call, no text message (content was null).
        assert_eq!(items.len(), 1);
        let json = serde_json::to_value(&items[0]).unwrap();
        assert_eq!(json["type"], "function_call");
    }

    #[test]
    fn convert_messages_handles_tool_results() {
        let tool_content = serde_json::json!({
            "tool_call_id": "call_abc",
            "content": "file contents here"
        })
        .to_string();
        let messages = vec![ChatMessage::tool(tool_content)];
        let items = convert_messages_to_responses(&messages);
        assert_eq!(items.len(), 1);
        let json = serde_json::to_value(&items[0]).unwrap();
        assert_eq!(json["type"], "function_call_output");
        assert_eq!(json["call_id"], "call_abc");
        assert_eq!(json["output"], "file contents here");
    }

    #[test]
    fn convert_messages_full_conversation() {
        let messages = vec![
            ChatMessage::system("Be helpful"),
            ChatMessage::user("List files"),
            ChatMessage::assistant(
                serde_json::json!({
                    "content": null,
                    "tool_calls": [{"id": "call_1", "name": "shell", "arguments": "{\"cmd\":\"ls\"}"}]
                })
                .to_string(),
            ),
            ChatMessage::tool(
                serde_json::json!({"tool_call_id": "call_1", "content": "file1.txt\nfile2.txt"})
                    .to_string(),
            ),
        ];
        let items = convert_messages_to_responses(&messages);

        // system skipped, user=1, function_call=1, function_call_output=1 => 3
        assert_eq!(items.len(), 3);

        let json0 = serde_json::to_value(&items[0]).unwrap();
        assert_eq!(json0["role"], "user");

        let json1 = serde_json::to_value(&items[1]).unwrap();
        assert_eq!(json1["type"], "function_call");

        let json2 = serde_json::to_value(&items[2]).unwrap();
        assert_eq!(json2["type"], "function_call_output");
    }

    #[test]
    fn extract_responses_tool_calls_parses_function_calls() {
        let response = ResponsesResponse {
            output: vec![
                ResponsesOutput {
                    kind: Some("message".into()),
                    content: vec![ResponsesContent {
                        kind: Some("output_text".into()),
                        text: Some("I'll check".into()),
                    }],
                    call_id: None,
                    name: None,
                    arguments: None,
                },
                ResponsesOutput {
                    kind: Some("function_call".into()),
                    content: vec![],
                    call_id: Some("call_xyz".into()),
                    name: Some("shell".into()),
                    arguments: Some(r#"{"cmd":"ls"}"#.into()),
                },
            ],
            output_text: Some("I'll check".into()),
        };

        let calls = extract_responses_tool_calls(&response);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_xyz");
        assert_eq!(calls[0].name, "shell");
        assert_eq!(calls[0].arguments, r#"{"cmd":"ls"}"#);
    }

    #[test]
    fn responses_input_item_serializes_correctly() {
        let message = ResponsesInputItem::Message(ResponsesInput {
            role: "user".to_string(),
            content: vec![ResponsesInputContent {
                kind: "input_text".to_string(),
                text: "hello".to_string(),
            }],
        });
        let json = serde_json::to_value(&message).unwrap();
        assert_eq!(json["role"], "user");
        assert_eq!(json["content"][0]["type"], "input_text");

        let call = ResponsesInputItem::FunctionCall(ResponsesFunctionCallInput {
            kind: "function_call".to_string(),
            call_id: "call_1".to_string(),
            name: "shell".to_string(),
            arguments: "{}".to_string(),
        });
        let json = serde_json::to_value(&call).unwrap();
        assert_eq!(json["type"], "function_call");
        assert_eq!(json["call_id"], "call_1");
        assert!(json.get("role").is_none());

        let output = ResponsesInputItem::FunctionCallOutput(ResponsesFunctionCallOutput {
            kind: "function_call_output".to_string(),
            call_id: "call_1".to_string(),
            output: "result".to_string(),
        });
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["type"], "function_call_output");
        assert_eq!(json["output"], "result");
    }

    #[test]
    fn parse_sse_full_response_with_tool_calls() {
        let payload = format!(
            "data: {}\n\ndata: [DONE]\n",
            serde_json::json!({
                "type": "response.completed",
                "response": {
                    "output": [
                        {
                            "type": "message",
                            "content": [{"type": "output_text", "text": "Let me check"}]
                        },
                        {
                            "type": "function_call",
                            "call_id": "call_99",
                            "name": "file_read",
                            "arguments": "{\"path\":\"test.rs\"}"
                        }
                    ],
                    "output_text": "Let me check"
                }
            })
        );

        let (text, tool_calls) = parse_sse_full(&payload).unwrap();
        assert_eq!(text.as_deref(), Some("Let me check"));
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].id, "call_99");
        assert_eq!(tool_calls[0].name, "file_read");
    }

    #[test]
    fn parse_sse_full_incremental_tool_calls_without_completed() {
        // Simulates a stream where tool calls arrive incrementally but
        // response.completed is absent (e.g., truncated stream).
        let payload = [
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.output_item.added",
                    "item": {
                        "type": "function_call",
                        "call_id": "call_inc_1",
                        "name": "shell"
                    }
                })
            ),
            String::new(), // blank line = SSE separator
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.function_call_arguments.delta",
                    "call_id": "call_inc_1",
                    "delta": "{\"cmd\":"
                })
            ),
            String::new(),
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.function_call_arguments.delta",
                    "call_id": "call_inc_1",
                    "delta": "\"ls\"}"
                })
            ),
            String::new(),
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.function_call_arguments.done",
                    "call_id": "call_inc_1",
                    "arguments": "{\"cmd\":\"ls\"}"
                })
            ),
            String::new(),
            "data: [DONE]".to_string(),
            String::new(),
        ]
        .join("\n");

        let (text, tool_calls) = parse_sse_full(&payload).unwrap();
        assert!(text.is_none());
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].id, "call_inc_1");
        assert_eq!(tool_calls[0].name, "shell");
        assert_eq!(tool_calls[0].arguments, r#"{"cmd":"ls"}"#);
    }

    #[test]
    fn parse_sse_full_completed_overrides_incremental() {
        // When both incremental events and response.completed are present,
        // the completed event's tool calls take precedence.
        let payload = [
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.output_item.added",
                    "item": {
                        "type": "function_call",
                        "call_id": "call_inc_1",
                        "name": "shell"
                    }
                })
            ),
            String::new(),
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.function_call_arguments.done",
                    "call_id": "call_inc_1",
                    "arguments": "{\"cmd\":\"ls\"}"
                })
            ),
            String::new(),
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.completed",
                    "response": {
                        "output": [
                            {
                                "type": "function_call",
                                "call_id": "call_auth_1",
                                "name": "file_read",
                                "arguments": "{\"path\":\"main.rs\"}"
                            }
                        ],
                        "output_text": null
                    }
                })
            ),
            String::new(),
            "data: [DONE]".to_string(),
            String::new(),
        ]
        .join("\n");

        let (_, tool_calls) = parse_sse_full(&payload).unwrap();
        // Completed event's tool calls win.
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].id, "call_auth_1");
        assert_eq!(tool_calls[0].name, "file_read");
    }

    #[test]
    fn parse_sse_full_incremental_multiple_tool_calls() {
        // Multiple tool calls accumulated incrementally.
        let payload = [
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.output_item.added",
                    "item": {"type": "function_call", "call_id": "call_a", "name": "shell"}
                })
            ),
            String::new(),
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.output_item.added",
                    "item": {"type": "function_call", "call_id": "call_b", "name": "file_read"}
                })
            ),
            String::new(),
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.function_call_arguments.done",
                    "call_id": "call_a",
                    "arguments": "{\"cmd\":\"pwd\"}"
                })
            ),
            String::new(),
            format!(
                "data: {}",
                serde_json::json!({
                    "type": "response.function_call_arguments.done",
                    "call_id": "call_b",
                    "arguments": "{\"path\":\"Cargo.toml\"}"
                })
            ),
            String::new(),
            "data: [DONE]".to_string(),
            String::new(),
        ]
        .join("\n");

        let (_, tool_calls) = parse_sse_full(&payload).unwrap();
        assert_eq!(tool_calls.len(), 2);
        // Verify insertion order is preserved.
        assert_eq!(tool_calls[0].id, "call_a");
        assert_eq!(tool_calls[0].name, "shell");
        assert_eq!(tool_calls[1].id, "call_b");
        assert_eq!(tool_calls[1].name, "file_read");
    }

    #[test]
    fn parse_sse_full_truncated_stream_diagnostic() {
        // Empty stream with only SSE markers but no useful data — should produce an error.
        let payload = "data: {\"type\":\"response.created\"}\n\n";
        let (text, tool_calls) = parse_sse_full(payload).unwrap();
        // No text or tool calls, but no error either (error comes from decode_responses_body_full).
        assert!(text.is_none());
        assert!(tool_calls.is_empty());
    }
}
