# ZeroClaw Config Reference (Operator-Oriented)

This is a high-signal reference for common config sections and defaults.

Last verified: **February 18, 2026**.

Config file path:

- `~/.zeroclaw/config.toml`

## Core Keys

| Key | Default | Notes |
|---|---|---|
| `default_provider` | `openrouter` | provider ID or alias |
| `default_model` | `anthropic/claude-sonnet-4-6` | model routed through selected provider |
| `default_temperature` | `0.7` | model temperature |

## `[agent]`

| Key | Default | Purpose |
|---|---|---|
| `max_tool_iterations` | `10` | Maximum tool-call loop turns per user message across CLI, gateway, and channels |

Notes:

- Setting `max_tool_iterations = 0` falls back to safe default `10`.
- If a channel message exceeds this value, the runtime returns: `Agent exceeded maximum tool iterations (<value>)`.

## `[gateway]`

| Key | Default | Purpose |
|---|---|---|
| `host` | `127.0.0.1` | bind address |
| `port` | `3000` | gateway listen port |
| `require_pairing` | `true` | require pairing before bearer auth |
| `allow_public_bind` | `false` | block accidental public exposure |

## `[memory]`

| Key | Default | Purpose |
|---|---|---|
| `backend` | `sqlite` | `sqlite`, `lucid`, `markdown`, `none` |
| `auto_save` | `true` | automatic persistence |
| `embedding_provider` | `none` | `none`, `openai`, `ollama`, or `custom:URL` endpoint |
| `vector_weight` | `0.7` | hybrid ranking vector weight |
| `keyword_weight` | `0.3` | hybrid ranking keyword weight |

## `[channels_config]`

Top-level channel options are configured under `channels_config`.

Examples:

- `[channels_config.telegram]`
- `[channels_config.discord]`
- `[channels_config.whatsapp]`
- `[channels_config.email]`

See detailed channel matrix and allowlist behavior in [channels-reference.md](channels-reference.md).

## `[[model_routes]]`

Route model calls by hint to specific provider+model combinations.

| Key | Type | Required | Notes |
|---|---|---|---|
| `hint` | string | yes | Task hint name (e.g. `"reasoning"`, `"fast"`, `"code"`) |
| `provider` | string | yes | Provider to route to (must match a known provider name) |
| `model` | string | yes | Model to use with that provider |
| `api_key` | string | no | Optional API key override for this route's provider |

Example:

```toml
[[model_routes]]
hint = "fast"
provider = "groq"
model = "llama-3.3-70b-versatile"

[[model_routes]]
hint = "reasoning"
provider = "openrouter"
model = "anthropic/claude-sonnet-4"
```

Use `hint:<name>` as the model parameter to route through the matching route (e.g. `hint:reasoning`).

## `[query_classification]`

Automatically classify user messages and route them to the appropriate model hint. Disabled by default.

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Enable query classification |
| `mode` | string | `"rules"` | `"rules"` (keyword/pattern) or `"adaptive"` (LLM-based) |
| `rules` | array | `[]` | Array of `ClassificationRule` objects (for `mode = "rules"`) |

Each `ClassificationRule` object:

| Key | Type | Default | Notes |
|---|---|---|---|
| `hint` | string | required | Must match a `[[model_routes]]` hint |
| `keywords` | array | `[]` | Case-insensitive substring matches |
| `patterns` | array | `[]` | Case-sensitive literal matches |
| `min_length` | integer | none | Only match if message >= N chars |
| `max_length` | integer | none | Only match if message <= N chars |
| `priority` | integer | `0` | Higher priority rules checked first |

### `[query_classification.adaptive]`

LLM-based adaptive classification (requires `mode = "adaptive"`).

| Key | Type | Default | Notes |
|---|---|---|---|
| `provider` | string | default provider | Provider for the classifier LLM |
| `model` | string | default model | Model for the classifier LLM |
| `api_key` | string | none | Optional API key override |
| `chat_hint` | string | `"fast"` | Hint for chat/conversational messages |
| `simple_task_hint` | string | `""` | Hint for simple tasks (empty = default model) |
| `complex_task_hint` | string | `"reasoning"` | Hint for complex tasks |
| `temperature` | float | `0.0` | Temperature for classifier LLM |

Minimal example (rules mode):

```toml
[query_classification]
enabled = true
mode = "rules"

[[query_classification.rules]]
hint = "reasoning"
keywords = ["analyze", "explain", "debug"]
min_length = 100
priority = 10
```

Full example (adaptive mode):

```toml
[query_classification]
enabled = true
mode = "adaptive"

[query_classification.adaptive]
provider = "groq"
model = "llama-3.3-70b-versatile"
chat_hint = "fast"
simple_task_hint = ""
complex_task_hint = "reasoning"

[[model_routes]]
hint = "fast"
provider = "groq"
model = "llama-3.3-70b-versatile"

[[model_routes]]
hint = "reasoning"
provider = "openrouter"
model = "anthropic/claude-sonnet-4"
```

Classification cascade: adaptive classification runs first, then falls back to rules, then to the default model.

## `[agents.*]`

Define named sub-agents for multi-agent delegation workflows. The agent can delegate tasks to these sub-agents via the `delegate` tool.

| Key | Type | Default | Notes |
|---|---|---|---|
| `provider` | string | required | Provider ID for this sub-agent (must match a known provider) |
| `model` | string | required | Model to use |
| `system_prompt` | string | none | Custom system prompt |
| `api_key` | string | none | API key override |
| `temperature` | float | none | Temperature override |
| `max_depth` | integer | `3` | Max recursion depth |
| `mode` | string | `"simple"` | `"simple"` (single LLM call) or `"full"` (tool loop) |
| `allowed_tools` | array | `[]` | Tool whitelist for full mode (empty = all parent tools) |
| `max_iterations` | integer | `10` | Tool loop iterations (full mode only) |
| `background` | bool | `false` | Run async, return task_id immediately |

### Delegate Tool Actions

The `delegate` tool supports 5 actions:

| Action | Description |
|---|---|
| `delegate` | Send a task to a named sub-agent |
| `status` | Check status of a background task |
| `result` | Retrieve result of a completed task |
| `cancel` | Cancel a running background task |
| `list` | List all active/completed tasks |

### Examples

Simple researcher (dedicated reasoning model, no tools):

```toml
[agents.researcher]
provider = "openrouter"
model = "anthropic/claude-sonnet-4"
system_prompt = "You are a research specialist. Analyze topics thoroughly and provide structured summaries."
mode = "simple"
```

Full coder (tool loop with filtered tool access):

```toml
[agents.coder]
provider = "openrouter"
model = "anthropic/claude-sonnet-4"
mode = "full"
allowed_tools = ["shell", "file_read", "file_write", "git_operations"]
max_iterations = 15
```

Background worker (async task with status polling):

```toml
[agents.background_worker]
provider = "groq"
model = "llama-3.3-70b-versatile"
mode = "full"
background = true
max_iterations = 20
```

## Security-Relevant Defaults

- deny-by-default channel allowlists (`[]` means deny all)
- pairing required on gateway by default
- public bind disabled by default

## Validation Commands

After editing config:

```bash
zeroclaw status
zeroclaw doctor
zeroclaw channel doctor
```

## Related Docs

- [channels-reference.md](channels-reference.md)
- [providers-reference.md](providers-reference.md)
- [operations-runbook.md](operations-runbook.md)
- [troubleshooting.md](troubleshooting.md)
