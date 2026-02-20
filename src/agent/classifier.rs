use crate::config::schema::{
    AdaptiveClassificationConfig, ClassificationMode, QueryClassificationConfig,
};
use crate::providers::Provider;

/// Classify a user message against the configured rules and return the
/// matching hint string, if any.
///
/// Returns `None` when classification is disabled, no rules are configured,
/// or no rule matches the message.
pub fn classify(config: &QueryClassificationConfig, message: &str) -> Option<String> {
    if !config.enabled || config.rules.is_empty() {
        return None;
    }

    let lower = message.to_lowercase();
    let len = message.len();

    let mut rules: Vec<_> = config.rules.iter().collect();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    for rule in rules {
        // Length constraints
        if let Some(min) = rule.min_length {
            if len < min {
                continue;
            }
        }
        if let Some(max) = rule.max_length {
            if len > max {
                continue;
            }
        }

        // Check keywords (case-insensitive) and patterns (case-sensitive)
        let keyword_hit = rule
            .keywords
            .iter()
            .any(|kw: &String| lower.contains(&kw.to_lowercase()));
        let pattern_hit = rule
            .patterns
            .iter()
            .any(|pat: &String| message.contains(pat.as_str()));

        if keyword_hit || pattern_hit {
            return Some(rule.hint.clone());
        }
    }

    None
}

// ── Adaptive (LLM-based) classification ──────────────────────────

/// Result of adaptive classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveCategory {
    Chat,
    SimpleTask,
    ComplexTask,
}

/// Parse the LLM response into an `AdaptiveCategory`.
///
/// Tries exact match first, then fuzzy contains-based fallback.
/// Defaults to `SimpleTask` for unrecognizable responses (safest default —
/// uses the default model without extra reasoning overhead).
pub fn parse_adaptive_response(response: &str) -> AdaptiveCategory {
    let trimmed = response.trim().to_lowercase();

    // Exact single-word match
    match trimmed.as_str() {
        "chat" => return AdaptiveCategory::Chat,
        "simple" => return AdaptiveCategory::SimpleTask,
        "complex" => return AdaptiveCategory::ComplexTask,
        _ => {}
    }

    // Fuzzy fallback — check contains (order matters: complex before simple,
    // since "complex" is more specific)
    if trimmed.contains("complex") {
        return AdaptiveCategory::ComplexTask;
    }
    if trimmed.contains("chat") {
        return AdaptiveCategory::Chat;
    }
    if trimmed.contains("simple") {
        return AdaptiveCategory::SimpleTask;
    }

    // Unknown → default to SimpleTask
    AdaptiveCategory::SimpleTask
}

/// Map an `AdaptiveCategory` to the configured hint string.
///
/// Returns `None` if the hint is empty (meaning "use default model").
fn category_to_hint(
    category: AdaptiveCategory,
    adaptive: &AdaptiveClassificationConfig,
) -> Option<String> {
    let hint = match category {
        AdaptiveCategory::Chat => &adaptive.chat_hint,
        AdaptiveCategory::SimpleTask => &adaptive.simple_task_hint,
        AdaptiveCategory::ComplexTask => &adaptive.complex_task_hint,
    };
    if hint.is_empty() {
        None
    } else {
        Some(hint.clone())
    }
}

const CLASSIFICATION_PROMPT_TEMPLATE: &str = r#"Classify the user message into exactly one category.
Reply with ONLY one word: chat, simple, or complex.

- chat: casual conversation, greetings, small talk, simple questions with no action needed
- simple: a clear task that can be done in 1-2 steps
- complex: multi-step task requiring reasoning, planning, code generation, analysis, or delegation

User message: "#;

/// Perform adaptive LLM-based classification.
///
/// Makes a fast `simple_chat()` call to classify the message, then maps the
/// category to a hint string. Returns `None` on any error (graceful fallback
/// to rules-based classification or default model).
///
/// Applies a 5-second timeout to prevent blocking the agent loop.
pub async fn adaptive_classify(
    provider: &dyn Provider,
    model: &str,
    config: &AdaptiveClassificationConfig,
    message: &str,
) -> Option<String> {
    let prompt = format!("{CLASSIFICATION_PROMPT_TEMPLATE}{message}");

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.simple_chat(&prompt, model, config.temperature),
    )
    .await;

    match result {
        Ok(Ok(response)) => {
            let category = parse_adaptive_response(&response);
            tracing::info!(
                response = response.trim(),
                ?category,
                "Adaptive classification result"
            );
            category_to_hint(category, config)
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "Adaptive classification LLM call failed");
            None
        }
        Err(_) => {
            tracing::warn!("Adaptive classification timed out (>5s)");
            None
        }
    }
}

/// Top-level classification entry point that respects `ClassificationMode`.
///
/// Cascade: adaptive → rules → None (caller uses default model).
pub async fn classify_message(
    config: &QueryClassificationConfig,
    provider: &dyn Provider,
    model: &str,
    message: &str,
) -> Option<String> {
    if !config.enabled {
        return None;
    }

    // Try adaptive first if configured
    if config.mode == ClassificationMode::Adaptive {
        if let Some(hint) = adaptive_classify(provider, model, &config.adaptive, message).await {
            return Some(hint);
        }
        // Fall through to rules on adaptive failure
    }

    // Rules-based classification
    classify(config, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{ClassificationRule, QueryClassificationConfig};

    fn make_config(enabled: bool, rules: Vec<ClassificationRule>) -> QueryClassificationConfig {
        QueryClassificationConfig {
            enabled,
            rules,
            ..Default::default()
        }
    }

    #[test]
    fn disabled_returns_none() {
        let config = make_config(
            false,
            vec![ClassificationRule {
                hint: "fast".into(),
                keywords: vec!["hello".into()],
                ..Default::default()
            }],
        );
        assert_eq!(classify(&config, "hello"), None);
    }

    #[test]
    fn empty_rules_returns_none() {
        let config = make_config(true, vec![]);
        assert_eq!(classify(&config, "hello"), None);
    }

    #[test]
    fn keyword_match_case_insensitive() {
        let config = make_config(
            true,
            vec![ClassificationRule {
                hint: "fast".into(),
                keywords: vec!["hello".into()],
                ..Default::default()
            }],
        );
        assert_eq!(classify(&config, "HELLO world"), Some("fast".into()));
    }

    #[test]
    fn pattern_match_case_sensitive() {
        let config = make_config(
            true,
            vec![ClassificationRule {
                hint: "code".into(),
                patterns: vec!["fn ".into()],
                ..Default::default()
            }],
        );
        assert_eq!(classify(&config, "fn main()"), Some("code".into()));
        assert_eq!(classify(&config, "FN MAIN()"), None);
    }

    #[test]
    fn length_constraints() {
        let config = make_config(
            true,
            vec![ClassificationRule {
                hint: "fast".into(),
                keywords: vec!["hi".into()],
                max_length: Some(10),
                ..Default::default()
            }],
        );
        assert_eq!(classify(&config, "hi"), Some("fast".into()));
        assert_eq!(
            classify(&config, "hi there, how are you doing today?"),
            None
        );

        let config2 = make_config(
            true,
            vec![ClassificationRule {
                hint: "reasoning".into(),
                keywords: vec!["explain".into()],
                min_length: Some(20),
                ..Default::default()
            }],
        );
        assert_eq!(classify(&config2, "explain"), None);
        assert_eq!(
            classify(&config2, "explain how this works in detail"),
            Some("reasoning".into())
        );
    }

    #[test]
    fn priority_ordering() {
        let config = make_config(
            true,
            vec![
                ClassificationRule {
                    hint: "fast".into(),
                    keywords: vec!["code".into()],
                    priority: 1,
                    ..Default::default()
                },
                ClassificationRule {
                    hint: "code".into(),
                    keywords: vec!["code".into()],
                    priority: 10,
                    ..Default::default()
                },
            ],
        );
        assert_eq!(classify(&config, "write some code"), Some("code".into()));
    }

    #[test]
    fn no_match_returns_none() {
        let config = make_config(
            true,
            vec![ClassificationRule {
                hint: "fast".into(),
                keywords: vec!["hello".into()],
                ..Default::default()
            }],
        );
        assert_eq!(classify(&config, "something completely different"), None);
    }

    // ── Adaptive classification tests ────────────────────────────

    #[test]
    fn parse_exact_chat() {
        assert_eq!(parse_adaptive_response("chat"), AdaptiveCategory::Chat);
    }

    #[test]
    fn parse_exact_simple() {
        assert_eq!(
            parse_adaptive_response("simple"),
            AdaptiveCategory::SimpleTask
        );
    }

    #[test]
    fn parse_exact_complex() {
        assert_eq!(
            parse_adaptive_response("complex"),
            AdaptiveCategory::ComplexTask
        );
    }

    #[test]
    fn parse_with_whitespace_and_casing() {
        assert_eq!(parse_adaptive_response("  Chat  "), AdaptiveCategory::Chat);
        assert_eq!(
            parse_adaptive_response("COMPLEX\n"),
            AdaptiveCategory::ComplexTask
        );
        assert_eq!(
            parse_adaptive_response(" Simple "),
            AdaptiveCategory::SimpleTask
        );
    }

    #[test]
    fn parse_fuzzy_contains() {
        assert_eq!(
            parse_adaptive_response("I think this is complex"),
            AdaptiveCategory::ComplexTask
        );
        assert_eq!(
            parse_adaptive_response("this is a chat message"),
            AdaptiveCategory::Chat
        );
        assert_eq!(
            parse_adaptive_response("simple task"),
            AdaptiveCategory::SimpleTask
        );
    }

    #[test]
    fn parse_unknown_defaults_to_simple_task() {
        assert_eq!(
            parse_adaptive_response("banana"),
            AdaptiveCategory::SimpleTask
        );
        assert_eq!(parse_adaptive_response(""), AdaptiveCategory::SimpleTask);
    }

    #[test]
    fn category_to_hint_empty_returns_none() {
        let adaptive = AdaptiveClassificationConfig {
            simple_task_hint: String::new(),
            ..Default::default()
        };
        assert_eq!(
            category_to_hint(AdaptiveCategory::SimpleTask, &adaptive),
            None
        );
    }

    #[test]
    fn category_to_hint_configured() {
        let adaptive = AdaptiveClassificationConfig {
            chat_hint: "fast".into(),
            simple_task_hint: String::new(),
            complex_task_hint: "reasoning".into(),
            ..Default::default()
        };
        assert_eq!(
            category_to_hint(AdaptiveCategory::Chat, &adaptive),
            Some("fast".into())
        );
        assert_eq!(
            category_to_hint(AdaptiveCategory::SimpleTask, &adaptive),
            None
        );
        assert_eq!(
            category_to_hint(AdaptiveCategory::ComplexTask, &adaptive),
            Some("reasoning".into())
        );
    }
}
