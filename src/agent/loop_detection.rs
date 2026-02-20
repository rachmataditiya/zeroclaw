//! Tool loop detection to break repetitive tool call patterns.
//!
//! Detects three patterns:
//! 1. **Generic repeat** — same tool+args called N times (warning only)
//! 2. **No-progress poll** — same tool+args+result N times (critical)
//! 3. **Ping-pong** — alternating between two tool signatures with identical results (critical)

use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::time::Instant;

/// Maximum tool call history size.
const TOOL_CALL_HISTORY_SIZE: usize = 30;

/// Default thresholds (can be overridden via config).
const DEFAULT_WARNING_THRESHOLD: usize = 10;
const DEFAULT_CRITICAL_THRESHOLD: usize = 20;

/// Result of loop detection check.
#[derive(Debug, Clone)]
pub enum LoopDetection {
    /// No loop detected.
    None,
    /// Warning: possible loop, but not yet critical.
    Warning(String),
    /// Critical: definite loop, should break.
    Critical(String),
}

/// Record of a single tool call in the history.
#[derive(Debug, Clone)]
struct ToolCallRecord {
    tool_name: String,
    args_hash: String,
    result_hash: Option<String>,
    #[allow(dead_code)]
    timestamp: Instant,
}

impl ToolCallRecord {
    fn signature(&self) -> String {
        format!("{}:{}", self.tool_name, self.args_hash)
    }

    fn full_signature(&self) -> String {
        format!(
            "{}:{}:{}",
            self.tool_name,
            self.args_hash,
            self.result_hash.as_deref().unwrap_or("none")
        )
    }
}

/// Detects repetitive tool call patterns.
pub struct LoopDetector {
    history: VecDeque<ToolCallRecord>,
    warned_pairs: HashSet<String>,
    warning_threshold: usize,
    critical_threshold: usize,
}

impl LoopDetector {
    pub fn new(warning_threshold: usize, critical_threshold: usize) -> Self {
        Self {
            history: VecDeque::with_capacity(TOOL_CALL_HISTORY_SIZE + 1),
            warned_pairs: HashSet::new(),
            warning_threshold: if warning_threshold == 0 {
                DEFAULT_WARNING_THRESHOLD
            } else {
                warning_threshold
            },
            critical_threshold: if critical_threshold == 0 {
                DEFAULT_CRITICAL_THRESHOLD
            } else {
                critical_threshold
            },
        }
    }

    /// Record a tool call (before execution).
    pub fn record_call(&mut self, tool: &str, args: &serde_json::Value) {
        let args_hash = hash_json(args);

        self.history.push_back(ToolCallRecord {
            tool_name: tool.to_string(),
            args_hash,
            result_hash: None,
            timestamp: Instant::now(),
        });

        // Trim to max history size
        while self.history.len() > TOOL_CALL_HISTORY_SIZE {
            self.history.pop_front();
        }
    }

    /// Record a tool result (after execution).
    pub fn record_result(&mut self, tool: &str, args: &serde_json::Value, result: &str) {
        let args_hash = hash_json(args);
        let result_hash = hash_str(result);

        // Find the last matching call without a result and update it
        for record in self.history.iter_mut().rev() {
            if record.tool_name == tool
                && record.args_hash == args_hash
                && record.result_hash.is_none()
            {
                record.result_hash = Some(result_hash);
                break;
            }
        }
    }

    /// Check for loop patterns. Returns the detection result.
    pub fn check(&mut self) -> LoopDetection {
        if self.history.len() < 3 {
            return LoopDetection::None;
        }

        // Check for no-progress poll (same tool+args+result repeated)
        if let Some(detection) = self.check_no_progress() {
            return detection;
        }

        // Check for ping-pong (alternating between two signatures)
        if let Some(detection) = self.check_ping_pong() {
            return detection;
        }

        // Check for generic repeat (same tool+args, possibly different results)
        if let Some(detection) = self.check_generic_repeat() {
            return detection;
        }

        LoopDetection::None
    }

    /// Check for same tool+args called repeatedly.
    fn check_generic_repeat(&self) -> Option<LoopDetection> {
        let last = self.history.back()?;

        let sig = last.signature();
        let count = self.history.iter().filter(|r| r.signature() == sig).count();

        if count >= self.critical_threshold {
            return Some(LoopDetection::Critical(format!(
                "Tool '{}' called with identical arguments {} times. Breaking loop.",
                last.tool_name, count
            )));
        }

        if count >= self.warning_threshold {
            return Some(LoopDetection::Warning(format!(
                "Tool '{}' has been called with identical arguments {} times. Consider a different approach.",
                last.tool_name, count
            )));
        }

        None
    }

    /// Check for same tool+args+result (no progress being made).
    fn check_no_progress(&self) -> Option<LoopDetection> {
        let last = self.history.back()?;

        last.result_hash.as_ref()?;

        let full_sig = last.full_signature();
        let count = self
            .history
            .iter()
            .filter(|r| r.full_signature() == full_sig)
            .count();

        // No-progress is more serious — use lower thresholds
        let warn_at = self.warning_threshold / 2;
        let critical_at = self.critical_threshold / 2;

        if count >= critical_at.max(3) {
            return Some(LoopDetection::Critical(format!(
                "Tool '{}' returned identical results {} times with the same arguments. No progress is being made. Breaking loop.",
                last.tool_name, count
            )));
        }

        if count >= warn_at.max(2) {
            return Some(LoopDetection::Warning(format!(
                "Tool '{}' has returned the same result {} times. Try a different approach.",
                last.tool_name, count
            )));
        }

        None
    }

    /// Check for alternating A-B-A-B pattern.
    fn check_ping_pong(&mut self) -> Option<LoopDetection> {
        if self.history.len() < 4 {
            return None;
        }

        let len = self.history.len();
        let records: Vec<_> = self.history.iter().collect();

        let sig_a = records[len - 2].full_signature();
        let sig_b = records[len - 1].full_signature();

        if sig_a == sig_b {
            return None; // Same signature, not ping-pong
        }

        // Count alternating pattern going backwards
        let mut alternating_count = 0;
        let mut expect_a = true;
        for i in (0..len).rev() {
            let sig = records[i].full_signature();
            if expect_a && sig == sig_a {
                alternating_count += 1;
                expect_a = false;
            } else if !expect_a && sig == sig_b {
                alternating_count += 1;
                expect_a = true;
            } else {
                break;
            }
        }

        let pair_key = format!("{sig_a}|{sig_b}");
        let threshold = self.warning_threshold / 2;

        if alternating_count >= (self.critical_threshold / 2).max(4) {
            return Some(LoopDetection::Critical(format!(
                "Ping-pong detected: tools '{}' and '{}' alternating with identical results {} times. Breaking loop.",
                records[len - 2].tool_name,
                records[len - 1].tool_name,
                alternating_count
            )));
        }

        if alternating_count >= threshold.max(3) && !self.warned_pairs.contains(&pair_key) {
            self.warned_pairs.insert(pair_key);
            return Some(LoopDetection::Warning(format!(
                "Possible ping-pong: tools '{}' and '{}' alternating with similar results. Consider a different approach.",
                records[len - 2].tool_name,
                records[len - 1].tool_name,
            )));
        }

        None
    }
}

/// Hash a JSON value for comparison (stable serialization).
fn hash_json(value: &serde_json::Value) -> String {
    let serialized = serde_json::to_string(value).unwrap_or_default();
    hash_str(&serialized)
}

/// Hash a string using SHA-256 (truncated to 16 hex chars for efficiency).
fn hash_str(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8]) // 16 hex chars
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn no_detection_with_few_calls() {
        let mut detector = LoopDetector::new(3, 5);
        detector.record_call("shell", &json!({"command": "ls"}));
        detector.record_result("shell", &json!({"command": "ls"}), "file1\nfile2");
        assert!(matches!(detector.check(), LoopDetection::None));
    }

    #[test]
    fn warns_on_generic_repeat() {
        let mut detector = LoopDetector::new(3, 6);
        let args = json!({"command": "ls"});

        for i in 0..3 {
            detector.record_call("shell", &args);
            detector.record_result("shell", &args, &format!("result_{i}"));
        }

        match detector.check() {
            LoopDetection::Warning(msg) => {
                assert!(msg.contains("shell"));
                assert!(msg.contains("3 times"));
            }
            other => panic!("Expected Warning, got: {other:?}"),
        }
    }

    #[test]
    fn critical_on_many_repeats() {
        let mut detector = LoopDetector::new(3, 6);
        let args = json!({"command": "ls"});

        for i in 0..6 {
            detector.record_call("shell", &args);
            detector.record_result("shell", &args, &format!("result_{i}"));
        }

        match detector.check() {
            LoopDetection::Critical(msg) => {
                assert!(msg.contains("shell"));
                assert!(msg.contains("Breaking loop"));
            }
            other => panic!("Expected Critical, got: {other:?}"),
        }
    }

    #[test]
    fn no_progress_detected() {
        // critical_at = critical_threshold / 2 = 6 / 2 = 3, .max(3) = 3
        // So 3 identical calls should trigger Critical.
        let mut detector = LoopDetector::new(4, 6);
        let args = json!({"command": "check_status"});

        for _ in 0..3 {
            detector.record_call("shell", &args);
            detector.record_result("shell", &args, "status: pending");
        }

        match detector.check() {
            LoopDetection::Critical(msg) => {
                assert!(msg.contains("identical results"));
            }
            other => panic!("Expected Critical for no-progress, got: {other:?}"),
        }
    }

    #[test]
    fn different_tools_no_detection() {
        let mut detector = LoopDetector::new(3, 6);

        detector.record_call("shell", &json!({"command": "ls"}));
        detector.record_result("shell", &json!({"command": "ls"}), "files");
        detector.record_call("file_read", &json!({"path": "a.txt"}));
        detector.record_result("file_read", &json!({"path": "a.txt"}), "content");
        detector.record_call("web_search_tool", &json!({"query": "test"}));
        detector.record_result("web_search_tool", &json!({"query": "test"}), "results");

        assert!(matches!(detector.check(), LoopDetection::None));
    }

    #[test]
    fn hash_json_deterministic() {
        let v1 = json!({"a": 1, "b": 2});
        let v2 = json!({"a": 1, "b": 2});
        assert_eq!(hash_json(&v1), hash_json(&v2));
    }

    #[test]
    fn hash_json_different_values() {
        let v1 = json!({"a": 1});
        let v2 = json!({"a": 2});
        assert_ne!(hash_json(&v1), hash_json(&v2));
    }
}
