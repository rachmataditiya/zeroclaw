//! JSONL-based session persistence store.
//!
//! Each session key (e.g. `"telegram_user123"`) maps to a file
//! `{base_dir}/{sanitized_key}.jsonl` where each line is a JSON-serialized
//! `ChatMessage`.

use crate::providers::ChatMessage;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Metadata about a stored session (without loading all messages).
#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub key: String,
    pub message_count: usize,
    pub file_size: u64,
    pub modified: SystemTime,
}

/// Persistent session store backed by JSONL files.
pub struct SessionStore {
    base_dir: PathBuf,
}

impl SessionStore {
    /// Create a new session store. Creates `base_dir` if it doesn't exist.
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&base_dir).with_context(|| {
            format!("Failed to create session directory: {}", base_dir.display())
        })?;
        Ok(Self { base_dir })
    }

    /// Load all messages for a session. Returns `None` if no session file exists.
    pub async fn load(&self, key: &str) -> Result<Option<Vec<ChatMessage>>> {
        let path = self.session_path(key);
        if !path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("Failed to read session file: {}", path.display()))?;

        let mut messages = Vec::new();
        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<ChatMessage>(trimmed) {
                Ok(msg) => messages.push(msg),
                Err(e) => {
                    tracing::warn!(
                        line = line_num + 1,
                        error = %e,
                        path = %path.display(),
                        "Skipping malformed session line"
                    );
                }
            }
        }

        if messages.is_empty() {
            Ok(None)
        } else {
            Ok(Some(messages))
        }
    }

    /// Append a single message to a session file.
    pub async fn append(&self, key: &str, message: &ChatMessage) -> Result<()> {
        let path = self.session_path(key);
        let mut line = serde_json::to_string(message).context("Failed to serialize ChatMessage")?;
        line.push('\n');

        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("Failed to open session file: {}", path.display()))?
            .write_all(line.as_bytes())
            .await
            .with_context(|| format!("Failed to append to session file: {}", path.display()))?;

        Ok(())
    }

    /// Overwrite a session with a new set of messages (e.g. after compaction).
    pub async fn overwrite(&self, key: &str, messages: &[ChatMessage]) -> Result<()> {
        let path = self.session_path(key);
        let mut content = String::new();
        for msg in messages {
            let line = serde_json::to_string(msg).context("Failed to serialize ChatMessage")?;
            content.push_str(&line);
            content.push('\n');
        }

        tokio::fs::write(&path, content.as_bytes())
            .await
            .with_context(|| format!("Failed to write session file: {}", path.display()))?;

        Ok(())
    }

    /// List all stored sessions with metadata.
    pub async fn list(&self) -> Result<Vec<SessionMeta>> {
        let mut sessions = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.base_dir).await.with_context(|| {
            format!(
                "Failed to read session directory: {}",
                self.base_dir.display()
            )
        })?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().map_or(true, |ext| ext != "jsonl") {
                continue;
            }

            let key = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();

            if key.is_empty() {
                continue;
            }

            let metadata = entry.metadata().await?;
            let content = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            let message_count = content.lines().filter(|l| !l.trim().is_empty()).count();

            sessions.push(SessionMeta {
                key,
                message_count,
                file_size: metadata.len(),
                modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }

        sessions.sort_by(|a, b| b.modified.cmp(&a.modified));
        Ok(sessions)
    }

    /// Remove sessions older than `max_age`.
    pub async fn prune(&self, max_age: Duration) -> Result<usize> {
        let now = SystemTime::now();
        let mut pruned = 0;
        let mut entries = tokio::fs::read_dir(&self.base_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().map_or(true, |ext| ext != "jsonl") {
                continue;
            }

            let metadata = entry.metadata().await?;
            let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

            if let Ok(age) = now.duration_since(modified) {
                if age > max_age {
                    if let Err(e) = tokio::fs::remove_file(&path).await {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "Failed to prune session file"
                        );
                    } else {
                        pruned += 1;
                    }
                }
            }
        }

        Ok(pruned)
    }

    /// Get the file path for a session key.
    fn session_path(&self, key: &str) -> PathBuf {
        let sanitized = sanitize_key(key);
        self.base_dir.join(format!("{sanitized}.jsonl"))
    }
}

/// Sanitize a session key for safe use as a filename.
/// Replaces non-alphanumeric characters (except `_` and `-`) with `_`.
fn sanitize_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

use tokio::io::AsyncWriteExt;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn sanitize_key_replaces_special_chars() {
        assert_eq!(sanitize_key("telegram_user123"), "telegram_user123");
        assert_eq!(sanitize_key("discord/user@name"), "discord_user_name");
        assert_eq!(sanitize_key("slack channel.id"), "slack_channel_id");
    }

    #[tokio::test]
    async fn round_trip_append_and_load() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf()).unwrap();

        store
            .append("test_session", &ChatMessage::user("hello"))
            .await
            .unwrap();
        store
            .append("test_session", &ChatMessage::assistant("hi there"))
            .await
            .unwrap();

        let loaded = store.load("test_session").await.unwrap().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].role, "user");
        assert_eq!(loaded[0].content, "hello");
        assert_eq!(loaded[1].role, "assistant");
        assert_eq!(loaded[1].content, "hi there");
    }

    #[tokio::test]
    async fn load_nonexistent_returns_none() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf()).unwrap();

        assert!(store.load("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn overwrite_replaces_content() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf()).unwrap();

        store
            .append("key", &ChatMessage::user("old"))
            .await
            .unwrap();

        let new_messages = vec![ChatMessage::user("new1"), ChatMessage::assistant("new2")];
        store.overwrite("key", &new_messages).await.unwrap();

        let loaded = store.load("key").await.unwrap().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].content, "new1");
        assert_eq!(loaded[1].content, "new2");
    }

    #[tokio::test]
    async fn list_returns_sessions() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf()).unwrap();

        store
            .append("session_a", &ChatMessage::user("hello"))
            .await
            .unwrap();
        store
            .append("session_b", &ChatMessage::user("world"))
            .await
            .unwrap();

        let sessions = store.list().await.unwrap();
        assert_eq!(sessions.len(), 2);

        let keys: Vec<&str> = sessions.iter().map(|s| s.key.as_str()).collect();
        assert!(keys.contains(&"session_a"));
        assert!(keys.contains(&"session_b"));
    }

    #[tokio::test]
    async fn prune_keeps_recent_sessions() {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf()).unwrap();

        store
            .append("recent_session", &ChatMessage::user("hello"))
            .await
            .unwrap();

        // All files are recent, so pruning with a 1-day max_age should remove nothing
        let pruned = store.prune(Duration::from_secs(24 * 3600)).await.unwrap();
        assert_eq!(pruned, 0);

        assert!(store.load("recent_session").await.unwrap().is_some());
    }
}
