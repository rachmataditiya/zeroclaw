use super::session::{ProcessSession, ProcessStatus};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Default idle timeout for sessions (30 minutes).
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30 * 60;

/// Maximum number of concurrent sessions.
const MAX_SESSIONS: usize = 20;

/// Manages the lifecycle of process sessions.
pub struct ProcessSessionManager {
    sessions: Arc<Mutex<HashMap<String, ProcessSession>>>,
    idle_timeout: Duration,
}

impl ProcessSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
        }
    }

    /// Spawn a new process and track it.
    pub fn spawn(
        &self,
        command: &str,
        workdir: &std::path::Path,
        use_pty: bool,
        timeout_secs: Option<u64>,
    ) -> Result<String, String> {
        let mut sessions = self.sessions.lock().unwrap();

        // Enforce session limit
        if sessions.len() >= MAX_SESSIONS {
            // Clean up completed sessions first
            sessions.retain(|_, s| s.status() == ProcessStatus::Running);
            if sessions.len() >= MAX_SESSIONS {
                return Err(format!(
                    "Maximum session limit ({MAX_SESSIONS}) reached. Kill or wait for existing sessions."
                ));
            }
        }

        let session_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
        let session =
            ProcessSession::spawn(session_id.clone(), command, workdir, use_pty, timeout_secs)?;

        sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    /// Poll a session's status.
    pub fn poll(&self, session_id: &str) -> Result<ProcessStatus, String> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .get(session_id)
            .map(|s| s.status())
            .ok_or_else(|| format!("Session not found: {session_id}"))
    }

    /// Read output from a session.
    pub fn read_log(
        &self,
        session_id: &str,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<(String, usize), String> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| format!("Session not found: {session_id}"))?;
        let total = session.output_len();
        let output = session.read_output(offset, limit);
        Ok((output, total))
    }

    /// Write to a session's stdin.
    pub fn write_input(&self, session_id: &str, data: &[u8]) -> Result<(), String> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| format!("Session not found: {session_id}"))?;
        session.write_input(data)
    }

    /// Kill a session's process.
    pub fn kill(&self, session_id: &str) -> Result<(), String> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| format!("Session not found: {session_id}"))?;
        session.kill()
    }

    /// List all sessions with their status.
    pub fn list(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .values()
            .map(|s| SessionInfo {
                session_id: s.id.clone(),
                command: s.command.clone(),
                status: s.status().to_string(),
                pty: s.pty,
                output_bytes: s.output_len(),
                uptime_secs: s.created_at.elapsed().as_secs(),
            })
            .collect()
    }

    /// Clean up idle and completed sessions.
    pub fn cleanup(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        let idle_timeout = self.idle_timeout;
        sessions.retain(|_, session| {
            let status = session.status();
            // Keep running sessions that are not idle
            if status == ProcessStatus::Running {
                !session.is_idle(idle_timeout)
            } else {
                // Keep recently completed sessions for a short window
                !session.is_idle(Duration::from_secs(300))
            }
        });
    }
}

impl Default for ProcessSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary info for a session (used in list output).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub command: String,
    pub status: String,
    pub pty: bool,
    pub output_bytes: usize,
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_spawn_and_poll() {
        let mgr = ProcessSessionManager::new();
        let id = mgr
            .spawn("echo hello", std::env::temp_dir().as_path(), false, Some(5))
            .unwrap();

        std::thread::sleep(Duration::from_millis(500));

        let status = mgr.poll(&id).unwrap();
        assert!(
            matches!(status, ProcessStatus::Exited(0)),
            "expected Exited(0), got {status:?}"
        );

        let (output, _total) = mgr.read_log(&id, 0, None).unwrap();
        assert!(output.contains("hello"));
    }

    #[test]
    fn manager_list_sessions() {
        let mgr = ProcessSessionManager::new();
        let _id = mgr
            .spawn("sleep 10", std::env::temp_dir().as_path(), false, Some(30))
            .unwrap();

        let list = mgr.list();
        assert_eq!(list.len(), 1);
        assert!(list[0].status.contains("running"));
    }

    #[test]
    fn manager_kill_session() {
        let mgr = ProcessSessionManager::new();
        let id = mgr
            .spawn("sleep 60", std::env::temp_dir().as_path(), false, None)
            .unwrap();

        mgr.kill(&id).unwrap();
        std::thread::sleep(Duration::from_millis(200));

        let status = mgr.poll(&id).unwrap();
        assert!(
            matches!(status, ProcessStatus::Killed),
            "expected Killed, got {status:?}"
        );
    }

    #[test]
    fn manager_nonexistent_session() {
        let mgr = ProcessSessionManager::new();
        assert!(mgr.poll("nonexistent").is_err());
        assert!(mgr.kill("nonexistent").is_err());
        assert!(mgr.read_log("nonexistent", 0, None).is_err());
    }
}
