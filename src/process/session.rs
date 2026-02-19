use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Maximum output buffer size per session (5MB).
const MAX_BUFFER_SIZE: usize = 5 * 1024 * 1024;

/// Environment variables safe to pass to spawned processes.
/// Only functional variables are included — never API keys or secrets (CWE-200).
const SAFE_ENV_VARS: &[&str] = &[
    "PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "USER", "SHELL", "TMPDIR",
];

/// Status of a process session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessStatus {
    Running,
    Exited(i32),
    Killed,
    Failed(String),
}

impl std::fmt::Display for ProcessStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Exited(code) => write!(f, "exited({code})"),
            Self::Killed => write!(f, "killed"),
            Self::Failed(msg) => write!(f, "failed: {msg}"),
        }
    }
}

/// Inner state for a process session, protected by a mutex.
struct SessionInner {
    output_buffer: Vec<u8>,
    status: ProcessStatus,
    last_activity: Instant,
}

/// A managed process session with output capture and input forwarding.
/// Supports both PTY-based and pipe-based I/O.
pub struct ProcessSession {
    pub id: String,
    pub command: String,
    pub created_at: Instant,
    pub pty: bool,
    inner: Arc<Mutex<SessionInner>>,
    /// Writer for sending stdin to the process.
    writer: Arc<Mutex<Option<Box<dyn Write + Send>>>>,
    /// Handle to the child process for kill (using ChildKiller trait).
    child_killer: Arc<Mutex<Option<Box<dyn portable_pty::ChildKiller + Send>>>>,
}

impl ProcessSession {
    /// Spawn a new process session.
    ///
    /// If `pty` is true, allocates a PTY for the process (interactive mode).
    /// Otherwise, uses pipe-based I/O.
    pub fn spawn(
        id: String,
        command: &str,
        workdir: &std::path::Path,
        use_pty: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Self, String> {
        let created_at = Instant::now();
        let inner = Arc::new(Mutex::new(SessionInner {
            output_buffer: Vec::with_capacity(4096),
            status: ProcessStatus::Running,
            last_activity: Instant::now(),
        }));

        let writer: Arc<Mutex<Option<Box<dyn Write + Send>>>>;
        let child_killer: Arc<Mutex<Option<Box<dyn portable_pty::ChildKiller + Send>>>>;

        if use_pty {
            // PTY-based spawn
            let pty_system = portable_pty::native_pty_system();
            let pair = pty_system
                .openpty(portable_pty::PtySize {
                    rows: 24,
                    cols: 80,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|e| format!("Failed to allocate PTY: {e}"))?;

            let cmd = build_shell_command(command, workdir);

            let child_proc = pair
                .slave
                .spawn_command(cmd)
                .map_err(|e| format!("Failed to spawn process: {e}"))?;

            // Get writer (master side) for stdin
            let master_writer = pair
                .master
                .take_writer()
                .map_err(|e| format!("Failed to get PTY writer: {e}"))?;

            writer = Arc::new(Mutex::new(Some(master_writer)));

            // Get killer handle
            let killer = child_proc.clone_killer();
            child_killer = Arc::new(Mutex::new(Some(killer)));

            // Spawn background reader for PTY output
            let master_reader = pair
                .master
                .try_clone_reader()
                .map_err(|e| format!("Failed to get PTY reader: {e}"))?;

            let inner_clone = Arc::clone(&inner);
            std::thread::spawn(move || {
                read_output_loop(master_reader, inner_clone);
            });

            // Spawn a thread to wait for process exit
            let inner_clone2 = Arc::clone(&inner);
            std::thread::spawn(move || {
                wait_for_exit(child_proc, inner_clone2);
            });
        } else {
            // Pipe-based spawn using std::process
            let mut parts =
                shell_words::split(command).map_err(|e| format!("Failed to parse command: {e}"))?;

            if parts.is_empty() {
                return Err("Empty command".into());
            }

            let program = parts.remove(0);
            let mut cmd = std::process::Command::new(&program);
            cmd.args(&parts)
                .current_dir(workdir)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            // Sanitize environment: clear all then re-add only safe vars (CWE-200)
            cmd.env_clear();
            for var in SAFE_ENV_VARS {
                if let Ok(val) = std::env::var(var) {
                    cmd.env(var, val);
                }
            }

            let mut child_proc = cmd
                .spawn()
                .map_err(|e| format!("Failed to spawn process: {e}"))?;

            let stdin = child_proc.stdin.take();
            writer = Arc::new(Mutex::new(
                stdin.map(|s| Box::new(s) as Box<dyn Write + Send>),
            ));

            // Spawn background readers for stdout/stderr
            let stdout = child_proc.stdout.take();
            let stderr = child_proc.stderr.take();

            let inner_clone = Arc::clone(&inner);
            if let Some(stdout) = stdout {
                let inner_c = Arc::clone(&inner_clone);
                std::thread::spawn(move || {
                    read_output_loop(stdout, inner_c);
                });
            }
            if let Some(stderr) = stderr {
                std::thread::spawn(move || {
                    read_output_loop(stderr, inner_clone);
                });
            }

            // Use PipeChildKiller for kill support
            let pid = child_proc.id();
            child_killer = Arc::new(Mutex::new(Some(
                Box::new(PipeChildKiller { pid }) as Box<dyn portable_pty::ChildKiller + Send>
            )));

            // Spawn waiter thread
            let inner_clone2 = Arc::clone(&inner);
            std::thread::spawn(move || match child_proc.wait() {
                Ok(status) => {
                    let code = status.code().unwrap_or(1);
                    let mut guard = inner_clone2.lock().unwrap();
                    if guard.status == ProcessStatus::Running {
                        guard.status = ProcessStatus::Exited(code);
                    }
                }
                Err(e) => {
                    let mut guard = inner_clone2.lock().unwrap();
                    if guard.status == ProcessStatus::Running {
                        guard.status = ProcessStatus::Failed(format!("{e}"));
                    }
                }
            });
        }

        // Spawn timeout watcher if configured
        if let Some(timeout) = timeout_secs {
            let killer_clone = Arc::clone(&child_killer);
            let inner_clone = Arc::clone(&inner);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(timeout));
                let mut guard = inner_clone.lock().unwrap();
                if guard.status == ProcessStatus::Running {
                    guard.status = ProcessStatus::Killed;
                    if let Some(ref mut k) = *killer_clone.lock().unwrap() {
                        let _ = k.kill();
                    }
                }
            });
        }

        Ok(Self {
            id,
            command: command.to_string(),
            created_at,
            pty: use_pty,
            inner,
            writer,
            child_killer,
        })
    }

    /// Get the current process status.
    pub fn status(&self) -> ProcessStatus {
        self.inner.lock().unwrap().status.clone()
    }

    /// Read captured output from the buffer.
    pub fn read_output(&self, offset: usize, limit: Option<usize>) -> String {
        let guard = self.inner.lock().unwrap();
        let buf = &guard.output_buffer;
        let start = offset.min(buf.len());
        let end = if let Some(lim) = limit {
            (start + lim).min(buf.len())
        } else {
            buf.len()
        };
        String::from_utf8_lossy(&buf[start..end]).to_string()
    }

    /// Get the total bytes captured so far.
    pub fn output_len(&self) -> usize {
        self.inner.lock().unwrap().output_buffer.len()
    }

    /// Write data to the process stdin.
    pub fn write_input(&self, data: &[u8]) -> Result<(), String> {
        let mut guard = self.writer.lock().unwrap();
        if let Some(ref mut w) = *guard {
            w.write_all(data)
                .map_err(|e| format!("Failed to write to stdin: {e}"))?;
            w.flush()
                .map_err(|e| format!("Failed to flush stdin: {e}"))?;
            Ok(())
        } else {
            Err("Process stdin is not available".into())
        }
    }

    /// Kill the process.
    pub fn kill(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        if inner.status != ProcessStatus::Running {
            return Ok(());
        }
        inner.status = ProcessStatus::Killed;
        drop(inner);

        let mut guard = self.child_killer.lock().unwrap();
        if let Some(ref mut k) = *guard {
            k.kill()
                .map_err(|e| format!("Failed to kill process: {e}"))?;
        }
        Ok(())
    }

    /// Check if the session has been idle for longer than the given duration.
    pub fn is_idle(&self, max_idle: std::time::Duration) -> bool {
        let guard = self.inner.lock().unwrap();
        guard.last_activity.elapsed() > max_idle
    }
}

/// Background thread loop: reads process output and appends to buffer.
fn read_output_loop(mut reader: impl Read, inner: Arc<Mutex<SessionInner>>) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break, // EOF or error
            Ok(n) => {
                let mut guard = inner.lock().unwrap();
                guard.last_activity = Instant::now();
                // Ring buffer behavior: drop oldest bytes if over limit
                let remaining = MAX_BUFFER_SIZE.saturating_sub(guard.output_buffer.len());
                if remaining >= n {
                    guard.output_buffer.extend_from_slice(&buf[..n]);
                } else if n < MAX_BUFFER_SIZE {
                    let to_remove = n - remaining;
                    guard.output_buffer.drain(..to_remove);
                    guard.output_buffer.extend_from_slice(&buf[..n]);
                }
            }
        }
    }
}

/// Wait for a portable_pty child to exit and update the session status.
fn wait_for_exit(mut child: Box<dyn portable_pty::Child>, inner: Arc<Mutex<SessionInner>>) {
    match child.wait() {
        Ok(status) => {
            let code: i32 = status.exit_code().try_into().unwrap_or(1);
            let mut guard = inner.lock().unwrap();
            if guard.status == ProcessStatus::Running {
                guard.status = ProcessStatus::Exited(code);
            }
        }
        Err(e) => {
            let mut guard = inner.lock().unwrap();
            if guard.status == ProcessStatus::Running {
                guard.status = ProcessStatus::Failed(format!("{e}"));
            }
        }
    }
}

/// Killer for pipe-based child processes (using PID-based kill).
#[derive(Debug)]
struct PipeChildKiller {
    pid: u32,
}

impl portable_pty::ChildKiller for PipeChildKiller {
    fn kill(&mut self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            let output = std::process::Command::new("kill")
                .args(["-9", &self.pid.to_string()])
                .output();
            match output {
                Ok(o) if o.status.success() => Ok(()),
                Ok(o) => Err(std::io::Error::other(
                    String::from_utf8_lossy(&o.stderr).to_string(),
                )),
                Err(e) => Err(e),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &self.pid.to_string(), "/F"])
                .output();
            Ok(())
        }
    }

    fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
        Box::new(PipeChildKiller { pid: self.pid })
    }
}

/// Build a shell command for portable_pty with sanitized environment.
fn build_shell_command(command: &str, workdir: &std::path::Path) -> portable_pty::CommandBuilder {
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = portable_pty::CommandBuilder::new("cmd");
        c.arg("/C");
        c.arg(command);
        c
    } else {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut c = portable_pty::CommandBuilder::new(shell);
        c.arg("-c");
        c.arg(command);
        c
    };
    cmd.cwd(workdir);
    // Sanitize environment: clear all then re-add only safe vars (CWE-200)
    cmd.env_clear();
    for var in SAFE_ENV_VARS {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_session_echo() {
        let dir = std::env::temp_dir();
        let session =
            ProcessSession::spawn("test-echo".into(), "echo hello", &dir, false, Some(5)).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(500));

        let status = session.status();
        assert!(
            matches!(status, ProcessStatus::Exited(0)),
            "expected Exited(0), got {status:?}"
        );

        let output = session.read_output(0, None);
        assert!(
            output.contains("hello"),
            "expected 'hello' in output, got: {output}"
        );
    }

    #[test]
    fn pipe_session_kill() {
        let dir = std::env::temp_dir();
        let session =
            ProcessSession::spawn("test-kill".into(), "sleep 60", &dir, false, None).unwrap();

        assert_eq!(session.status(), ProcessStatus::Running);
        session.kill().unwrap();

        std::thread::sleep(std::time::Duration::from_millis(500));
        let status = session.status();
        assert!(
            matches!(status, ProcessStatus::Killed),
            "expected Killed, got {status:?}"
        );
    }

    #[test]
    fn pipe_session_timeout() {
        let dir = std::env::temp_dir();
        let session =
            ProcessSession::spawn("test-timeout".into(), "sleep 60", &dir, false, Some(1)).unwrap();

        std::thread::sleep(std::time::Duration::from_secs(2));
        let status = session.status();
        assert!(
            matches!(status, ProcessStatus::Killed),
            "expected Killed from timeout, got {status:?}"
        );
    }

    #[test]
    fn output_offset_and_limit() {
        let dir = std::env::temp_dir();
        let session = ProcessSession::spawn(
            "test-offset".into(),
            "echo abcdefghij",
            &dir,
            false,
            Some(5),
        )
        .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(500));

        let full = session.read_output(0, None);
        let partial = session.read_output(0, Some(3));
        assert_eq!(partial.len(), 3);
        assert_eq!(partial, &full[..3]);
    }

    #[test]
    fn safe_env_vars_excludes_secrets() {
        for var in SAFE_ENV_VARS {
            let lower = var.to_lowercase();
            assert!(
                !lower.contains("key") && !lower.contains("secret") && !lower.contains("token"),
                "SAFE_ENV_VARS must not include sensitive variable: {var}"
            );
        }
    }

    #[test]
    fn safe_env_vars_includes_essentials() {
        assert!(SAFE_ENV_VARS.contains(&"PATH"));
        assert!(SAFE_ENV_VARS.contains(&"HOME"));
        assert!(SAFE_ENV_VARS.contains(&"TERM"));
    }

    #[test]
    fn pipe_session_does_not_leak_env() {
        // Set a fake secret env var
        let key = "ZEROCLAW_TEST_SECRET_XYZ";
        std::env::set_var(key, "super-secret-value");

        let dir = std::env::temp_dir();
        let session =
            ProcessSession::spawn("test-env-leak".into(), "env", &dir, false, Some(5)).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(500));

        let output = session.read_output(0, None);
        assert!(
            !output.contains("super-secret-value"),
            "Secret env var leaked to child process"
        );

        std::env::remove_var(key);
    }
}
