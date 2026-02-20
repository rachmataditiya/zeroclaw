//! Session persistence for conversation history.
//!
//! Stores per-sender conversation history as JSONL files so sessions
//! survive daemon restarts. Each session key maps to a file at
//! `{base_dir}/{key}.jsonl`.

mod store;

#[allow(unused_imports)]
pub use store::SessionMeta;
pub use store::SessionStore;
