//! In-memory LRU cache with TTL expiration.
//!
//! Simple cache for web tool responses (search results, fetched pages)
//! to avoid redundant HTTP requests within a configurable time window.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Entry in the cache with expiration.
struct CacheEntry<V> {
    key: String,
    value: V,
    expires_at: Instant,
}

/// Thread-safe LRU cache with per-entry TTL.
///
/// Uses a `VecDeque` for simplicity (no extra dependencies). On access,
/// matching entries are moved to the back (most recent). Eviction is
/// from the front (oldest).
pub struct TtlCache<V> {
    entries: Mutex<VecDeque<CacheEntry<V>>>,
    max_entries: usize,
    ttl: Duration,
}

impl<V: Clone> TtlCache<V> {
    /// Create a new cache with the given capacity and TTL.
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(max_entries)),
            max_entries,
            ttl,
        }
    }

    /// Get a cached value by key. Returns `None` if missing or expired.
    pub fn get(&self, key: &str) -> Option<V> {
        let mut entries = self.entries.lock();
        let now = Instant::now();

        // Remove expired entries from the front
        while entries.front().is_some_and(|e| now >= e.expires_at) {
            entries.pop_front();
        }

        // Find and return the matching entry, moving it to the back (MRU)
        if let Some(pos) = entries.iter().position(|e| e.key == key) {
            let entry = &entries[pos];
            if now < entry.expires_at {
                let value = entry.value.clone();
                // Move to back (most recently used)
                let entry = entries.remove(pos).unwrap();
                entries.push_back(entry);
                return Some(value);
            }
            // Expired — remove it
            entries.remove(pos);
        }

        None
    }

    /// Insert a value into the cache. Evicts the oldest entry if at capacity.
    pub fn insert(&self, key: &str, value: V) {
        let mut entries = self.entries.lock();
        let now = Instant::now();

        // Remove expired entries
        while entries.front().is_some_and(|e| now >= e.expires_at) {
            entries.pop_front();
        }

        // Remove existing entry with the same key
        if let Some(pos) = entries.iter().position(|e| e.key == key) {
            entries.remove(pos);
        }

        // Evict oldest if at capacity
        while entries.len() >= self.max_entries {
            entries.pop_front();
        }

        entries.push_back(CacheEntry {
            key: key.to_string(),
            value,
            expires_at: now + self.ttl,
        });
    }

    /// Remove all entries from the cache.
    pub fn clear(&self) {
        self.entries.lock().clear();
    }

    /// Return the number of non-expired entries.
    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        let mut entries = self.entries.lock();
        let now = Instant::now();
        while entries.front().is_some_and(|e| now >= e.expires_at) {
            entries.pop_front();
        }
        entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let cache = TtlCache::new(10, Duration::from_secs(60));
        cache.insert("key1", "value1".to_string());
        assert_eq!(cache.get("key1"), Some("value1".to_string()));
    }

    #[test]
    fn missing_key_returns_none() {
        let cache: TtlCache<String> = TtlCache::new(10, Duration::from_secs(60));
        assert_eq!(cache.get("nonexistent"), None);
    }

    #[test]
    fn overwrite_existing_key() {
        let cache = TtlCache::new(10, Duration::from_secs(60));
        cache.insert("key1", "old".to_string());
        cache.insert("key1", "new".to_string());
        assert_eq!(cache.get("key1"), Some("new".to_string()));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let cache = TtlCache::new(2, Duration::from_secs(60));
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("c", 3); // should evict "a"
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.get("b"), Some(2));
        assert_eq!(cache.get("c"), Some(3));
    }

    #[test]
    fn lru_moves_accessed_to_back() {
        let cache = TtlCache::new(2, Duration::from_secs(60));
        cache.insert("a", 1);
        cache.insert("b", 2);
        // Access "a" to make it most-recently-used
        cache.get("a");
        // Insert "c" — should evict "b" (now oldest)
        cache.insert("c", 3);
        assert_eq!(cache.get("a"), Some(1));
        assert_eq!(cache.get("b"), None);
        assert_eq!(cache.get("c"), Some(3));
    }

    #[test]
    fn clear_empties_cache() {
        let cache = TtlCache::new(10, Duration::from_secs(60));
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.get("a"), None);
    }

    #[test]
    fn expired_entries_not_returned() {
        let cache = TtlCache::new(10, Duration::from_millis(1));
        cache.insert("key", "value".to_string());
        // Sleep just past the TTL
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get("key"), None);
    }
}
