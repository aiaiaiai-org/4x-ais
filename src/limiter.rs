// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Fixed-window attempt limits per key, in process memory.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const MAX_KEYS: usize = 100_000;

/// Windows of different lengths share one map, so every entry carries its own
/// expiry: pruning by the caller's window would let a 60-second check drop a
/// 15-minute password lock.
#[derive(Clone, Default)]
pub struct Limiter {
    windows: Arc<Mutex<HashMap<String, (u64, u32)>>>,
}

impl Limiter {
    /// Counts one attempt for `key`; false once `limit` is reached inside the
    /// window of `window_seconds` that started with the first attempt, and
    /// false for a new key while the map is full of live windows, so a flood
    /// of keys cannot grow memory or push out someone else's lock.
    pub fn allow(&self, key: &str, now: u64, limit: u32, window_seconds: u64) -> bool {
        let mut windows = self.windows.lock().expect("limiter lock poisoned");
        if windows.len() >= MAX_KEYS && !windows.contains_key(key) {
            windows.retain(|_, (expires_at, _)| *expires_at > now);
            if windows.len() >= MAX_KEYS {
                return false;
            }
        }
        let entry = windows
            .entry(key.to_owned())
            .or_insert((now.saturating_add(window_seconds), 0));
        if entry.0 <= now {
            *entry = (now.saturating_add(window_seconds), 0);
        }
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }

    pub fn clear(&self, key: &str) {
        self.windows
            .lock()
            .expect("limiter lock poisoned")
            .remove(key);
    }

    #[cfg(test)]
    fn fill(&self, count: usize, expires_at: u64) {
        let mut windows = self.windows.lock().expect("limiter lock poisoned");
        for index in 0..count {
            windows.insert(format!("filler:{index}"), (expires_at, 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_inside_a_window_and_resets_after_it() {
        let limiter = Limiter::default();
        assert!(limiter.allow("k", 0, 2, 60));
        assert!(limiter.allow("k", 1, 2, 60));
        assert!(!limiter.allow("k", 2, 2, 60));
        assert!(limiter.allow("other", 2, 2, 60));
        assert!(limiter.allow("k", 61, 2, 60));
        limiter.clear("k");
        assert!(limiter.allow("k", 62, 1, 60));
    }

    #[test]
    fn a_short_window_never_evicts_a_long_lock() {
        let limiter = Limiter::default();
        assert!(limiter.allow("long", 0, 1, 900));
        limiter.fill(MAX_KEYS - 1, 60);
        // The map is full; the fillers expire at 60, the lock at 900.
        assert!(limiter.allow("short", 120, 5, 60));
        assert!(!limiter.allow("long", 120, 1, 900));
    }

    #[test]
    fn a_full_map_of_live_windows_refuses_new_keys() {
        let limiter = Limiter::default();
        limiter.fill(MAX_KEYS, 1_000);
        assert!(!limiter.allow("new", 0, 5, 60));
        assert!(limiter.allow("filler:0", 0, 5, 60));
    }
}
