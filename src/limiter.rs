// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! Fixed-window attempt limits per key, in process memory.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const MAX_KEYS: usize = 100_000;

#[derive(Clone, Default)]
pub struct Limiter {
    windows: Arc<Mutex<HashMap<String, (u64, u32)>>>,
}

impl Limiter {
    /// Counts one attempt for `key`; false once `limit` is reached inside the
    /// window of `window_seconds` that started with the first attempt.
    pub fn allow(&self, key: &str, now: u64, limit: u32, window_seconds: u64) -> bool {
        let mut windows = self.windows.lock().expect("limiter lock poisoned");
        if windows.len() >= MAX_KEYS {
            windows.retain(|_, (started, _)| now.saturating_sub(*started) < window_seconds);
        }
        let entry = windows.entry(key.to_owned()).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= window_seconds {
            *entry = (now, 0);
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
}
