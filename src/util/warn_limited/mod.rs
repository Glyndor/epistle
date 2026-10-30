//! A log line that says something about an account is for a change, not for
//! every message: this lets a caller say it once per key and hour. A script
//! that overspends does so on every message that reaches it, and a flood of
//! those must not become a flood of log lines.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a key stays quiet after it was let through.
const QUIET: Duration = Duration::from_secs(3600);
/// The most keys remembered. Past it, the keys whose hour is over go first,
/// and if there are none the table starts over: some lines are said again,
/// none is lost for good.
const MAX_KEYS: usize = 4096;

static SEEN: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// Whether the line for `key` may be said now: the first time, and then once
/// an hour. A key names what is said and about whom, for example
/// `format!("sieve-aborted:{account}")`.
pub fn allow(key: &str) -> bool {
	let mut seen = SEEN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	allow_at(seen.get_or_insert_with(HashMap::new), key, Instant::now())
}

fn allow_at(seen: &mut HashMap<String, Instant>, key: &str, now: Instant) -> bool {
	if let Some(last) = seen.get(key)
		&& now.saturating_duration_since(*last) < QUIET
	{
		return false;
	}
	if seen.len() >= MAX_KEYS && !seen.contains_key(key) {
		seen.retain(|_, last| now.saturating_duration_since(*last) < QUIET);
		if seen.len() >= MAX_KEYS {
			seen.clear();
		}
	}
	seen.insert(key.to_string(), now);
	true
}

#[cfg(test)]
mod tests;
