//! A notice about an account that would otherwise repeat at every sign-in.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a notice about one account and cause stays quiet after it is given.
const QUIET: Duration = Duration::from_secs(60 * 60);

/// Keys remembered before the oldest are forgotten.
const MAX_KEYS: usize = 10_000;

static GIVEN: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// Whether the notice `cause` about `account` is due: the first time, and
/// again once an hour has passed.
pub fn due(account: &str, cause: &str) -> bool {
	due_at(account, cause, Instant::now(), &GIVEN)
}

fn due_at(
	account: &str,
	cause: &str,
	now: Instant,
	given: &Mutex<Option<HashMap<String, Instant>>>,
) -> bool {
	let mut guard = given.lock().unwrap_or_else(|p| p.into_inner());
	let map = guard.get_or_insert_with(HashMap::new);
	if map.len() >= MAX_KEYS {
		map.retain(|_, at| now.duration_since(*at) < QUIET);
		if map.len() >= MAX_KEYS {
			map.clear();
		}
	}
	let key = format!("{cause}\0{account}");
	match map.get(&key) {
		Some(at) if now.duration_since(*at) < QUIET => false,
		_ => {
			map.insert(key, now);
			true
		}
	}
}

#[cfg(test)]
mod tests;
