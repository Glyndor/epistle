
use std::sync::Mutex;

static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub(in super::super) fn note(script: &str) {
	let first = script.lines().next().unwrap_or("").to_string();
	SEEN.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner())
		.push(first);
}

/// How many times a script whose first line is `first` was checked.
pub(crate) fn times(first: &str) -> usize {
	SEEN.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner())
		.iter()
		.filter(|line| line.as_str() == first)
		.count()
}
