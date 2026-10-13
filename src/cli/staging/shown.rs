//! Messages of a delegated run name the operator's paths, not the staged
//! copies: the root parent passes the pairs in [`ENV`], and [`shown`]
//! rewrites a message with them.

use std::path::PathBuf;
use std::sync::OnceLock;

/// The environment variable carrying the staged paths and the operator's,
/// as a JSON array of `[staged, named]` pairs.
pub(crate) const ENV: &str = "EPISTLE_STAGED_PATHS";

/// Encode the pairs for [`ENV`]. A path that is not UTF-8 is left out and
/// shows as staged.
pub(super) fn encode(pairs: &[(PathBuf, PathBuf)]) -> String {
	let pairs: Vec<(&str, &str)> = pairs
		.iter()
		.filter_map(|(staged, named)| Some((staged.to_str()?, named.to_str()?)))
		.collect();
	serde_json::to_string(&pairs).unwrap_or_default()
}

pub(super) fn decode(value: &str) -> Vec<(String, String)> {
	let mut pairs: Vec<(String, String)> = serde_json::from_str(value).unwrap_or_default();
	// The longest staged path first, so a directory never claims the
	// prefix of a file staged inside it.
	pairs.sort_by_key(|(staged, _)| std::cmp::Reverse(staged.len()));
	pairs
}

/// `text` with every staged path the root parent passed replaced by the
/// path the operator named. Unchanged outside a delegated run.
pub(crate) fn shown(text: &str) -> String {
	static PAIRS: OnceLock<Vec<(String, String)>> = OnceLock::new();
	let pairs = PAIRS.get_or_init(|| {
		std::env::var(ENV)
			.map(|value| decode(&value))
			.unwrap_or_default()
	});
	replace(pairs, text)
}

fn replace(pairs: &[(String, String)], text: &str) -> String {
	let mut text = text.to_owned();
	for (staged, named) in pairs {
		if text.contains(staged.as_str()) {
			text = text.replace(staged.as_str(), named);
		}
	}
	text
}

#[cfg(test)]
#[path = "shown_tests.rs"]
mod tests;
