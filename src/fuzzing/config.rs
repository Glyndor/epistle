//! The configuration adapter: the text of a configuration file.

use super::common::INPUT_CAP;

/// The text of a configuration file, parsed and validated as the loader does
/// after reading it: `${VAR}` references, TOML, the schema and every
/// validation rule. A refusal is the expected answer; the target looks for a
/// panic, an overflow or a hang.
pub fn config_parse(raw: &[u8]) {
	let raw = &raw[..raw.len().min(INPUT_CAP)];
	let Ok(text) = std::str::from_utf8(raw) else {
		return;
	};
	let path = std::path::Path::new("fuzz.toml");
	let _ = crate::config::Config::parse_text(text, path);
	let _ = crate::config::Config::parse_text_lenient(text, path);
}
