//! Substitution of the `${VAR}` references in the raw configuration file with
//! the values of the process environment.

use super::ConfigError;

/// Substitute every `${VAR}` in the raw config with its environment value.
/// Fails closed: a referenced variable that is not set aborts the load, so a
/// missing secret can never silently become an empty string.
pub(super) fn expand_env(raw: &str) -> Result<String, ConfigError> {
	let mut out = String::with_capacity(raw.len());
	let mut rest = raw;
	while let Some(start) = rest.find("${") {
		out.push_str(&rest[..start]);
		let after = &rest[start + 2..];
		let end = after
			.find('}')
			.ok_or_else(|| ConfigError::Invalid("unterminated ${...} in config".to_string()))?;
		let var = &after[..end];
		let value = std::env::var(var).map_err(|_| ConfigError::MissingEnv(var.to_string()))?;
		out.push_str(&value);
		rest = &after[end + 1..];
	}
	out.push_str(rest);
	Ok(out)
}
