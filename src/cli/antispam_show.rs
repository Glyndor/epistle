//! `epistle antispam`: rendering helpers and input parsers for the
//! show and set paths. Lives in a sibling so the dispatch module
//! stays below the per-file code-line budget.

use crate::config::Config;

use super::Key;

/// Render one line per antispam key. Secret fields (LLM credentials)
/// show as `set`/`unset`, never the value.
pub fn show(config: &Config, out: &mut impl std::io::Write) -> std::io::Result<()> {
	for key in all_keys() {
		let line = render_row(config, key);
		writeln!(out, "{line}")?;
	}
	Ok(())
}

/// `antispam show --json`: `{"<key>": {"value", "source"}}` with the same
/// values and sources as the text rows. A DNSBL list is an array; every
/// other value is the string the text form prints (`unset` when absent,
/// `set` for a secret).
pub fn show_json(config: &Config) -> serde_json::Value {
	let mut keys = serde_json::Map::new();
	for key in all_keys() {
		let row = render_row(config, key);
		let mut fields = row.splitn(3, '\t');
		let (name, value, source) = (
			fields.next().unwrap_or_default(),
			fields.next().unwrap_or_default(),
			fields.next().unwrap_or_default(),
		);
		let value = match key {
			Key::DnsblZones | Key::DnsblDomainZones | Key::DnsblUrlZones => {
				let values: Vec<&str> = match value {
					"(empty)" => Vec::new(),
					list => list.split(',').collect(),
				};
				serde_json::json!(values)
			}
			_ => serde_json::json!(value),
		};
		keys.insert(
			name.to_string(),
			serde_json::json!({ "value": value, "source": source }),
		);
	}
	serde_json::Value::Object(keys)
}

pub(super) fn list_row(name: &str, values: &[String]) -> String {
	if values.is_empty() {
		format!("{name}\t(empty)\tdefault")
	} else {
		format!("{name}\t{}\tconfigured", values.join(","))
	}
}

/// Every key the show path walks, in stable order.
pub(super) fn all_keys() -> [Key; 15] {
	[
		Key::DnsblZones,
		Key::DnsblDomainZones,
		Key::DnsblUrlZones,
		Key::GreylistDelay,
		Key::FirstTimeSenderDelay,
		Key::ClamdSocket,
		Key::ClamdOnFound,
		Key::ClamdTimeout,
		Key::ClamdMaxSize,
		Key::Subjectpass,
		Key::LlmEndpoint,
		Key::LlmModel,
		Key::LlmApiKeyEnv,
		Key::LlmUncertainLow,
		Key::LlmUncertainHigh,
	]
}

fn render_row(config: &Config, key: Key) -> String {
	match key {
		Key::DnsblZones => list_row(key.name(), &config.dnsbl_zones),
		Key::DnsblDomainZones => list_row(key.name(), &config.dnsbl_domain_zones),
		Key::DnsblUrlZones => list_row(key.name(), &config.dnsbl_url_zones),
		Key::GreylistDelay => duration_row(key.name(), config.greylist_delay_secs),
		Key::FirstTimeSenderDelay => duration_row(key.name(), config.first_time_sender_delay_secs),
		Key::ClamdSocket => optional_row(
			key.name(),
			config
				.antispam
				.clamd_socket
				.as_ref()
				.map(|path| path.display().to_string())
				.as_deref(),
		),
		Key::ClamdOnFound => scalar_row(
			key.name(),
			Some(match config.antispam.clamd_on_found {
				crate::config::ClamdOnFound::Quarantine => "quarantine",
				crate::config::ClamdOnFound::Reject => "reject",
			}),
		),
		Key::ClamdTimeout => scalar_row(key.name(), Some(config.antispam.clamd_timeout_secs)),
		Key::ClamdMaxSize => scalar_row(key.name(), Some(config.antispam.clamd_max_bytes)),
		Key::Subjectpass => scalar_row(
			key.name(),
			Some(if config.subjectpass.enabled {
				"on"
			} else {
				"off"
			}),
		),
		Key::LlmEndpoint => optional_row(key.name(), config.antispam_llm.as_ref().map(|_| "set")),
		Key::LlmModel => optional_row(key.name(), config.antispam_llm.as_ref().map(|_| "set")),
		Key::LlmApiKeyEnv => optional_row(key.name(), config.antispam_llm.as_ref().map(|_| "set")),
		Key::LlmUncertainLow => scalar_row(
			key.name(),
			config.antispam_llm.as_ref().map(|llm| llm.uncertain_low),
		),
		Key::LlmUncertainHigh => scalar_row(
			key.name(),
			config.antispam_llm.as_ref().map(|llm| llm.uncertain_high),
		),
	}
}

fn duration_row(name: &str, seconds: u64) -> String {
	if seconds == 0 {
		format!("{name}\t0 seconds\tdefault")
	} else {
		format!("{name}\t{seconds} seconds\tconfigured")
	}
}

fn scalar_row<T: std::fmt::Display>(name: &str, value: Option<T>) -> String {
	match value {
		Some(value) => format!("{name}\t{value}\tset"),
		None => format!("{name}\tunset\tdefault"),
	}
}

fn optional_row(name: &str, value: Option<&str>) -> String {
	match value {
		Some(value) => format!("{name}\t{value}\tset"),
		None => format!("{name}\tunset\tdefault"),
	}
}

pub(super) fn parse_duration_seconds(input: &str) -> Result<u64, &'static str> {
	const INVALID: &str = "expected a non-negative integer or a duration suffix (s, m, h, d, w)";
	let trimmed = input.trim();
	if trimmed.is_empty() {
		return Err(INVALID);
	}
	let digit_end = trimmed
		.find(|character: char| !character.is_ascii_digit())
		.unwrap_or(trimmed.len());
	let (digits, suffix) = trimmed.split_at(digit_end);
	if digits.is_empty() {
		return Err(INVALID);
	}
	let multiplier: u64 = match suffix {
		"" | "s" => 1,
		"m" => 60,
		"h" => 3600,
		"d" => 86400,
		"w" => 7 * 86400,
		_ => return Err(INVALID),
	};
	digits
		.parse::<u64>()
		.ok()
		.and_then(|value| value.checked_mul(multiplier))
		.ok_or(INVALID)
}

pub(super) fn parse_u64(input: &str) -> Result<u64, &'static str> {
	const INVALID: &str = "expected a non-negative integer";
	input.trim().parse::<u64>().map_err(|_| INVALID)
}

pub(super) fn parse_size_bytes(input: &str) -> Result<i64, &'static str> {
	const INVALID: &str = "expected a non-negative byte count or a binary suffix (K, M, G, T)";
	let trimmed = input.trim();
	if trimmed.is_empty() {
		return Err(INVALID);
	}
	let digit_end = trimmed
		.find(|character: char| !character.is_ascii_digit())
		.unwrap_or(trimmed.len());
	let (digits, suffix) = trimmed.split_at(digit_end);
	if digits.is_empty() {
		return Err(INVALID);
	}
	let multiplier: i64 = match suffix {
		"" => 1,
		"K" | "k" => 1024,
		"M" | "m" => 1024 * 1024,
		"G" | "g" => 1024 * 1024 * 1024,
		"T" | "t" => 1024_i64.pow(4),
		_ => return Err(INVALID),
	};
	digits
		.parse::<i64>()
		.ok()
		.and_then(|value| value.checked_mul(multiplier))
		.filter(|value| *value > 0)
		.ok_or(INVALID)
}

pub(super) fn parse_on_off(input: &str) -> Result<bool, &'static str> {
	match input.trim().to_ascii_lowercase().as_str() {
		"on" | "true" | "yes" | "1" => Ok(true),
		"off" | "false" | "no" | "0" => Ok(false),
		_ => Err("expected on or off"),
	}
}

pub(super) fn parse_unit_interval(input: &str) -> Result<f64, &'static str> {
	const INVALID: &str = "expected a float in [0.0, 1.0]";
	let value: f64 = input.trim().parse().map_err(|_| INVALID)?;
	if !(0.0..=1.0).contains(&value) {
		return Err(INVALID);
	}
	Ok(value)
}
